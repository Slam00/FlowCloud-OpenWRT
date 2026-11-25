package lists

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"flowcloud-openwrt/internal/config"
)

const maxListSize = 16 << 20

// Kind tells how a downloaded list is parsed.
type Kind int

const (
	KindDomains Kind = iota
	KindSubnets
)

// Source is one remote list.
type Source struct {
	URL  string
	Kind Kind
}

// Result is a section's resolved content: its own entries plus every list it
// references.
type Result struct {
	Domains []string
	Subnets []netip.Prefix
	// Missing are sources that have neither a fresh download nor a cached copy.
	Missing []string
}

// Store downloads lists into a cache directory and serves them from there, so
// a router that boots without internet still routes with the last lists.
type Store struct {
	directory string
	client    *http.Client
	mutex     sync.Mutex
	updated   map[string]time.Time
}

func NewStore(directory string, client *http.Client) *Store {
	if client == nil {
		client = &http.Client{Timeout: 60 * time.Second}
	}
	return &Store{directory: directory, client: client, updated: map[string]time.Time{}}
}

// Sources lists the remote lists a section needs.
func Sources(section *config.Section) ([]Source, []string) {
	var sources []Source
	var unknown []string
	for _, name := range section.CommunityLists {
		preset, ok := LookupPreset(name)
		if !ok {
			unknown = append(unknown, name)
			continue
		}
		sources = append(sources, Source{URL: CommunityBase + preset.Domains, Kind: KindDomains})
		if preset.Subnets != "" {
			sources = append(sources, Source{URL: CommunityBase + preset.Subnets, Kind: KindSubnets})
		}
	}
	for _, url := range section.RemoteDomainLists {
		sources = append(sources, Source{URL: url, Kind: KindDomains})
	}
	for _, url := range section.RemoteSubnetLists {
		sources = append(sources, Source{URL: url, Kind: KindSubnets})
	}
	return sources, unknown
}

func (s *Store) path(url string) string {
	sum := sha256.Sum256([]byte(url))
	return filepath.Join(s.directory, hex.EncodeToString(sum[:12])+".lst")
}

// Fetch downloads one source and replaces the cached copy only when the new
// content differs, which keeps flash writes rare.
func (s *Store) Fetch(ctx context.Context, source Source) error {
	if !strings.HasPrefix(source.URL, "https://") && !strings.HasPrefix(source.URL, "http://") {
		return fmt.Errorf("%s: only http(s) URLs are supported", source.URL)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source.URL, nil)
	if err != nil {
		return err
	}
	request.Header.Set("User-Agent", "FlowCloud-OpenWrt")
	response, err := s.client.Do(request)
	if err != nil {
		return fmt.Errorf("%s: %w", source.URL, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", source.URL, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxListSize+1))
	if err != nil {
		return fmt.Errorf("%s: %w", source.URL, err)
	}
	if len(body) > maxListSize {
		return fmt.Errorf("%s: list is larger than %d bytes", source.URL, maxListSize)
	}
	path := s.path(source.URL)
	if previous, readErr := os.ReadFile(path); readErr != nil || string(previous) != string(body) {
		if err := os.MkdirAll(s.directory, 0o755); err != nil {
			return err
		}
		temporary := path + ".tmp"
		if err := os.WriteFile(temporary, body, 0o644); err != nil {
			return err
		}
		if err := os.Rename(temporary, path); err != nil {
			return err
		}
	}
	s.mutex.Lock()
	s.updated[source.URL] = time.Now()
	s.mutex.Unlock()
	return nil
}

// FetchAll downloads every source, a few at a time, and returns the errors.
func (s *Store) FetchAll(ctx context.Context, sources []Source) []error {
	unique := map[string]Source{}
	for _, source := range sources {
		unique[source.URL] = source
	}
	var mutex sync.Mutex
	var errs []error
	var wait sync.WaitGroup
	slots := make(chan struct{}, 4)
	for _, source := range unique {
		wait.Add(1)
		go func(source Source) {
			defer wait.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			if err := s.Fetch(ctx, source); err != nil {
				mutex.Lock()
				errs = append(errs, err)
				mutex.Unlock()
			}
		}(source)
	}
	wait.Wait()
	return errs
}

// Has reports whether a cached copy of the source exists.
func (s *Store) Has(url string) bool {
	_, err := os.Stat(s.path(url))
	return err == nil
}

// Resolve merges a section's own entries with its cached lists.
func (s *Store) Resolve(section *config.Section) Result {
	result := Result{}
	domains := map[string]bool{}
	subnets := map[netip.Prefix]bool{}
	for _, domain := range section.Domains {
		domains[domain] = true
	}
	for _, prefix := range section.Subnets {
		subnets[prefix] = true
	}
	sources, unknown := Sources(section)
	result.Missing = append(result.Missing, unknown...)
	for _, source := range sources {
		data, err := os.ReadFile(s.path(source.URL))
		if err != nil {
			result.Missing = append(result.Missing, source.URL)
			continue
		}
		if source.Kind == KindDomains {
			parsed, _ := config.ParseDomains(string(data))
			for _, domain := range parsed {
				domains[domain] = true
			}
		} else {
			parsed, _ := config.ParseSubnets(string(data))
			for _, prefix := range parsed {
				subnets[prefix] = true
			}
		}
	}
	for domain := range domains {
		result.Domains = append(result.Domains, domain)
	}
	for prefix := range subnets {
		result.Subnets = append(result.Subnets, prefix)
	}
	return result
}

// LastUpdate returns when the source was last downloaded in this run.
func (s *Store) LastUpdate(url string) (time.Time, bool) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	when, ok := s.updated[url]
	return when, ok
}

// ErrNoSources is returned when nothing needs downloading.
var ErrNoSources = errors.New("no remote lists")
