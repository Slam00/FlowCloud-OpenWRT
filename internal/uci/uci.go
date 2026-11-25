// Package uci reads OpenWrt UCI configuration through the `uci show` output,
// which is stable, needs no C bindings and is available on every OpenWrt.
package uci

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
)

// Section is one UCI section: its name ("cfg0123ab" for anonymous ones), type
// and options. A plain option has one value; a list has any number.
type Section struct {
	Name    string
	Type    string
	Options map[string][]string
	// Order keeps the position of the section in the file.
	Order int
}

// Get returns the first value of an option or def.
func (s *Section) Get(option, def string) string {
	if values, ok := s.Options[option]; ok && len(values) > 0 {
		return values[0]
	}
	return def
}

// List returns every value of an option.
func (s *Section) List(option string) []string {
	return s.Options[option]
}

// Bool reads a UCI boolean ("1", "true", "yes", "on", "enabled").
func (s *Section) Bool(option string, def bool) bool {
	value, ok := s.Options[option]
	if !ok || len(value) == 0 {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(value[0])) {
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	}
	return def
}

// Load runs `uci -q show <config>` and parses it.
func Load(config string) ([]*Section, error) {
	output, err := exec.Command("uci", "-q", "show", config).Output()
	if err != nil {
		return nil, fmt.Errorf("uci show %s: %w", config, err)
	}
	return Parse(config, string(output))
}

// Parse reads the text of `uci show <config>`.
func Parse(config, text string) ([]*Section, error) {
	var sections []*Section
	byName := map[string]*Section{}
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	var pending strings.Builder
	for scanner.Scan() {
		line := scanner.Text()
		if pending.Len() > 0 {
			pending.WriteString("\n")
			pending.WriteString(line)
		} else {
			pending.WriteString(line)
		}
		// A quoted value may span several lines; wait until quotes balance.
		if !quotesBalanced(pending.String()) {
			continue
		}
		entry := pending.String()
		pending.Reset()
		if strings.TrimSpace(entry) == "" {
			continue
		}
		key, raw, found := strings.Cut(entry, "=")
		if !found {
			return nil, fmt.Errorf("uci: malformed line %q", entry)
		}
		parts := strings.Split(key, ".")
		if len(parts) < 2 || parts[0] != config {
			return nil, fmt.Errorf("uci: unexpected key %q", key)
		}
		name := parts[1]
		if len(parts) == 2 {
			section := &Section{Name: name, Type: raw, Options: map[string][]string{}, Order: len(sections)}
			sections = append(sections, section)
			byName[name] = section
			continue
		}
		section := byName[name]
		if section == nil {
			return nil, fmt.Errorf("uci: option for unknown section %q", name)
		}
		values, err := parseValues(raw)
		if err != nil {
			return nil, fmt.Errorf("uci: %s: %w", key, err)
		}
		section.Options[strings.Join(parts[2:], ".")] = values
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if pending.Len() > 0 {
		return nil, fmt.Errorf("uci: unterminated quote in %q", pending.String())
	}
	return sections, nil
}

// quotesBalanced reports whether every quoted value in a `uci show` entry is
// closed, treating uci's '\” escape as part of the value.
func quotesBalanced(text string) bool {
	inQuote := false
	for index := 0; index < len(text); index++ {
		if text[index] != '\'' {
			continue
		}
		if inQuote && strings.HasPrefix(text[index:], `'\''`) {
			index += 3
			continue
		}
		inQuote = !inQuote
	}
	return !inQuote
}

// parseValues splits `'a' 'b c'` into its values, handling the '\” escape.
func parseValues(raw string) ([]string, error) {
	var values []string
	var current strings.Builder
	inQuote := false
	hasValue := false
	for index := 0; index < len(raw); index++ {
		char := raw[index]
		switch {
		case char == '\'' && !inQuote:
			inQuote = true
			hasValue = true
		case char == '\'' && inQuote:
			// '\'' inside a value: close, escaped quote, reopen.
			if strings.HasPrefix(raw[index:], `'\''`) {
				current.WriteByte('\'')
				index += 3
				continue
			}
			inQuote = false
		case char == ' ' && !inQuote:
			if hasValue {
				values = append(values, current.String())
				current.Reset()
				hasValue = false
			}
		default:
			current.WriteByte(char)
			hasValue = true
		}
	}
	if inQuote {
		return nil, fmt.Errorf("unterminated quote")
	}
	if hasValue {
		values = append(values, current.String())
	}
	return values, nil
}
