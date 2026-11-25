package dnsproxy

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"flowcloud-openwrt/internal/nft"
)

func TestMatcher(t *testing.T) {
	matcher := NewMatcher([][]string{{"googlevideo.com"}, {"youtube.com", "rr1.googlevideo.com"}})
	cases := map[string]struct {
		index int
		ok    bool
	}{
		"rr1---sn-abc.googlevideo.com.": {0, true},
		"rr1.googlevideo.com":           {0, true},
		"www.youtube.com.":              {1, true},
		"YOUTUBE.COM":                   {1, true},
		"notyoutube.com":                {0, false},
		"example.org":                   {0, false},
	}
	for name, want := range cases {
		index, ok := matcher.Match(name)
		if index != want.index || ok != want.ok {
			t.Errorf("Match(%q) = %d,%v want %d,%v", name, index, ok, want.index, want.ok)
		}
	}
}

func buildQuery(t *testing.T, name string, qtype dnsmessage.Type) []byte {
	t.Helper()
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 0x1234, RecursionDesired: true})
	_ = builder.StartQuestions()
	_ = builder.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: qtype, Class: dnsmessage.ClassINET})
	message, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return message
}

type fakeUpstream struct{ answers []netip.Addr }

func (f *fakeUpstream) String() string { return "fake" }

func (f *fakeUpstream) Exchange(_ context.Context, query []byte) ([]byte, error) {
	var parser dnsmessage.Parser
	header, _ := parser.Start(query)
	question, _ := parser.Question()
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: header.ID, Response: true})
	_ = builder.StartQuestions()
	_ = builder.Question(question)
	_ = builder.StartAnswers()
	for _, address := range f.answers {
		_ = builder.AResource(dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: address.As4()})
	}
	return builder.Finish()
}

type recordingAdder struct{ elements []nft.Element }

func (r *recordingAdder) Add(elements []nft.Element) error {
	r.elements = append(r.elements, elements...)
	return nil
}

func TestHandleLearnsRoutedDomains(t *testing.T) {
	adder := &recordingAdder{}
	proxy := &Proxy{
		Upstreams:  []Upstream{&fakeUpstream{answers: []netip.Addr{netip.MustParseAddr("142.250.1.1"), netip.MustParseAddr("10.0.0.1")}}},
		StripAAAA:  true,
		MinTimeout: time.Hour,
		Adder:      adder,
	}
	proxy.SetState(&State{Matcher: NewMatcher([][]string{{"youtube.com"}}), Routes: []Route{{Section: "yt"}}})

	if response := proxy.Handle(context.Background(), buildQuery(t, "www.youtube.com.", dnsmessage.TypeA)); response == nil {
		t.Fatal("no answer")
	}
	if len(adder.elements) != 1 || adder.elements[0].Set != "s_yt_dns" || adder.elements[0].Address.String() != "142.250.1.1" || adder.elements[0].Timeout != time.Hour {
		t.Fatalf("learned %+v, want only the public address with the minimum timeout", adder.elements)
	}

	proxy.Handle(context.Background(), buildQuery(t, "example.org.", dnsmessage.TypeA))
	if len(adder.elements) != 1 {
		t.Fatal("an unrouted domain must not be learned")
	}

	response := proxy.Handle(context.Background(), buildQuery(t, "www.youtube.com.", dnsmessage.TypeAAAA))
	var parser dnsmessage.Parser
	header, err := parser.Start(response)
	if err != nil || header.ID != 0x1234 || !header.Response {
		t.Fatalf("AAAA answer header %+v, %v", header, err)
	}
	_ = parser.SkipAllQuestions()
	if _, err := parser.AnswerHeader(); err != dnsmessage.ErrSectionDone {
		t.Fatal("AAAA for a routed domain must be empty")
	}
}
