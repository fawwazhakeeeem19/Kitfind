package unit_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/kitfind/kitfind/internal/dns"
)

func TestCleanDomain(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"example.com", "example.com"},
		{"https://example.com", "example.com"},
		{"http://example.com/path", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"  example.com  ", "example.com"},
		{"example.com:443", "example.com"},
	}

	for _, tc := range cases {
		got := dns.CleanDomain(tc.input)
		if got != tc.want {
			t.Errorf("CleanDomain(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestAnalyzeRealDomain(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	a := dns.NewAnalyzer([]string{"8.8.8.8:53"}, 10*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := a.Analyze(ctx, "example.com")
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if result.Domain != "example.com" {
		t.Errorf("expected domain example.com, got %s", result.Domain)
	}

	hasA := false
	for _, r := range result.Records {
		if r.Type == dns.TypeA {
			hasA = true
			break
		}
	}
	if !hasA {
		t.Error("expected at least one A record for example.com")
	}
}

func TestSubdomainEnumeration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	a := dns.NewAnalyzer(nil, 10*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	subs := a.EnumerateSubdomains(ctx, "google.com")


	hasWWW := false
	for _, s := range subs {
		if strings.HasPrefix(s.Subdomain, "www.") {
			hasWWW = true
		}
	}
	if !hasWWW {
		t.Error("expected www.google.com in subdomain results")
	}
}
