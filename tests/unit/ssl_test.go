package unit_test

import (
	"context"
	"testing"
	"time"

	"github.com/kitfind/kitfind/internal/ssl"
)

func TestSSLInspect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := ssl.Inspect(ctx, "example.com", 10*time.Second)
	if err != nil {
		t.Fatalf("SSL inspect failed: %v", err)
	}

	if result.Certificate == nil {
		t.Fatal("expected certificate in result")
	}

	if result.Certificate.Subject.CommonName == "" {
		t.Error("expected non-empty CommonName")
	}

	validGrades := map[string]bool{"A+": true, "A": true, "B": true, "C": true, "F": true}
	if !validGrades[result.Grade] {
		t.Errorf("unexpected grade %q", result.Grade)
	}

	if result.TLSVersion == "" {
		t.Error("expected non-empty TLS version")
	}
}

func TestSSLInvalidHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := ssl.Inspect(ctx, "invalid-host-that-does-not-exist.example", 3*time.Second)
	if err == nil {
		t.Error("expected error for invalid host, got nil")
	}
}
