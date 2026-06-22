package unit_test

import (
	"context"
	"testing"
	"time"

	httpmod "github.com/kitfind/kitfind/internal/http"
)

func TestHTTPAnalyze(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping network test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := httpmod.Analyze(ctx, "https://example.com", 10*time.Second, "KitFind-Test/1.0")
	if err != nil {
		t.Fatalf("HTTP analyze failed: %v", err)
	}

	if result.StatusCode != 200 {
		t.Errorf("expected status 200, got %d", result.StatusCode)
	}

	if result.SecurityScore < 0 || result.SecurityScore > 100 {
		t.Errorf("security score %d out of range [0, 100]", result.SecurityScore)
	}

	if len(result.Checks) == 0 {
		t.Error("expected non-empty header checks")
	}


	for _, check := range result.Checks {
		if check.Name == "" {
			t.Error("check has empty name")
		}
		validStatus := map[string]bool{"good": true, "warning": true, "missing": true, "bad": true, "info": true}
		if !validStatus[check.Status] && check.Status != "" {
			t.Errorf("check %q has invalid status %q", check.Name, check.Status)
		}
	}
}
