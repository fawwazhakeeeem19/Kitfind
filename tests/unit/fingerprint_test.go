package unit_test

import (
	"testing"

	"github.com/kitfind/kitfind/internal/fingerprint"
)

func TestFingerprintDetectNginx(t *testing.T) {
	headers := map[string]string{
		"server": "nginx/1.24.0",
	}
	result := fingerprint.Detect(headers, "", nil)

	found := false
	for _, tech := range result.Technologies {
		if tech.Name == "Nginx" {
			found = true
			if tech.Confidence < 30 {
				t.Errorf("Nginx confidence too low: %d", tech.Confidence)
			}
		}
	}
	if !found {
		t.Error("expected Nginx to be detected from server header")
	}
}

func TestFingerprintDetectWordPress(t *testing.T) {
	body := `<html><link rel='stylesheet' href='/wp-content/themes/twentytwenty/style.css'></html>`
	result := fingerprint.Detect(nil, body, nil)

	found := false
	for _, tech := range result.Technologies {
		if tech.Name == "WordPress" {
			found = true
		}
	}
	if !found {
		t.Error("expected WordPress to be detected from body")
	}
}

func TestFingerprintEmptyInput(t *testing.T) {
	result := fingerprint.Detect(nil, "", nil)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Technologies == nil {
		t.Error("expected non-nil Technologies slice")
	}
}

func TestFingerprintSummary(t *testing.T) {
	headers := map[string]string{
		"server":      "nginx",
		"x-powered-by": "PHP/8.1",
	}
	result := fingerprint.Detect(headers, "", nil)

	if result.Summary == nil {
		t.Fatal("expected non-nil Summary map")
	}
}
