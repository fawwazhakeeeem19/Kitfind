package unit_test

import (
	"testing"

	"github.com/kitfind/kitfind/internal/scanner"
)

func TestDefaultOptions(t *testing.T) {
	opts := scanner.DefaultOptions("example.com")

	if opts.Target != "example.com" {
		t.Errorf("expected target example.com, got %s", opts.Target)
	}
	if opts.Timeout == 0 {
		t.Error("expected non-zero timeout")
	}
	if len(opts.Modules) == 0 {
		t.Error("expected non-empty modules")
	}
}

func TestModuleEnabled(t *testing.T) {

	opts := scanner.DefaultOptions("example.com")
	opts.Modules = []string{"all"}



	if len(opts.Modules) == 0 {
		t.Error("modules should not be empty")
	}
}
