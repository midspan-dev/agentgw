package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestWatchFlags(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"watch", "--since", "x"}, &out); err == nil || !strings.Contains(err.Error(), "--since") {
		t.Fatalf("bad --since: %v", err)
	}
	// An explicit --config that does not load is an error, not a fallback.
	missing := filepath.Join(t.TempDir(), "none.yaml")
	if err := run(context.Background(), []string{"watch", "--config", missing}, &out); err == nil {
		t.Fatal("missing config accepted")
	}
	if !strings.Contains(usageText(), "agentgw watch") {
		t.Fatalf("usage lacks watch: %q", usageText())
	}
}
