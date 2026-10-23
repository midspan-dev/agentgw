package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The config init writes must pass the loader run uses.
func TestInitConfigLoads(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "gw")
	var out bytes.Buffer
	args := []string{"--dir", dir, "--yes", "--name", "s", "--agent", "a", "--owner", "o@x", "--no-discover", "--no-register", "--", "echo", "hi"}
	if err := initCmd(context.Background(), args, &out); err != nil {
		t.Fatal(err, out.String())
	}
	cfg, err := loadConfig(filepath.Join(dir, "agentgw.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Upstreams[0].Name != "s" || len(cfg.Upstreams[0].Command) != 2 {
		t.Fatalf("%+v", cfg.Upstreams)
	}
}

// A Homebrew-style symlink on PATH that points at this binary is registered
// as the link, not its target, so the registration survives brew upgrade.
func TestRegisteredExecutableKeepsPathLink(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "agentgw")
	if err := os.Symlink(exe, link); err != nil {
		t.Fatal(err)
	}
	if got := registeredExecutable(func(string) (string, error) { return link, nil }); got != link {
		t.Fatalf("got %q, want the PATH link %q", got, link)
	}
	other := filepath.Join(t.TempDir(), "agentgw")
	if err := os.WriteFile(other, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := registeredExecutable(func(string) (string, error) { return other, nil }); got != exe {
		t.Fatalf("a different agentgw on PATH: got %q, want this binary %q", got, exe)
	}
	if got := registeredExecutable(func(string) (string, error) { return "", errors.New("not found") }); got != exe {
		t.Fatalf("none on PATH: got %q, want %q", got, exe)
	}
}
