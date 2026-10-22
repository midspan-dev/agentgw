package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	c, err := loadConfig("../../contracts/examples/config.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join("../../contracts/examples", "ledger.jsonl"); c.Ledger.Path != want {
		t.Fatalf("ledger path %q, want %q", c.Ledger.Path, want)
	}

	src, _ := os.ReadFile("../../contracts/examples/config.example.json")
	for name, edit := range map[string][2]string{
		"unknown field": {`"listen"`, `"bogus": 1, "listen"`},
		"bad currency":  {`"USD"`, `"usd"`},
		"url no path":   {`, "path": "/search"`, ``},
		"both":          {`"name": "stripe",`, `"name": "stripe", "url": "http://x",`},
		"checkpoint 0":  {`"checkpoint_every": 100`, `"checkpoint_every": 0`},
	} {
		p := filepath.Join(t.TempDir(), "c.json")
		os.WriteFile(p, []byte(strings.Replace(string(src), edit[0], edit[1], 1)), 0o600)
		if _, err := loadConfig(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
