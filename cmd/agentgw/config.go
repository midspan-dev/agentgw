package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/midspan-dev/agentgw/pkg/contracts"
	"gopkg.in/yaml.v3"
)

var (
	currencyRe = regexp.MustCompile(`^[A-Z]{3}$`)
	serverRe   = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// loadConfig reads a config file (YAML or JSON) per contracts/config.schema.json
// and resolves relative paths against the file's directory.
func loadConfig(path string) (*contracts.Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true) // additionalProperties: false
	var c contracts.Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	if err := validate(&c); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	dir := filepath.Dir(path)
	for _, p := range []*string{&c.PolicyPath, &c.Ledger.Path, &c.KeyPath, &c.StatePath, &c.Approvals.CLI.TokenPath} {
		if !filepath.IsAbs(*p) {
			*p = filepath.Join(dir, *p)
		}
	}
	return &c, nil
}

// validate checks what the schema requires beyond the Go types.
func validate(c *contracts.Config) error {
	var errs []error
	bad := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }
	if c.Version != contracts.SchemaVersion {
		bad("version must be %q", contracts.SchemaVersion)
	}
	if c.Agent.ID == "" || c.Agent.Owner == "" {
		bad("agent.id and agent.owner are required")
	}
	if !currencyRe.MatchString(c.Currency) {
		bad("currency must be an ISO 4217 code like USD")
	}
	if len(c.Upstreams) == 0 {
		bad("upstreams: at least one is required")
	}
	seen := map[string]bool{}
	for i, u := range c.Upstreams {
		if !serverRe.MatchString(u.Name) {
			bad("upstreams[%d].name must match %s", i, serverRe)
		}
		if seen[u.Name] {
			bad("upstreams[%d].name %q is a duplicate", i, u.Name)
		}
		seen[u.Name] = true
		switch {
		case len(u.Command) > 0 && u.URL == "" && u.Path == "":
		case len(u.Command) == 0 && u.URL != "" && len(u.Path) > 0 && u.Path[0] == '/':
		default:
			bad("upstreams[%d]: exactly one of command, or url with a path starting with /", i)
		}
	}
	for i, p := range c.Prices {
		if p.Server == "" || p.Tool == "" || p.PerCall < 0 || p.ArgMultiplier < 0 {
			bad("prices[%d]: server and tool required, per_call and arg_multiplier >= 0", i)
		}
	}
	for name, v := range map[string]string{"policy_path": c.PolicyPath, "ledger.path": c.Ledger.Path,
		"key_path": c.KeyPath, "state_path": c.StatePath, "approvals.cli.token_path": c.Approvals.CLI.TokenPath} {
		if v == "" {
			bad("%s is required", name)
		}
	}
	if c.Ledger.CheckpointEvery < 1 {
		bad("ledger.checkpoint_every must be >= 1")
	}
	return errors.Join(errs...)
}
