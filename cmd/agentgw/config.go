package main

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/midspan-dev/agentgw/pkg/contracts"
	"gopkg.in/yaml.v3"
)

var (
	currencyRe = regexp.MustCompile(`^[A-Z]{3}$`)
	serverRe   = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	headerRe   = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
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
	// *UpstreamAuth cannot tell `auth: null` from absent; null would silently drop the credential.
	var probe struct {
		Upstreams []struct {
			Auth yaml.Node `yaml:"auth"`
		} `yaml:"upstreams"`
	}
	if err := yaml.Unmarshal(raw, &probe); err == nil {
		for i, u := range probe.Upstreams {
			if u.Auth.Kind != 0 && u.Auth.Kind != yaml.MappingNode {
				return nil, fmt.Errorf("config %s: upstreams[%d].auth must be an object", path, i)
			}
			// The Go types cannot tell a present-empty string from an absent one.
			var m map[string]any
			u.Auth.Decode(&m)
			for _, k := range []string{"issuer", "token_file"} {
				if v, ok := m[k]; ok && v == "" {
					return nil, fmt.Errorf("config %s: upstreams[%d].auth.%s must not be empty", path, i, k)
				}
			}
		}
	}
	if err := validate(&c); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	dir := filepath.Dir(path)
	paths := []*string{&c.PolicyPath, &c.Ledger.Path, &c.KeyPath, &c.StatePath, &c.Approvals.CLI.TokenPath}
	for _, u := range c.Upstreams {
		if u.Auth != nil && u.Auth.SecretFile != "" {
			paths = append(paths, &u.Auth.SecretFile)
		}
		if u.Auth != nil && u.Auth.TokenFile != "" {
			paths = append(paths, &u.Auth.TokenFile)
		}
	}
	for _, p := range paths {
		if !filepath.IsAbs(*p) {
			*p = filepath.Join(dir, *p)
		}
	}
	// After state_path is resolved, so every reader sees one absolute path.
	for _, u := range c.Upstreams {
		if u.Auth != nil && u.Auth.Kind == contracts.AuthKindAuthorizationCode && u.Auth.TokenFile == "" {
			u.Auth.TokenFile = filepath.Join(filepath.Dir(c.StatePath), "tokens", u.Name+".json")
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
		if u.Auth != nil {
			validateAuth(i, u, bad)
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

func validateAuth(i int, u contracts.Upstream, bad func(string, ...any)) {
	a := u.Auth
	if u.URL == "" {
		bad("upstreams[%d].auth: only allowed on url upstreams", i)
	} else if !secureURL(u.URL) {
		bad("upstreams[%d]: url must be an https URL (http only for localhost) when it has auth: the credential travels with every request", i)
	}
	exactlyOne := func() {
		if (a.SecretEnv == "") == (a.SecretFile == "") {
			bad("upstreams[%d].auth: exactly one of secret_env, secret_file is required", i)
		}
	}
	if a.Issuer != "" && a.Kind != contracts.AuthKindAuthorizationCode {
		bad("upstreams[%d].auth: issuer is only allowed with kind authorization_code", i)
	}
	if a.TokenFile != "" && a.Kind != contracts.AuthKindAuthorizationCode {
		bad("upstreams[%d].auth: token_file is only allowed with kind authorization_code", i)
	}
	switch a.Kind {
	case contracts.AuthKindHeader:
		exactlyOne()
		if !headerRe.MatchString(a.Header) {
			bad("upstreams[%d].auth: header is required and must match %s", i, headerRe)
		}
		if a.TokenURL != "" || a.ClientID != "" || len(a.Scopes) > 0 || a.Resource != "" {
			bad("upstreams[%d].auth: token_url, client_id, scopes and resource are not allowed with kind header", i)
		}
	case contracts.AuthKindClientCredentials:
		exactlyOne()
		if a.TokenURL == "" || a.ClientID == "" {
			bad("upstreams[%d].auth: token_url and client_id are required with kind client_credentials", i)
		}
		if a.TokenURL != "" && !secureURL(a.TokenURL) {
			bad("upstreams[%d].auth: token_url must be an https URL (http only for localhost)", i)
		}
		if a.Header != "" || a.Prefix != "" {
			bad("upstreams[%d].auth: header and prefix are not allowed with kind client_credentials", i)
		}
	case contracts.AuthKindAuthorizationCode:
		if a.Header != "" || a.Prefix != "" || a.TokenURL != "" {
			bad("upstreams[%d].auth: header, prefix and token_url are not allowed with kind authorization_code", i)
		}
		if a.SecretEnv != "" && a.SecretFile != "" {
			bad("upstreams[%d].auth: at most one of secret_env, secret_file", i)
		}
		if a.Issuer != "" && !validIssuer(a.Issuer) {
			bad("upstreams[%d].auth: issuer must be an https URL (http only for localhost) without query or fragment", i)
		}
		if (a.SecretEnv != "" || a.SecretFile != "") && a.Issuer == "" {
			bad("upstreams[%d].auth: issuer is required with a client secret", i)
		}
	default:
		bad("upstreams[%d].auth: kind must be header, client_credentials or authorization_code", i)
	}
}

func validIssuer(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.User != nil || strings.HasSuffix(s, "#") {
		return false
	}
	return secureURL(s)
}

// secureURL reports whether a secret may be sent to s: https, or http to this machine.
func secureURL(s string) bool {
	u, err := url.Parse(s)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		h := u.Hostname()
		return h == "127.0.0.1" || h == "localhost" || h == "::1"
	}
	return false
}
