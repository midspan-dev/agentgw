package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/midspan-dev/agentgw/pkg/contracts"
)

func TestLoginErrors(t *testing.T) {
	ups := `{"name":"a","url":"https://x","path":"/a","auth":{"kind":"authorization_code"}},
{"name":"h","url":"https://x","path":"/h","auth":{"kind":"header","header":"X","secret_env":"K"}},
{"name":"n","url":"http://x","path":"/n"}`
	p := filepath.Join(t.TempDir(), "c.json")
	os.WriteFile(p, []byte(fmt.Sprintf(authCfg, ups)), 0o600)
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"unknown":   {[]string{"--config", p, "zzz"}, "login: no upstream zzz"},
		"header":    {[]string{"--config", p, "h"}, "login: upstream h has no authorization_code auth"},
		"no auth":   {[]string{"--config", p, "n"}, "login: upstream n has no authorization_code auth"},
		"flags first": {[]string{"--no-browser", "--config", p, "zzz"}, "login: no upstream zzz"},
		"flags after": {[]string{"zzz", "--no-browser", "--config", p}, "login: no upstream zzz"},
		"two servers": {[]string{"zzz", "--config", p, "yyy"}, "bad usage"},
		"no server": {[]string{"--config", p}, "bad usage"},
	} {
		err := loginCmd(context.Background(), tc.args, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want %q", name, err, tc.want)
		}
	}
}

func TestReadSecret(t *testing.T) {
	t.Setenv("TEST_RS", "from-env")
	f := filepath.Join(t.TempDir(), "s")
	os.WriteFile(f, []byte("from-file\n"), 0o600)
	for name, tc := range map[string]struct {
		a    contracts.UpstreamAuth
		want string
	}{
		"env":     {contracts.UpstreamAuth{SecretEnv: "TEST_RS"}, "from-env"},
		"file":    {contracts.UpstreamAuth{SecretFile: f}, "from-file"},
		"neither": {contracts.UpstreamAuth{}, ""},
	} {
		if got, err := readSecret(tc.a); err != nil || got != tc.want {
			t.Errorf("%s: %q %v, want %q", name, got, err, tc.want)
		}
	}
	if _, err := readSecret(contracts.UpstreamAuth{SecretEnv: "TEST_RS_UNSET"}); err == nil || !strings.Contains(err.Error(), "TEST_RS_UNSET") {
		t.Errorf("unset env: %v", err)
	}
	if _, err := readSecret(contracts.UpstreamAuth{SecretFile: f + ".missing"}); err == nil || !strings.Contains(err.Error(), f+".missing") {
		t.Errorf("missing file: %v", err)
	}
}
