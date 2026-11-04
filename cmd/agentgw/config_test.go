package main

import (
	"fmt"
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

const authCfg = `{"version":"1","agent":{"id":"a","owner":"o"},"currency":"USD","listen":"127.0.0.1:0","upstreams":[%s],
"policy_path":"p.yaml","prices":[],"redaction":{"fields":[],"patterns":[]},"approvals":{"cli":{"token_path":"t"}},
"ledger":{"path":"l","checkpoint_every":1},"key_path":"k","state_path":"s"}`

func TestLoadConfigTokenFile(t *testing.T) {
	dir := t.TempDir()
	for name, tc := range map[string]struct{ auth, state, want string }{
		"default":   {`"kind":"authorization_code"`, "s", filepath.Join(dir, "tokens", "u.json")},
		"state_dir": {`"kind":"authorization_code"`, "st/s", filepath.Join(dir, "st", "tokens", "u.json")},
		"relative":  {`"kind":"authorization_code","token_file":"sub/t.json"`, "s", filepath.Join(dir, "sub/t.json")},
		"absolute":  {`"kind":"authorization_code","token_file":"/x/t.json"`, "s", "/x/t.json"},
	} {
		p := filepath.Join(dir, "c.json")
		src := fmt.Sprintf(authCfg, `{"name":"u","url":"https://x","path":"/u","auth":{`+tc.auth+`}}`)
		src = strings.Replace(src, `"state_path":"s"`, `"state_path":"`+tc.state+`"`, 1)
		os.WriteFile(p, []byte(src), 0o600)
		c, err := loadConfig(p)
		if err != nil {
			t.Fatal(name, err)
		}
		if got := c.Upstreams[0].Auth.TokenFile; got != tc.want {
			t.Errorf("%s: token_file %q, want %q", name, got, tc.want)
		}
	}
}

func TestLoadConfigAuth(t *testing.T) {
	const hdr = `"kind":"header","header":"X-Api-Key","secret_env":"K"`
	const cc = `"kind":"client_credentials","token_url":"https://t/token","client_id":"id","secret_env":"K"`
	const ac = `"kind":"authorization_code"`
	const u = `{"name":"u","url":"https://x","path":"/u","auth":{`
	for _, tc := range []struct{ name, up, want string }{
		{"no auth", `{"name":"u","url":"http://x","path":"/u"}`, ""},
		{"http url with header", `{"name":"u","url":"http://x","path":"/u","auth":{` + hdr + `}}`, "url must be an https URL"},
		{"http url with cc", `{"name":"u","url":"http://x","path":"/u","auth":{` + cc + `}}`, "url must be an https URL"},
		{"http url with ac", `{"name":"u","url":"http://x","path":"/u","auth":{` + ac + `}}`, "url must be an https URL"},
		{"relative url with header", `{"name":"u","url":"x","path":"/u","auth":{` + hdr + `}}`, "url must be an https URL"},
		{"http loopback url", `{"name":"u","url":"http://127.0.0.1:9/mcp","path":"/u","auth":{` + hdr + `}}`, ""},
		{"http localhost url", `{"name":"u","url":"http://localhost:9/mcp","path":"/u","auth":{` + hdr + `}}`, ""},
		{"http ipv6 loopback url", `{"name":"u","url":"http://[::1]:9/mcp","path":"/u","auth":{` + hdr + `}}`, ""},
		{"lookalike loopback url", `{"name":"u","url":"http://127.0.0.1.evil.example/mcp","path":"/u","auth":{` + hdr + `}}`, "url must be an https URL"},
		{"cc http token_url", u + `"kind":"client_credentials","token_url":"http://t/token","client_id":"i","secret_env":"K"}}`, "token_url must be an https URL"},
		{"cc relative token_url", u + `"kind":"client_credentials","token_url":"t/token","client_id":"i","secret_env":"K"}}`, "token_url must be an https URL"},
		{"cc http loopback token_url", u + `"kind":"client_credentials","token_url":"http://127.0.0.1:9/token","client_id":"i","secret_env":"K"}}`, ""},
		{"header ok", u + hdr + `,"prefix":"Bearer "}}`, ""},
		{"cc ok", u + cc + `,"scopes":["a"],"resource":"r"}}`, ""},
		{"command upstream", `{"name":"c","command":["x"],"auth":{` + hdr + `}}`, "only allowed on url upstreams"},
		{"bad kind", u + `"kind":"basic","secret_env":"K"}}`, "kind must be header, client_credentials or authorization_code"},
		{"no secret", u + `"kind":"header","header":"X"}}`, "exactly one of secret_env, secret_file"},
		{"both secrets", u + hdr + `,"secret_file":"f"}}`, "exactly one of secret_env, secret_file"},
		{"header missing", u + `"kind":"header","secret_env":"K"}}`, "header is required"},
		{"header bad name", u + `"kind":"header","header":"X Y","secret_env":"K"}}`, "header is required"},
		{"header with token_url", u + hdr + `,"token_url":"http://t"}}`, "not allowed with kind header"},
		{"header with client_id", u + hdr + `,"client_id":"i"}}`, "not allowed with kind header"},
		{"header with scopes", u + hdr + `,"scopes":["a"]}}`, "not allowed with kind header"},
		{"header with resource", u + hdr + `,"resource":"r"}}`, "not allowed with kind header"},
		{"cc no token_url", u + `"kind":"client_credentials","client_id":"i","secret_env":"K"}}`, "token_url and client_id are required"},
		{"cc no client_id", u + `"kind":"client_credentials","token_url":"https://t","secret_env":"K"}}`, "token_url and client_id are required"},
		{"cc with header", u + cc + `,"header":"X"}}`, "not allowed with kind client_credentials"},
		{"cc with prefix", u + cc + `,"prefix":"B "}}`, "not allowed with kind client_credentials"},
		{"ac ok", u + ac + `}}`, ""},
		{"ac token_file", u + ac + `,"token_file":"t.json"}}`, ""},
		{"ac full", u + ac + `,"issuer":"https://idp.example","client_id":"i","secret_env":"K","scopes":["a"],"resource":"r"}}`, ""},
		{"ac http localhost issuer", u + ac + `,"issuer":"http://127.0.0.1:9/x"}}`, ""},
		{"ac header", u + ac + `,"header":"X"}}`, "not allowed with kind authorization_code"},
		{"ac prefix", u + ac + `,"prefix":"B "}}`, "not allowed with kind authorization_code"},
		{"ac token_url", u + ac + `,"token_url":"http://t"}}`, "not allowed with kind authorization_code"},
		{"ac both secrets", u + ac + `,"issuer":"https://i.example","secret_env":"K","secret_file":"f"}}`, "at most one of secret_env, secret_file"},
		{"ac secret no issuer", u + ac + `,"secret_env":"K"}}`, "issuer is required with a client secret"},
		{"ac secret_file no issuer", u + ac + `,"secret_file":"f"}}`, "issuer is required with a client secret"},
		{"ac http issuer", u + ac + `,"issuer":"http://idp.example"}}`, "issuer must be an https URL"},
		{"ac relative issuer", u + ac + `,"issuer":"idp.example"}}`, "issuer must be an https URL"},
		{"ac issuer query", u + ac + `,"issuer":"https://idp.example/?a=1"}}`, "issuer must be an https URL"},
		{"ac issuer fragment", u + ac + `,"issuer":"https://idp.example/#f"}}`, "issuer must be an https URL"},
		{"ac issuer userinfo", u + ac + `,"issuer":"https://u:p@idp.example"}}`, "issuer must be an https URL"},
		{"ac issuer empty fragment", u + ac + `,"issuer":"https://idp.example/#"}}`, "issuer must be an https URL"},
		{"ac empty issuer", u + ac + `,"issuer":""}}`, "issuer must not be empty"},
		{"ac empty token_file", u + ac + `,"token_file":""}}`, "token_file must not be empty"},
		{"header with token_file", u + hdr + `,"token_file":"t"}}`, "token_file is only allowed with kind authorization_code"},
		{"cc with token_file", u + cc + `,"token_file":"t"}}`, "token_file is only allowed with kind authorization_code"},
		{"header with issuer", u + hdr + `,"issuer":"https://idp.example"}}`, "issuer is only allowed with kind authorization_code"},
		{"cc with issuer", u + cc + `,"issuer":"https://idp.example"}}`, "issuer is only allowed with kind authorization_code"},
	} {
		p := filepath.Join(t.TempDir(), "c.json")
		os.WriteFile(p, []byte(fmt.Sprintf(authCfg, tc.up)), 0o600)
		_, err := loadConfig(p)
		if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: err %v, want %q", tc.name, err, tc.want)
		}
	}

	for name, up := range map[string]string{"null": `auth: null`, "empty": "auth:\n    # kind: header"} {
		y := "version: \"1\"\nupstreams:\n  - name: u\n    url: https://x\n    path: /u\n    " + up + "\n"
		p := filepath.Join(t.TempDir(), "c.yaml")
		os.WriteFile(p, []byte(y), 0o600)
		if _, err := loadConfig(p); err == nil || !strings.Contains(err.Error(), "upstreams[0].auth must be an object") {
			t.Errorf("auth %s: err %v", name, err)
		}
	}

	dir := t.TempDir()
	p := filepath.Join(dir, "c.json")
	os.WriteFile(p, []byte(fmt.Sprintf(authCfg, u+`"kind":"header","header":"X","secret_file":"sub/key"}}`)), 0o600)
	c, err := loadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := c.Upstreams[0].Auth.SecretFile, filepath.Join(dir, "sub/key"); got != want {
		t.Fatalf("secret_file %q, want %q", got, want)
	}
}
