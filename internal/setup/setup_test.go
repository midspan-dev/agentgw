package setup

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/midspan-dev/agentgw/internal/harness"
	"github.com/midspan-dev/agentgw/internal/policy"
)

var now = time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)

func TestStarterPolicy(t *testing.T) {
	var names []string
	for _, tl := range harness.DefaultTools(t) {
		names = append(names, tl.Name)
	}
	p := string(StarterPolicy("harness", names, true, now))
	if _, err := policy.Compile([]byte(p)); err != nil {
		t.Fatal(err, p)
	}
	want := `tools: ["harness.delete_everything", "harness.refund"]`
	if !strings.Contains(p, want) || strings.Contains(p, "#   tools") {
		t.Fatalf("review-destructive wrong:\n%s", p)
	}
	for _, tc := range []struct {
		tools      []string
		discovered bool
		rule       bool
	}{{[]string{"echo"}, true, false}, {nil, false, false}} {
		p := string(StarterPolicy("harness", tc.tools, tc.discovered, now))
		if _, err := policy.Compile([]byte(p)); err != nil {
			t.Fatal(err, p)
		}
		if !strings.Contains(p, "  # - id: review-destructive") || strings.Contains(p, "\n  - id: review-destructive") {
			t.Fatalf("rule should be commented out:\n%s", p)
		}
	}
	if !strings.Contains(string(StarterPolicy("h", nil, false, now)), "not listed") {
		t.Fatal("template header missing")
	}
	// a hostile tool name must not reach the file
	bad := string(StarterPolicy("h", []string{"x\n  - id: evil", "ok"}, true, now))
	if strings.Contains(bad, "evil") {
		t.Fatal("unsafe tool name written")
	}
}

func TestVerbs(t *testing.T) {
	for n, want := range map[string]bool{"deleteUser": true, "user_delete": true, "send-mail": true, "undeletable": false, "sender": false, "HTTPSend": true} {
		if isDestructive(n) != want {
			t.Errorf("isDestructive(%q) != %v", n, want)
		}
	}
}

func opts(dir string) Options {
	return Options{Dir: dir, Name: "srv", AgentID: "a", Owner: "o@x", Yes: true, NoDiscover: true,
		Command: []string{"echo", "hi"}, Executable: "/bin/agentgw", Now: func() time.Time { return now },
		LookPath: func(string) (string, error) { return "", exec.ErrNotFound }}
}

func TestRunTwice(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "gw")
	var out bytes.Buffer
	if err := Run(context.Background(), opts(dir), nil, &out); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"agentgw.yaml", "policy.yaml", "ledger.key", "approver.key"} {
		if !strings.Contains(out.String(), "created  "+filepath.Join(dir, f)) {
			t.Errorf("no created line for %s:\n%s", f, out.String())
		}
	}
	type snap struct {
		b []byte
		m time.Time
	}
	read := func() map[string]snap {
		m := map[string]snap{}
		es, _ := os.ReadDir(dir)
		for _, e := range es {
			b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
			fi, _ := e.Info()
			m[e.Name()] = snap{b, fi.ModTime()}
		}
		return m
	}
	before := read()
	out.Reset()
	time.Sleep(10 * time.Millisecond)
	if err := Run(context.Background(), opts(dir), nil, &out); err != nil {
		t.Fatal(err)
	}
	after := read()
	for f, s := range before {
		if !bytes.Equal(s.b, after[f].b) || !s.m.Equal(after[f].m) {
			t.Errorf("%s changed on second run", f)
		}
		if !strings.Contains(out.String(), "kept     "+filepath.Join(dir, f)) {
			t.Errorf("no kept line for %s:\n%s", f, out.String())
		}
	}
	if len(after) != 4 || strings.Contains(out.String(), "created") {
		t.Fatalf("second run wrote something:\n%s", out.String())
	}
}

// fakeClaude installs a claude script logging its argv; getRC is the exit
// status of `mcp get`.
func fakeClaude(t *testing.T, getRC int) (lookPath func(string) (string, error), log string) {
	t.Helper()
	d := t.TempDir()
	log = filepath.Join(d, "argv")
	script := "#!/bin/sh\necho \"$@\" >> " + log + "\nif [ \"$2\" = get ]; then echo 'entry: srv, scope: user'; exit " + string(rune('0'+getRC)) + "; fi\n"
	p := filepath.Join(d, "claude")
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return func(string) (string, error) { return p, nil }, log
}

func TestRegister(t *testing.T) {
	cwd, _ := os.Getwd()
	for scope, line := range map[string]string{
		"user":    "available in Claude Code from any directory (scope user)",
		"local":   "available only when claude runs from " + cwd + " (scope local)",
		"project": "written to " + cwd + "/.mcp.json; available to anyone who opens this project (scope project)",
	} {
		lp, log := fakeClaude(t, 1)
		o := opts(filepath.Join(t.TempDir(), "gw"))
		o.LookPath, o.Scope = lp, scope
		var out bytes.Buffer
		if err := Run(context.Background(), o, nil, &out); err != nil {
			t.Fatal(err)
		}
		cfg := filepath.Join(o.Dir, "agentgw.yaml")
		add := "mcp add --scope " + scope + " srv -- /bin/agentgw run --config " + cfg + " --server srv"
		got, _ := os.ReadFile(log)
		if string(got) != "mcp get srv\n"+add+"\n" {
			t.Errorf("%s: argv log %q", scope, got)
		}
		if !strings.Contains(out.String(), "registered with Claude Code: claude "+add+"\n         "+line) {
			t.Errorf("%s: output\n%s", scope, out.String())
		}
	}
}

func TestRegisterExisting(t *testing.T) {
	lp, log := fakeClaude(t, 0)
	o := opts(filepath.Join(t.TempDir(), "gw"))
	o.LookPath = lp
	var out bytes.Buffer
	if err := Run(context.Background(), o, nil, &out); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(log); string(got) != "mcp get srv\n" {
		t.Fatalf("add was called: %q", got)
	}
	if !strings.Contains(out.String(), "already registered with Claude Code as \"srv\"\nentry: srv, scope: user") {
		t.Fatal(out.String())
	}
}

func TestClaudeAbsent(t *testing.T) {
	var out bytes.Buffer
	if err := Run(context.Background(), opts(filepath.Join(t.TempDir(), "gw")), nil, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "register it yourself: claude mcp add --scope user srv -- /bin/agentgw run --config ") ||
		!strings.Contains(out.String(), "(scope user)") {
		t.Fatal(out.String())
	}
}

func TestYesWithoutCommand(t *testing.T) {
	o := opts(filepath.Join(t.TempDir(), "gw"))
	o.Command = nil
	if err := Run(context.Background(), o, nil, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "--") {
		t.Fatalf("want usage error naming --, got %v", err)
	}
	if _, err := os.Stat(o.Dir); err == nil {
		t.Fatal("directory created")
	}
}

func TestPrompts(t *testing.T) {
	o := opts(filepath.Join(t.TempDir(), "gw"))
	o.Yes, o.Command, o.Name, o.AgentID, o.Owner = false, nil, "", "", ""
	var out bytes.Buffer
	// command, name (default accepted via Enter blank), agent, owner
	if err := Run(context.Background(), o, strings.NewReader("npx -y @scope/server-everything\n\nbob\nb@x\n"), &out); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(o.Dir, "agentgw.yaml"))
	for _, w := range []string{`name: "server-everything"`, `id: "bob"`, `owner: "b@x"`, `"@scope/server-everything"`} {
		if !strings.Contains(string(b), w) {
			t.Errorf("config lacks %s:\n%s", w, b)
		}
	}
}
