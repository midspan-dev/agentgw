package reload

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/midspan-dev/agentgw/internal/policy"
	"github.com/midspan-dev/agentgw/pkg/contracts"
)

const allow = "version: \"1\"\ncurrency: USD\nrules:\n  - id: allow-all\n    effect: allow\n    tools: [\"*\"]\n"
const deny = allow + "  - id: no-echo\n    effect: deny\n    tools: [\"s.echo\"]\n"

type fixture struct {
	t    *testing.T
	path string
	d    *Decider
	errb *bytes.Buffer
	tick time.Time
}

// put writes the file and forces a distinct mtime.
func (f *fixture) put(s string) {
	f.t.Helper()
	if err := os.WriteFile(f.path, []byte(s), 0o600); err != nil {
		f.t.Fatal(err)
	}
	f.tick = f.tick.Add(time.Hour)
	if err := os.Chtimes(f.path, f.tick, f.tick); err != nil {
		f.t.Fatal(err)
	}
}

func newFixture(t *testing.T, initial string) *fixture {
	t.Helper()
	f := &fixture{t: t, path: filepath.Join(t.TempDir(), "policy.yaml"), errb: &bytes.Buffer{}, tick: time.Unix(1_700_000_000, 0)}
	f.put(initial)
	p, err := policy.Compile([]byte(initial))
	if err != nil {
		t.Fatal(err)
	}
	f.d = New(f.path, p, f.errb, time.Now, WithCurrency("USD"))
	return f
}

func (f *fixture) decide() contracts.DecisionOutput {
	f.t.Helper()
	out, err := f.d.Decide(context.Background(), contracts.DecisionInput{
		Version: contracts.SchemaVersion,
		Action:  contracts.Action{Server: "s", Tool: "echo"},
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return out
}

func (f *fixture) lines(sub string) int { return strings.Count(f.errb.String(), sub) }

func TestUnchangedNoRecompile(t *testing.T) {
	f := newFixture(t, allow)
	p := f.d.Active()
	for i := 0; i < 3; i++ {
		f.decide()
	}
	if f.d.Active() != p || f.errb.Len() != 0 {
		t.Fatalf("recompiled: %q", f.errb.String())
	}
}

func TestChangeReloads(t *testing.T) {
	f := newFixture(t, allow)
	v1 := f.decide().PolicyVersion
	f.put(deny)
	v2 := f.decide().PolicyVersion
	f.decide()
	if v1 == v2 || f.d.Active().Version() != v2 || f.lines("policy reloaded: version "+v2[:8]) != 1 || f.lines("\n") != 1 {
		t.Fatalf("v1=%s v2=%s stderr=%q", v1, v2, f.errb.String())
	}
}

func TestInvalidKeepsAndRecovers(t *testing.T) {
	f := newFixture(t, deny)
	v1 := f.decide().PolicyVersion
	f.put("rules: [not valid")
	for i := 0; i < 10; i++ {
		if f.decide().PolicyVersion != v1 {
			t.Fatal("version changed on invalid file")
		}
	}
	if f.lines("policy.yaml invalid, keeping version "+v1[:8]) != 1 || f.lines("\n") != 1 {
		t.Fatalf("stderr=%q", f.errb.String())
	}
	f.put(allow)
	if f.decide().PolicyVersion == v1 || f.lines("policy reloaded") != 1 {
		t.Fatalf("no recovery: %q", f.errb.String())
	}
}

func TestDeletedKeepsOld(t *testing.T) {
	f := newFixture(t, deny)
	v1 := f.decide().PolicyVersion
	os.Remove(f.path)
	for i := 0; i < 5; i++ {
		f.decide()
	}
	if f.d.Active().Version() != v1 || f.lines("invalid, keeping version") != 1 {
		t.Fatalf("stderr=%q", f.errb.String())
	}
	f.put(allow)
	if f.decide().PolicyVersion == v1 {
		t.Fatal("did not recover after file returned")
	}
}

// Pins the documented limitation: same size and mtime, different bytes.
func TestSameStatNotDetected(t *testing.T) {
	f := newFixture(t, deny)
	p := f.d.Active()
	b := []byte(strings.Replace(deny, "no-echo", "no-ecKo", 1))
	os.WriteFile(f.path, b, 0o600)
	os.Chtimes(f.path, f.tick, f.tick)
	f.decide()
	if f.d.Active() != p || f.errb.Len() != 0 {
		t.Fatalf("unexpectedly detected: %q", f.errb.String())
	}
}

func TestBudgetsChangedWarnsOnce(t *testing.T) {
	f := newFixture(t, allow)
	f.put(deny + "budgets:\n  - agent: \"*\"\n    tool: \"s.echo\"\n    limits:\n      per_run: 1\n")
	if out := f.decide(); out.RuleID != "no-echo" {
		t.Fatalf("new rules not applied: %+v", out)
	}
	f.decide()
	if f.lines("budgets changed; restart the gateway to apply them") != 1 || f.lines("policy reloaded") != 1 {
		t.Fatalf("stderr=%q", f.errb.String())
	}
}

func TestConcurrentSwap(t *testing.T) {
	f := newFixture(t, allow)
	v1 := f.d.Active().Version()
	p2, err := policy.Compile([]byte(deny))
	if err != nil {
		t.Fatal(err)
	}
	v2 := p2.Version()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if v := f.decide().PolicyVersion; v != v1 && v != v2 {
					t.Errorf("unexpected version %s", v)
				}
			}
		}()
	}
	f.put(deny)
	wg.Wait()
	if f.d.Active().Version() != v2 {
		t.Fatal("swap not applied")
	}
}
