package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/midspan-dev/agentgw/internal/harness"
	"github.com/midspan-dev/agentgw/pkg/contracts"
)

// TestE2EInitThenRun: `agentgw init` against a harness server writes a setup
// that `agentgw run` loads, with discovered tools named in the starter policy.
func TestE2EInitThenRun(t *testing.T) {
	target := harness.StartServer(t, harness.Options{Tools: harness.DefaultTools(t)})
	dir := filepath.Join(t.TempDir(), "gw")
	args := append([]string{"init", "--dir", dir, "--yes", "--name", "harness", "--agent", "a", "--owner", "o@x", "--no-register", "--"}, target.Command...)
	if out, err := exec.Command(bin, args...).CombinedOutput(); err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	for f, mode := range map[string]os.FileMode{"agentgw.yaml": 0o644, "policy.yaml": 0o644, "ledger.key": 0o600, "approver.key": 0o600} {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil || fi.Mode().Perm() != mode {
			t.Fatalf("%s: %v mode %v, want %v", f, err, fi, mode)
		}
	}
	pol, _ := os.ReadFile(filepath.Join(dir, "policy.yaml"))
	if !strings.Contains(string(pol), `tools: ["harness.delete_everything", "harness.refund"]`) {
		t.Fatalf("policy:\n%s", pol)
	}

	cfg := filepath.Join(dir, "agentgw.yaml")
	g := &gw{t: t, dir: dir, cfg: cfg}
	g.client = harness.NewClient(t, harness.Target{Command: []string{bin, "run", "--config", cfg}})
	res, err := g.client.Call("echo", map[string]any{"n": 1})
	if err != nil || res.IsError {
		t.Fatalf("echo: %v %+v", err, res)
	}

	denied := make(chan error, 1)
	go func() {
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			out, err := exec.Command(bin, "approvals", "list", "--config", cfg).Output()
			if err != nil {
				denied <- err
				return
			}
			if line := strings.TrimSpace(string(out)); line != "" {
				f := strings.Split(line, "\t")
				denied <- exec.Command(bin, "approvals", "deny", "--config", cfg, f[0], f[2]).Run()
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		denied <- fmt.Errorf("no pending approval appeared")
	}()
	res, err = g.client.Call("delete_everything", map[string]any{})
	if derr := <-denied; derr != nil {
		t.Fatal(derr)
	}
	if err != nil || !res.IsError {
		t.Fatalf("delete_everything: %v %+v", err, res)
	}
	es := g.entries()
	if len(es) != 2 ||
		es[0].Outcome != contracts.EntryOK || es[0].Decision.RuleID != "allow-all" ||
		es[1].Outcome != contracts.EntryApprovalDenied || es[1].Decision.RuleID != "review-destructive" {
		t.Fatalf("ledger entries: %+v", es)
	}
	if out := g.cli("verify"); !strings.HasPrefix(out, "ok: ") {
		t.Fatalf("verify: %q", out)
	}
}
