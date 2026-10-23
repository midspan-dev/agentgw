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

// setPolicy rewrites the gateway's policy file and moves its mtime forward so
// the change is seen even when the size is unchanged.
func (g *gw) setPolicy(text string) {
	g.t.Helper()
	p := filepath.Join(g.dir, "policy.yaml")
	write(g.t, p, []byte(text))
	when := time.Now().Add(time.Duration(len(g.entries())+1) * time.Hour)
	if err := os.Chtimes(p, when, when); err != nil {
		g.t.Fatal(err)
	}
}

func (g *gw) lastVersion() string {
	g.t.Helper()
	es := g.entries()
	return es[len(es)-1].Decision.PolicyVersion
}

func TestE2EPolicyReload(t *testing.T) {
	const noEcho = `  - id: no-echo
    effect: deny
    tools: ["harness.echo"]
`
	base := fmt.Sprintf(policyTmpl, "60s")
	denyPol := strings.Replace(base, "  - id: allow-all", noEcho+"  - id: allow-all", 1)

	t.Run("edits apply to the next call", func(t *testing.T) {
		g := start(t, harness.Options{}, "60s")
		res, err := g.client.Call("echo", map[string]any{"n": 1})
		okText(t, res, err, `{"n":1}`)
		v1 := g.lastVersion()

		g.setPolicy(denyPol)
		res, err = g.client.Call("echo", map[string]any{"n": 2})
		refused(t, res, err, contracts.EntryDenied, "no-echo", "agentgw: denied by policy: denied by rule no-echo")
		v2 := g.lastVersion()
		if v2 == v1 {
			t.Fatal("policy_version did not change after reload")
		}

		g.setPolicy("rules: [not valid")
		res, err = g.client.Call("echo", map[string]any{"n": 3})
		refused(t, res, err, contracts.EntryDenied, "no-echo", "agentgw: denied by policy: denied by rule no-echo")
		if g.lastVersion() != v2 {
			t.Fatal("invalid file changed the active version")
		}

		g.setPolicy(denyPol + "\n")
		res, err = g.client.Call("echo", map[string]any{"n": 4})
		refused(t, res, err, contracts.EntryDenied, "no-echo", "agentgw: denied by policy: denied by rule no-echo")
	})

	t.Run("held call keeps the policy that held it", func(t *testing.T) {
		g := start(t, harness.Options{}, "60s")
		res, err := g.client.Call("echo", map[string]any{"n": 1})
		okText(t, res, err, `{"n":1}`)
		v1 := g.lastVersion()

		done := make(chan error, 1)
		go func() {
			deadline := time.Now().Add(20 * time.Second)
			for time.Now().Before(deadline) {
				out, err := exec.Command(bin, "approvals", "list", "--config", g.cfg).Output()
				if err != nil {
					done <- err
					return
				}
				if line := strings.TrimSpace(string(out)); line != "" {
					f := strings.Split(line, "\t")
					// The call is pending: deny refunds now, then approve it.
					g.setPolicy(strings.Replace(base, "  - id: allow-all",
						"  - id: no-refund\n    effect: deny\n    tools: [\"harness.refund\"]\n  - id: allow-all", 1))
					done <- exec.Command(bin, "approvals", "approve", "--config", g.cfg, f[0], f[2]).Run()
					return
				}
				time.Sleep(100 * time.Millisecond)
			}
			done <- fmt.Errorf("no pending approval appeared")
		}()
		res, err = g.client.CallWithProgress("refund", map[string]any{"amount": 50, "charge": "ch_1"}, "tok")
		if aerr := <-done; aerr != nil {
			t.Fatal(aerr)
		}
		okText(t, res, err, `{"amount":50,"charge":"ch_1"}`)
		es := g.entries()
		last := es[len(es)-1]
		if last.Outcome != contracts.EntryOK || last.Decision.PolicyVersion != v1 {
			t.Fatalf("held call: outcome %s version %s, want ok under %s", last.Outcome, last.Decision.PolicyVersion, v1)
		}
		// The next refund sees the new policy.
		res, err = g.client.Call("refund", map[string]any{"amount": 5, "charge": "ch_2"})
		refused(t, res, err, contracts.EntryDenied, "no-refund", "agentgw: denied by policy: denied by rule no-refund")
	})
}
