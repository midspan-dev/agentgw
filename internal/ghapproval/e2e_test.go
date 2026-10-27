package ghapproval

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/midspan-dev/agentgw/internal/approval"
	"github.com/midspan-dev/agentgw/internal/harness"
	"github.com/midspan-dev/agentgw/pkg/contracts"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const e2ePolicy = `version: "1"
currency: USD
rules:
  - id: refunds-need-approval
    effect: require_approval
    tools: ["harness.refund"]
    timeout: 60s
  - id: allow-all
    effect: allow
    tools: ["*"]
`

// TestE2EGitHubApproval holds a refund in `agentgw run` (harness client and
// server) and approves it with a comment on a fake GitHub, polled by Run
// against the same state database.
func TestE2EGitHubApproval(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "agentgw")
	if out, err := exec.Command("go", "build", "-o", bin, "github.com/midspan-dev/agentgw/cmd/agentgw").CombinedOutput(); err != nil {
		t.Fatalf("build agentgw: %v\n%s", err, out)
	}
	target := harness.StartServer(t, harness.Options{Tools: harness.DefaultTools(t)})
	cfgPath := filepath.Join(dir, "agentgw.json")
	cfg := map[string]any{
		"version": "1", "agent": map[string]any{"id": "test-agent", "owner": "test@example.com"}, "currency": "USD",
		"listen": "", "upstreams": []any{map[string]any{"name": "harness", "command": target.Command}},
		"policy_path": "policy.yaml",
		"prices":      []any{map[string]any{"server": "*", "tool": "refund", "per_call": 0, "arg_field": "amount", "arg_multiplier": 1}},
		"redaction":   map[string]any{"fields": []string{}, "patterns": []string{}},
		"approvals":   map[string]any{"cli": map[string]any{"token_path": "approver.key"}},
		"ledger":      map[string]any{"path": "ledger.jsonl", "checkpoint_every": 2},
		"key_path":    "ledger.key", "state_path": "agentgw.db",
	}
	b, _ := json.Marshal(cfg)
	for path, data := range map[string][]byte{cfgPath: b, filepath.Join(dir, "policy.yaml"): []byte(e2ePolicy)} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"keygen", "--config", cfgPath}, {"approvals", "init", "--config", cfgPath}} {
		if out, err := exec.Command(bin, args...).CombinedOutput(); err != nil {
			t.Fatalf("agentgw %v: %v\n%s", args, err, out)
		}
	}

	store, err := approval.Open(filepath.Join(dir, "agentgw.db"), filepath.Join(dir, "approver.key"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	f := newFake(t)
	f.perms["alice"] = "write"
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		Run(ctx, Options{
			Config: contracts.GitHubApprovals{Repo: "o/r", Issue: 7, MinPermission: "write", PollInterval: "20ms"},
			Token:  "tok", APIBase: f.srv.URL, Store: store,
		})
		close(done)
	}()
	defer func() { cancel(); <-done }()

	client := harness.NewClient(t, harness.Target{Command: []string{bin, "run", "--config", cfgPath}})
	type result struct {
		res *mcp.CallToolResult
		err error
	}
	c := make(chan result, 1)
	go func() {
		r, err := client.Call("refund", map[string]any{"amount": 50, "charge": "ch_123"})
		c <- result{r, err}
	}()

	waitFor(t, "request comment", func() bool { return f.botsWith("harness.refund") == 1 })
	body := f.bots()[0]
	ref := body[len(body)-len("XXXXXXXX -->")-0 : len(body)-len(" -->")]
	f.add("alice", "User", "/approve "+ref)

	r := <-c
	if r.err != nil || r.res.IsError || r.res.Content[0].(*mcp.TextContent).Text != `{"amount":50,"charge":"ch_123"}` {
		t.Fatalf("call: %v %+v", r.err, r.res)
	}
	waitFor(t, "outcome comment", func() bool { return f.botsWith("approved by @alice") == 1 })

	lf, err := os.Open(filepath.Join(dir, "ledger.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer lf.Close()
	var entry *contracts.Entry
	for sc := bufio.NewScanner(lf); sc.Scan(); {
		var e contracts.Entry
		if json.Unmarshal(sc.Bytes(), &e) == nil && e.Type == contracts.LineTypeEntry {
			entry = &e
		}
	}
	if entry == nil || entry.Decision.Approval == nil || entry.Decision.Approval.Via == nil ||
		entry.Decision.Approval.Via.User != "alice" || entry.Decision.Approval.Via.Surface != "github" {
		t.Fatalf("ledger entry lacks decision.approval.via: %+v", entry)
	}
	if out, err := exec.Command(bin, "verify", "--config", cfgPath).CombinedOutput(); err != nil {
		t.Fatalf("verify: %v %s", err, out)
	}
}
