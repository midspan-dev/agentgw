// Package e2e drives the built agentgw binary end to end: harness client ->
// `agentgw run` (stdio proxy + pipeline) -> harness server, then checks the
// ledger against the harness goldens and with `agentgw verify`.
package e2e

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/midspan-dev/agentgw/internal/harness"
	"github.com/midspan-dev/agentgw/pkg/contracts"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var bin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "agentgw-e2e")
	if err != nil {
		panic(err)
	}
	bin = filepath.Join(dir, "agentgw")
	if out, err := exec.Command("go", "build", "-o", bin, "github.com/midspan-dev/agentgw/cmd/agentgw").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build agentgw: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

const policyTmpl = `version: "1"
currency: USD
budgets:
  - agent: "*"
    tool: "harness.search"
    limits:
      per_run: 0.01
rules:
  - id: no-destructive
    effect: deny
    tools: ["harness.delete_everything"]
  - id: refunds-need-approval
    effect: require_approval
    tools: ["harness.refund"]
    timeout: %s
  - id: allow-all
    effect: allow
    tools: ["*"]
`

type gw struct {
	t      *testing.T
	dir    string
	cfg    string
	pub    string
	client *harness.Client
}

// start connects a harness client to `agentgw run` in front of a harness server.
func start(t *testing.T, opts harness.Options, approvalTimeout string) *gw {
	t.Helper()
	if opts.Tools == nil {
		opts.Tools = harness.DefaultTools(t)
	}
	target := harness.StartServer(t, opts)
	g := setup(t, map[string]any{"name": "harness", "command": target.Command}, "", approvalTimeout)
	g.client = harness.NewClient(t, harness.Target{Command: []string{bin, "run", "--config", g.cfg}})
	return g
}

// setup writes a config with one upstream and the policy, and creates the
// ledger key and approver token with the CLI.
func setup(t *testing.T, upstream map[string]any, listen, approvalTimeout string) *gw {
	t.Helper()
	g := &gw{t: t, dir: t.TempDir()}
	g.cfg = filepath.Join(g.dir, "agentgw.json")
	cfg := map[string]any{
		"version":     "1",
		"agent":       map[string]any{"id": "test-agent", "owner": "test@example.com"},
		"currency":    "USD",
		"listen":      listen,
		"upstreams":   []any{upstream},
		"policy_path": "policy.yaml",
		"prices": []any{
			map[string]any{"server": "*", "tool": "search", "per_call": 0.005, "arg_field": "", "arg_multiplier": 0},
			map[string]any{"server": "*", "tool": "refund", "per_call": 0, "arg_field": "amount", "arg_multiplier": 1},
		},
		"redaction":  map[string]any{"fields": []string{}, "patterns": []string{}},
		"approvals":  map[string]any{"cli": map[string]any{"token_path": "approver.key"}},
		"ledger":     map[string]any{"path": "ledger.jsonl", "checkpoint_every": 2},
		"key_path":   "ledger.key",
		"state_path": "agentgw.db",
	}
	b, _ := json.Marshal(cfg)
	write(t, g.cfg, b)
	write(t, filepath.Join(g.dir, "policy.yaml"), []byte(fmt.Sprintf(policyTmpl, approvalTimeout)))
	g.pub = strings.TrimSpace(g.cli("keygen"))
	g.cli("approvals", "init")
	return g
}

func write(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// cli runs an agentgw subcommand with this gateway's config and returns stdout.
func (g *gw) cli(args ...string) string {
	g.t.Helper()
	if args[0] == "approvals" {
		args = append([]string{args[0], args[1], "--config", g.cfg}, args[2:]...)
	} else {
		args = append([]string{args[0], "--config", g.cfg}, args[1:]...)
	}
	var out, errb bytes.Buffer
	c := exec.Command(bin, args...)
	c.Stdout, c.Stderr = &out, &errb
	if err := c.Run(); err != nil {
		g.t.Fatalf("agentgw %v: %v\n%s", args, err, errb.String())
	}
	return out.String()
}

// check compares the ledger with golden name and verifies it with the CLI,
// both from the config and offline from file + public key.
func (g *gw) check(name string) {
	g.t.Helper()
	path := filepath.Join(g.dir, "ledger.jsonl")
	harness.Golden(g.t, name, path)
	if out := g.cli("verify"); !strings.HasPrefix(out, "ok: ") {
		g.t.Fatalf("verify: %q", out)
	}
	out, err := exec.Command(bin, "verify", path, g.pub).CombinedOutput()
	if err != nil || !strings.HasPrefix(string(out), "ok: ") {
		g.t.Fatalf("offline verify: %v %s", err, out)
	}
}

// entries reads the ledger's entry lines.
func (g *gw) entries() []contracts.Entry {
	g.t.Helper()
	f, err := os.Open(filepath.Join(g.dir, "ledger.jsonl"))
	if err != nil {
		g.t.Fatal(err)
	}
	defer f.Close()
	var out []contracts.Entry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e contracts.Entry
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			g.t.Fatal(err)
		}
		if e.Type == contracts.LineTypeEntry {
			out = append(out, e)
		}
	}
	return out
}

var callIDRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// refused asserts res is a gateway refusal with outcome, rule and text.
func refused(t *testing.T, res *mcp.CallToolResult, err error, outcome contracts.EntryOutcome, rule, text string) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	m, ok := harness.MetaOf(res)
	if !res.IsError || !ok || m.Outcome != outcome || m.RuleID != rule || !callIDRe.MatchString(m.CallID) {
		t.Fatalf("want refusal %s/%s, got isError=%v meta=%+v", outcome, rule, res.IsError, m)
	}
	if got := res.Content[0].(*mcp.TextContent).Text; got != text {
		t.Fatalf("text %q, want %q", got, text)
	}
}

func okText(t *testing.T, res *mcp.CallToolResult, err error, want string) {
	t.Helper()
	if err != nil || res.IsError {
		t.Fatalf("call failed: %v %+v", err, res)
	}
	if got := res.Content[0].(*mcp.TextContent).Text; got != want {
		t.Fatalf("text %q, want %q", got, want)
	}
}

func TestE2EAllow(t *testing.T) {
	g := start(t, harness.Options{}, "10m")
	for i := 1; i <= 5; i++ {
		res, err := g.client.Call("echo", map[string]any{"n": i})
		okText(t, res, err, fmt.Sprintf(`{"n":%d}`, i))
	}
	g.check("allow")
}

func TestE2EDeny(t *testing.T) {
	g := start(t, harness.Options{}, "10m")
	res, err := g.client.Call("delete_everything", map[string]any{"path": "/"})
	refused(t, res, err, contracts.EntryDenied, "no-destructive", "agentgw: denied by policy: denied by rule no-destructive")
	g.check("deny")
}

func TestE2EBudget(t *testing.T) {
	g := start(t, harness.Options{}, "10m")
	for i := 1; i <= 2; i++ {
		res, err := g.client.Call("search", map[string]any{"query": fmt.Sprintf("q%d", i)})
		okText(t, res, err, fmt.Sprintf(`{"query":"q%d"}`, i))
	}
	res, err := g.client.Call("search", map[string]any{"query": "q3"})
	refused(t, res, err, contracts.EntryBudgetExceeded, "", "agentgw: budget exceeded: per_run budget exceeded")
	g.check("budget")
}

func TestE2EApproval(t *testing.T) {
	g := start(t, harness.Options{}, "60s")
	approved := make(chan error, 1)
	go func() {
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			out, err := exec.Command(bin, "approvals", "list", "--config", g.cfg).Output()
			if err != nil {
				approved <- err
				return
			}
			if line := strings.TrimSpace(string(out)); line != "" {
				f := strings.Split(line, "\t")
				if f[1] != "harness.refund" || f[4] != "refunds-need-approval" {
					approved <- fmt.Errorf("unexpected pending approval %q", line)
					return
				}
				wrong := strings.Repeat("0", 64)
				if exec.Command(bin, "approvals", "approve", "--config", g.cfg, f[0], wrong).Run() == nil {
					approved <- fmt.Errorf("approve with a wrong args hash succeeded")
					return
				}
				approved <- exec.Command(bin, "approvals", "approve", "--config", g.cfg, f[0], f[2]).Run()
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		approved <- fmt.Errorf("no pending approval appeared")
	}()
	res, err := g.client.CallWithProgress("refund", map[string]any{"amount": 50, "charge": "ch_123"}, "tok")
	if aerr := <-approved; aerr != nil {
		t.Fatal(aerr)
	}
	okText(t, res, err, `{"amount":50,"charge":"ch_123"}`)
	select {
	case p := <-g.client.Progress:
		if !strings.HasPrefix(p.Message, "waiting for approval ") {
			t.Fatalf("progress %q", p.Message)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no progress notification while held")
	}
	g.check("approval")
	e := g.entries()[0]
	if a := e.Decision.Approval; a == nil || a.Decision != contracts.DecisionApproved || a.ApproverSig == "" ||
		a.CallID != e.CallID || a.ArgsHash != e.Action.ArgsHash {
		t.Fatalf("decision.approval not recorded or not bound to the call: %+v (call %s, args_hash %s)", a, e.CallID, e.Action.ArgsHash)
	}
}

func TestE2ETimeout(t *testing.T) {
	g := start(t, harness.Options{}, "1s")
	res, err := g.client.Call("refund", map[string]any{"amount": 50, "charge": "ch_123"})
	refused(t, res, err, contracts.EntryApprovalTimeout, "refunds-need-approval", "agentgw: approval timed out")
	g.check("timeout")
}

func TestE2EUpstreamError(t *testing.T) {
	g := start(t, harness.Options{FailNext: 1}, "10m")
	if _, err := g.client.Call("echo", map[string]any{"n": 1}); err == nil {
		t.Fatal("want a JSON-RPC error for the failed upstream call")
	}
	g.check("error")
	if e := g.entries()[0]; e.Result.Error == "" {
		t.Fatal("result.error empty on outcome error")
	}
}

// A failed priced call whose request reached the upstream is settled at the
// estimate, never refunded (gap-006): with a per_run limit of two searches,
// only one more search fits after the failure.
func TestE2EUpstreamErrorSettlesEstimate(t *testing.T) {
	g := start(t, harness.Options{FailNext: 1}, "10m")
	if _, err := g.client.Call("search", map[string]any{"query": "fails"}); err == nil {
		t.Fatal("want a JSON-RPC error for the failed upstream call")
	}
	res, err := g.client.Call("search", map[string]any{"query": "q1"})
	okText(t, res, err, `{"query":"q1"}`)
	res, err = g.client.Call("search", map[string]any{"query": "q2"})
	refused(t, res, err, contracts.EntryBudgetExceeded, "", "agentgw: budget exceeded: per_run budget exceeded")
	e := g.entries()[0]
	if e.Outcome != contracts.EntryError || e.Cost.Estimated.Micros != 5000 || e.Cost.Actual.Micros != 5000 ||
		!strings.HasPrefix(e.Result.Error, "upstream may have run: ") {
		t.Fatalf("failed call entry %+v", e)
	}
	if out := g.cli("verify"); !strings.HasPrefix(out, "ok: ") {
		t.Fatalf("verify: %q", out)
	}
}

// Shutdown mid-call (review finding 1): the client closes stdin while a call
// is in flight upstream; the gateway must still write its entry before exit.
func TestE2EShutdownMidCallRecords(t *testing.T) {
	g := setup(t, map[string]any{"name": "harness", "command": []string{"sh", "-c", "cat >> up.log"}}, "", "10m")
	up := filepath.Join(g.dir, "up.log")
	cmd := exec.Command(bin, "run", "--config", g.cfg)
	cmd.Dir = g.dir // the upstream writes up.log in its cwd
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	stdin.Write([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"n":1}}}` + "\n"))
	time.Sleep(500 * time.Millisecond)
	stdin.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		cmd.Process.Kill()
		t.Fatalf("gateway did not exit after stdin closed\n%s", stderr.String())
	}
	if b, _ := os.ReadFile(up); !strings.Contains(string(b), `"tools/call"`) {
		t.Fatalf("call never reached the upstream: %q", b)
	}
	es := g.entries()
	if len(es) != 1 || es[0].Outcome != contracts.EntryError || es[0].Decision.Outcome != contracts.OutcomeAllow {
		t.Fatalf("want one error entry for the in-flight call, got %+v\n%s", es, stderr.String())
	}
	if out := g.cli("verify"); !strings.HasPrefix(out, "ok: ") {
		t.Fatalf("verify: %q", out)
	}
}

// freeAddr returns a loopback address with nothing listening on it.
func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// serve starts `agentgw serve` with one url upstream on path /mcp and returns
// the gateway's MCP endpoint once it accepts connections.
func serve(t *testing.T, upstreamURL string) (*gw, string) {
	t.Helper()
	addr := freeAddr(t)
	g := setup(t, map[string]any{"name": "harness", "url": upstreamURL, "path": "/mcp"}, addr, "10m")
	cmd := exec.Command(bin, "serve", "--config", g.cfg)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Signal(syscall.SIGTERM)
		cmd.Wait()
	})
	for i := 0; ; i++ {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			break
		}
		if i == 100 {
			t.Fatalf("serve did not listen on %s\n%s", addr, stderr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	return g, "http://" + addr + "/mcp"
}

// The allow scenario over `agentgw serve` (Streamable HTTP).
func TestE2EServeAllow(t *testing.T) {
	target := harness.StartServer(t, harness.Options{HTTP: true, Tools: harness.DefaultTools(t)})
	g, url := serve(t, target.URL)
	client := harness.NewClient(t, harness.Target{URL: url})
	for i := 1; i <= 5; i++ {
		res, err := client.Call("echo", map[string]any{"n": i})
		okText(t, res, err, fmt.Sprintf(`{"n":%d}`, i))
	}
	g.check("allow")
}

// ErrNotSent path (gap-006): the upstream port is closed, so the request
// provably never left the gateway and each reservation is released. The
// per_run limit fits two searches; a third call reaching the upstream stage
// (outcome error, not budget_exceeded) shows nothing stayed reserved. The
// tools/call is POSTed directly: the client cannot complete an MCP handshake
// through a dead upstream, and tools/call needs none to reach the pipeline.
func TestE2EServeNotSentReleases(t *testing.T) {
	g, url := serve(t, "http://"+freeAddr(t)+"/mcp")
	for i := 1; i <= 3; i++ {
		body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"search","arguments":{"query":"q%d"}}}`, i, i)
		resp, err := http.Post(url, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(b), `"code":-32603`) || !strings.Contains(string(b), "request not sent upstream") {
			t.Fatalf("call %d: %s", i, b)
		}
	}
	es := g.entries()
	if len(es) != 3 {
		t.Fatalf("%d entries, want 3", len(es))
	}
	for i, e := range es {
		if e.Outcome != contracts.EntryError || e.Cost.Estimated.Micros != 5000 || e.Cost.Actual.Micros != 0 ||
			strings.HasPrefix(e.Result.Error, "upstream may have run") || !strings.Contains(e.Result.Error, "request not sent upstream") {
			t.Fatalf("entry %d: %+v", i+1, e)
		}
	}
	if out := g.cli("verify"); !strings.HasPrefix(out, "ok: ") {
		t.Fatalf("verify: %q", out)
	}
}
