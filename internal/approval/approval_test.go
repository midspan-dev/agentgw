package approval

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gowebpki/jcs"
	"github.com/midspan-dev/agentgw/internal/harness"
	"github.com/midspan-dev/agentgw/pkg/contracts"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func open(t *testing.T) (*Store, ed25519.PublicKey) {
	t.Helper()
	dir := t.TempDir()
	tok := filepath.Join(dir, "tok")
	if err := GenerateToken(tok); err != nil {
		t.Fatal(err)
	}
	s, err := Open(filepath.Join(dir, "state.db"), tok)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, s.priv.Public().(ed25519.PublicKey)
}

func req(timeout int) contracts.ApprovalRequest {
	return contracts.ApprovalRequest{
		CallID: "c1", Principal: contracts.Principal{AgentID: "a1", RunID: "r1"},
		Server: "pay", Tool: "refund", ArgsHash: "h1", Args: json.RawMessage(`{"amount":5}`),
		RuleID: "big-refund", Spec: contracts.ApprovalSpec{TimeoutSeconds: timeout},
	}
}

func verify(t *testing.T, pub ed25519.PublicKey, d *contracts.ApprovalDecision) {
	t.Helper()
	p, _ := json.Marshal(map[string]string{"approval_id": d.ApprovalID, "args_hash": d.ArgsHash, "decision": d.Decision, "ts": d.Ts.UTC().Format(time.RFC3339)})
	c, _ := jcs.Transform(p)
	sig, _ := hex.DecodeString(d.ApproverSig)
	if d.ApproverID != hex.EncodeToString(pub) || !ed25519.Verify(pub, c, sig) {
		t.Errorf("bad signature on %+v", d)
	}
}

func TestTokenFormat(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tok")
	if err := GenerateToken(p); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	b, _ := os.ReadFile(p)
	if st.Mode().Perm() != 0o600 || len(strings.TrimSpace(string(b))) != 128 || strings.Count(string(b), "\n") != 1 {
		t.Fatalf("token: %v %d", st.Mode(), len(b))
	}
}

func TestRejections(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	id, _ := s.Request(ctx, req(60))
	if err := s.Approve(ctx, "nope", "h1", "", time.Time{}); !errors.Is(err, ErrNotPending) {
		t.Fatalf("unknown id: %v", err)
	}
	if err := s.Approve(ctx, id, "bad", "", time.Time{}); !errors.Is(err, ErrArgsHashMismatch) {
		t.Fatalf("hash: %v", err)
	}
	if err := s.Approve(ctx, id, "h1", "agent", time.Time{}); !errors.Is(err, ErrBadGrant) {
		t.Fatalf("agent no until: %v", err)
	}
	if l, _ := s.List(ctx); len(l) != 1 {
		t.Fatalf("failures must record nothing: %v", l)
	}
	if err := s.Approve(ctx, id, "h1", "", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := s.Approve(ctx, id, "h1", "", time.Time{}); !errors.Is(err, ErrNotPending) {
		t.Fatalf("twice: %v", err)
	}
	if err := s.Deny(ctx, id, "h1", "x"); !errors.Is(err, ErrNotPending) {
		t.Fatalf("deny after approve: %v", err)
	}
}

func TestTimeout(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	id, _ := s.Request(ctx, req(1))
	d, err := s.Wait(ctx, id, func(string) {})
	var ce *contracts.CallError
	if d != nil || !errors.As(err, &ce) || !errors.Is(err, contracts.ErrApprovalTimeout) || ce.RuleID != "big-refund" || ce.Reason != "" {
		t.Fatalf("timeout: %v %v", d, err)
	}
	if err := s.Approve(ctx, id, "h1", "", time.Time{}); !errors.Is(err, ErrNotPending) {
		t.Fatalf("approve after timeout: %v", err)
	}
	id2, _ := s.Request(ctx, req(1))
	time.Sleep(1100 * time.Millisecond)
	if err := s.Approve(ctx, id2, "h1", "", time.Time{}); !errors.Is(err, ErrNotPending) {
		t.Fatalf("approve after expiry before wait: %v", err)
	}
}

func TestWaitDecisions(t *testing.T) {
	s, pub := open(t)
	ctx := context.Background()
	id, _ := s.Request(ctx, req(60))
	var msgs []string
	go func() { time.Sleep(300 * time.Millisecond); s.Approve(ctx, id, "h1", "", time.Time{}) }()
	d, err := s.Wait(ctx, id, func(m string) { msgs = append(msgs, m) })
	if err != nil || d.Decision != contracts.DecisionApproved || d.CallID != "c1" || d.Grant != nil {
		t.Fatalf("approved: %+v %v", d, err)
	}
	verify(t, pub, d)
	if len(msgs) == 0 || !strings.HasPrefix(msgs[0], "waiting for approval "+id+", ") {
		t.Fatalf("progress: %v", msgs)
	}

	id, _ = s.Request(ctx, req(60))
	s.Deny(ctx, id, "h1", "too much")
	d, err = s.Wait(ctx, id, func(string) {})
	var ce *contracts.CallError
	if !errors.As(err, &ce) || !errors.Is(err, contracts.ErrApprovalDenied) || ce.Reason != "too much" || d == nil || d.Decision != contracts.DecisionDenied {
		t.Fatalf("denied: %+v %v", d, err)
	}
	verify(t, pub, d)

	cctx, cancel := context.WithCancel(ctx)
	id, _ = s.Request(ctx, req(60))
	cancel()
	if d, err := s.Wait(cctx, id, func(string) {}); d != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("ctx: %v %v", d, err)
	}
}

func TestGrants(t *testing.T) {
	s, _ := open(t)
	ctx := context.Background()
	id, _ := s.Request(ctx, req(60))
	if err := s.Approve(ctx, id, "h1", contracts.GrantScopeRun, time.Time{}); err != nil {
		t.Fatal(err)
	}
	id, _ = s.Request(ctx, req(60))
	s.Approve(ctx, id, "h1", contracts.GrantScopeAgent, time.Now().Add(time.Hour))
	id, _ = s.Request(ctx, req(60))
	s.Approve(ctx, id, "h1", contracts.GrantScopeAgent, time.Now().Add(-time.Hour))

	g, _ := s.Grants(ctx, contracts.Principal{AgentID: "a1", RunID: "r1"})
	if len(g) != 2 || g[0].Scope != contracts.GrantScopeRun || g[0].RunID != "r1" || g[0].Server != "pay" || g[0].Tool != "refund" || !g[0].Until.After(time.Now().Add(23*time.Hour)) {
		t.Fatalf("r1: %+v", g)
	}
	g, _ = s.Grants(ctx, contracts.Principal{AgentID: "a1", RunID: "r2"})
	if len(g) != 1 || g[0].Scope != contracts.GrantScopeAgent {
		t.Fatalf("r2: %+v", g)
	}
	g, _ = s.Grants(ctx, contracts.Principal{AgentID: "other"})
	if g == nil || len(g) != 0 {
		t.Fatalf("other: %#v", g)
	}
}

func TestE2E(t *testing.T) {
	s, pub := open(t)
	tools := harness.DefaultTools(t)
	for i := range tools {
		if tools[i].Name != "refund" {
			continue
		}
		tools[i].Handler = func(ctx context.Context, r *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			id, err := s.Request(ctx, req(60))
			if err != nil {
				return nil, err
			}
			progress := func(m string) {
				if tok := r.Params.GetProgressToken(); tok != nil {
					r.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{ProgressToken: tok, Message: m, Progress: 1})
				}
			}
			d, err := s.Wait(ctx, id, progress)
			if err != nil {
				return nil, err
			}
			verify(t, pub, d)
			return harness.Echo(ctx, r)
		}
	}
	c := harness.NewClient(t, harness.StartServer(t, harness.Options{Tools: tools}))
	go func() {
		for {
			l, _ := s.List(context.Background())
			if len(l) > 0 {
				if err := s.Approve(context.Background(), l[0].ID, l[0].Request.ArgsHash, "", time.Time{}); err != nil {
					t.Error(err)
				}
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	res, err := c.CallWithProgress("refund", map[string]any{"amount": 5}, "tok")
	if err != nil || res.IsError {
		t.Fatalf("refund: %v %+v", err, res)
	}
	select {
	case p := <-c.Progress:
		if !strings.HasPrefix(p.Message, "waiting for approval ") {
			t.Fatalf("progress: %q", p.Message)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no progress notification")
	}
}
