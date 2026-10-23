package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/midspan-dev/agentgw/internal/harness"
	"github.com/midspan-dev/agentgw/internal/watch"
	"github.com/midspan-dev/agentgw/pkg/contracts"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// waitFor polls the stream until pred is true and returns the stream then.
func waitFor(t *testing.T, buf *safeBuf, what string, pred func(string) bool) string {
	t.Helper()
	for end := time.Now().Add(20 * time.Second); time.Now().Before(end); time.Sleep(25 * time.Millisecond) {
		if s := buf.String(); pred(s) {
			return s
		}
	}
	t.Fatalf("timed out waiting for %s; stream:\n%s", what, buf.String())
	return ""
}

func hasLine(s string, parts ...string) bool { return lineIndex(s, 0, parts...) >= 0 }

// lineIndex returns the offset of the first line at or after from containing all parts.
func lineIndex(s string, from int, parts ...string) int {
	off := from
	for _, l := range strings.SplitAfter(s[from:], "\n") {
		ok := true
		for _, p := range parts {
			ok = ok && strings.Contains(l, p)
		}
		if ok {
			return off
		}
		off += len(l)
	}
	return -1
}

func TestE2EWatchApproves(t *testing.T) {
	g := start(t, harness.Options{}, "60s")
	raw, err := os.ReadFile(g.cfg)
	if err != nil {
		t.Fatal(err)
	}
	var cfg contracts.Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	for _, p := range []*string{&cfg.PolicyPath, &cfg.Ledger.Path, &cfg.KeyPath, &cfg.StatePath, &cfg.Approvals.CLI.TokenPath} {
		*p = filepath.Join(g.dir, *p)
	}
	pr, pw := io.Pipe()
	buf := &safeBuf{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- watch.Run(ctx, watch.Options{Config: &cfg, ConfigPath: g.cfg, Poll: 20 * time.Millisecond}, pr, buf)
	}()
	t.Cleanup(func() {
		cancel()
		pw.Close()
		if err := <-done; err != nil {
			t.Errorf("watch.Run: %v", err)
		}
	})
	waitFor(t, buf, "status block", func(s string) bool {
		return strings.Contains(s, "0 entries, 0 checkpoints, verified ok") &&strings.Contains(s, "compiles, version ") && strings.Contains(s, "approver ready")
	})

	res, err := g.client.Call("echo", map[string]any{"n": 1})
	okText(t, res, err, `{"n":1}`)
	waitFor(t, buf, "echo line", func(s string) bool { return hasLine(s, "allow", "harness.echo", "ok", "allow-all") })

	// Hostile bytes in args and result render escaped.
	res, err = g.client.Call("echo", map[string]any{"m": "\x1b[31m", "t": "\x1b]0;pwned\x07"})
	if err != nil || res.IsError {
		t.Fatal(err, res)
	}
	waitFor(t, buf, "hostile echo line", func(s string) bool { return strings.Count(s, "harness.echo") >= 2 })
	// JSON encoding already neutralises bytes in args, so also send a raw
	// path: the tool name is recorded as given and printed on the call line.
	g.client.Call("\x1b]0;pwned\x07\x1b[31m", map[string]any{})
	s := waitFor(t, buf, "hostile tool name line", func(s string) bool { return strings.Contains(s, `\u001B]0;pwned\u0007\u001B[31m`) })
	if strings.ContainsRune(s, 0x1b) || strings.ContainsRune(s, 7) {
		t.Fatalf("control byte in stream:\n%q", s)
	}

	refund := func() (*mcp.CallToolResult, error) {
		return g.client.Call("refund", map[string]any{"amount": 50, "charge": "ch_123"})
	}
	type result struct {
		res *mcp.CallToolResult
		err error
	}
	call := func() chan result {
		c := make(chan result, 1)
		go func() { r, e := refund(); c <- result{r, e} }()
		return c
	}

	c := call()
	waitFor(t, buf, "card", func(s string) bool { return strings.Contains(s, "── approval 1") })
	io.WriteString(pw, "a\n")
	r := <-c
	okText(t, r.res, r.err, `{"amount":50,"charge":"ch_123"}`)
	s = waitFor(t, buf, "approved", func(s string) bool { return hasLine(s, "approved") })
	at := waitFor(t, buf, "hold line", func(s string) bool { return hasLine(s, "hold", "harness.refund", "ok", "refunds-need-approval") })
	hold := lineIndex(at, 0, "hold", "harness.refund", "ok", "refunds-need-approval")
	waitFor(t, buf, "ledger verified after hold", func(s string) bool { return lineIndex(s, hold, "ledger", "verified ok") >= 0 })

	c = call()
	// Card numbers are never reused in a session: the second refund is card 2.
	waitFor(t, buf, "second card", func(s string) bool { return strings.Contains(s, "── approval 2") })
	io.WriteString(pw, "d 2 nope\n")
	r = <-c
	refused(t, r.res, r.err, contracts.EntryApprovalDenied, "refunds-need-approval", "agentgw: approval denied: nope")
	waitFor(t, buf, "approval_denied line", func(s string) bool { return hasLine(s, "approval_denied", "refunds-need-approval", "denied by") })
}
