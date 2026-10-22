package proxy_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/midspan-dev/agentgw/internal/harness"
	"github.com/midspan-dev/agentgw/internal/proxy"
	"github.com/midspan-dev/agentgw/pkg/contracts"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const helperArg = "-proxy-helper"

// fn is a stub Interceptor that records every call it sees.
type fn struct {
	mu    sync.Mutex
	calls []*contracts.Call
	f     func(context.Context, *contracts.Call) (json.RawMessage, error)
}

func (s *fn) Intercept(ctx context.Context, c *contracts.Call) (json.RawMessage, error) {
	s.mu.Lock()
	s.calls = append(s.calls, c)
	s.mu.Unlock()
	return s.f(ctx, c)
}

func pass(ctx context.Context, c *contracts.Call) (json.RawMessage, error) { return c.Forward(ctx) }

func progressTwice(ctx context.Context, c *contracts.Call) (json.RawMessage, error) {
	c.Progress("one")
	c.Progress("two")
	return c.Forward(ctx)
}

// modes are the interceptors the stdio helper process can run.
var modes = map[string]func(context.Context, *contracts.Call) (json.RawMessage, error){
	"pass":     pass,
	"progress": progressTwice,
	"deny": func(context.Context, *contracts.Call) (json.RawMessage, error) {
		return nil, &contracts.CallError{Err: contracts.ErrDenied, RuleID: "r1", Reason: "denied by rule r1"}
	},
	"passrec": func(ctx context.Context, c *contracts.Call) (json.RawMessage, error) {
		fmt.Fprintf(os.Stderr, "SAW %s %s\n", c.Tool, c.Args) // the parent reads this to learn what the interceptor saw
		return c.Forward(ctx)
	},
	// ns* report, through the refusal text, whether Forward's error wraps ErrNotSent.
	"nsCancelled": func(ctx context.Context, c *contracts.Call) (json.RawMessage, error) {
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		_, err := c.Forward(cctx)
		return nil, &contracts.CallError{Err: contracts.ErrDenied, Reason: fmt.Sprintf("notsent=%v", errors.Is(err, contracts.ErrNotSent))}
	},
	"nsAfterWrite": func(ctx context.Context, c *contracts.Call) (json.RawMessage, error) {
		cctx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		defer cancel()
		_, err := c.Forward(cctx) // the upstream never answers
		return nil, &contracts.CallError{Err: contracts.ErrDenied, Reason: fmt.Sprintf("notsent=%v deadline=%v", errors.Is(err, contracts.ErrNotSent), errors.Is(err, context.DeadlineExceeded))}
	},
	"nilnil": func(context.Context, *contracts.Call) (json.RawMessage, error) { return nil, nil },
	"boom":   func(context.Context, *contracts.Call) (json.RawMessage, error) { return nil, errors.New("boom") },
	"slowpass": func(ctx context.Context, c *contracts.Call) (json.RawMessage, error) {
		time.Sleep(500 * time.Millisecond)
		return c.Forward(ctx)
	},
	// hold reports a cancelled context as a distinctive refusal so tests can see it.
	"hold": func(ctx context.Context, c *contracts.Call) (json.RawMessage, error) {
		<-ctx.Done()
		return nil, &contracts.CallError{Err: contracts.ErrDenied, Reason: "cancelled-seen"}
	},
}

// The stdio proxy is a separate process: this test binary re-executes itself as
// `agentgw run` would, with the interceptor chosen by mode. Mode "dupup" is
// instead a hostile upstream that answers every request twice.
func TestMain(m *testing.M) {
	if len(os.Args) > 2 && os.Args[1] == helperArg {
		if os.Args[2] == "evilup" { // a hostile upstream: a notification with extra, differently-cased members, then a response
			sc := bufio.NewScanner(os.Stdin)
			for sc.Scan() {
				var r struct {
					ID json.RawMessage `json:"id"`
				}
				if json.Unmarshal(sc.Bytes(), &r) == nil && r.ID != nil {
					fmt.Println(`{"jsonrpc":"2.0","method":"notifications/message","Method":"","Id":7,"Result":{},"params":{}}`)
					fmt.Printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{}}\n", r.ID)
				}
			}
			os.Exit(0)
		}
		if os.Args[2] == "silentup" { // reads everything, answers nothing
			io.Copy(io.Discard, os.Stdin)
			os.Exit(0)
		}
		if os.Args[2] == "dupup" {
			sc := bufio.NewScanner(os.Stdin)
			for sc.Scan() {
				var r struct {
					ID json.RawMessage `json:"id"`
				}
				if json.Unmarshal(sc.Bytes(), &r) == nil && r.ID != nil {
					fmt.Printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"content\":[]}}\n", r.ID)
					fmt.Printf("{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"content\":[]}}\n", r.ID)
				}
			}
			os.Exit(0)
		}
		err := proxy.Stdio(context.Background(), "up", os.Args[3:], &fn{f: modes[os.Args[2]]})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func stdioProxy(t *testing.T, mode string, up harness.Target) harness.Target {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return harness.Target{Command: append([]string{exe, helperArg, mode}, up.Command...)}
}

func httpProxy(t *testing.T, i contracts.Interceptor, up harness.Target) harness.Target {
	return httpProxyURL(t, i, up.URL)
}

func httpProxyURL(t *testing.T, i contracts.Interceptor, upURL string) harness.Target {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	go proxy.HTTP(t.Context(), addr, []proxy.Route{{Name: "up", Path: "/mcp/up", URL: upURL}}, i)
	for range 100 {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return harness.Target{URL: "http://" + addr + "/mcp/up"}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("proxy did not start")
	return harness.Target{}
}

func j(t *testing.T, v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// roundTrip checks that echo and search through the proxy equal the direct results.
func roundTrip(t *testing.T, direct, proxied *harness.Client) {
	for _, tc := range []struct {
		tool string
		args any
	}{{"echo", map[string]any{"a": 1, "b": "x"}}, {"search", map[string]any{"query": "q"}}} {
		want, err := direct.Call(tc.tool, tc.args)
		if err != nil {
			t.Fatal(err)
		}
		got, err := proxied.Call(tc.tool, tc.args)
		if err != nil {
			t.Fatal(err)
		}
		if j(t, got) != j(t, want) {
			t.Errorf("%s: proxied %s, direct %s", tc.tool, j(t, got), j(t, want))
		}
		if tc.tool == "search" && got.Meta["cost"] == nil {
			t.Errorf("search lost _meta.cost: %s", j(t, got))
		}
	}
	for _, c := range []*harness.Client{direct, proxied} {
		if v := c.InitializeResult().ProtocolVersion; v != "2026-07-28" {
			t.Errorf("negotiated protocol %q, want 2026-07-28", v)
		}
	}
}

func progressSeen(t *testing.T, c *harness.Client) {
	if _, err := c.CallWithProgress("echo", map[string]any{}, "tok"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"one", "two"} {
		select {
		case p := <-c.Progress:
			if p.Message != want {
				t.Errorf("progress message %q, want %q", p.Message, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("no progress notification %q", want)
		}
	}
}

func TestE2EStdio(t *testing.T) {
	up := harness.StartServer(t, harness.Options{Tools: harness.DefaultTools(t)})
	direct := harness.NewClient(t, up)
	roundTrip(t, direct, harness.NewClient(t, stdioProxy(t, "pass", up)))
	progressSeen(t, harness.NewClient(t, stdioProxy(t, "progress", up)))
}

func TestE2EHTTP(t *testing.T) {
	up := harness.StartServer(t, harness.Options{HTTP: true, Tools: harness.DefaultTools(t)})
	rec := &fn{f: pass}
	roundTrip(t, harness.NewClient(t, up), harness.NewClient(t, httpProxy(t, rec, up)))

	// What the interceptor saw.
	c := rec.calls[0]
	if c.Server != "up" || c.Tool != "echo" || c.Args == nil || len(c.ID) != 32 || strings.ToLower(c.ID) != c.ID || c.Progress == nil {
		t.Errorf("bad Call: %+v", c)
	}

	progressSeen(t, harness.NewClient(t, httpProxy(t, &fn{f: progressTwice}, up)))
}

func TestMissingArgsAreEmptyObject(t *testing.T) {
	up := harness.StartServer(t, harness.Options{HTTP: true, Tools: harness.DefaultTools(t)})
	rec := &fn{f: pass}
	c := harness.NewClient(t, httpProxy(t, rec, up))
	if _, err := c.Call("echo", nil); err != nil {
		t.Fatal(err)
	}
	if got := string(rec.calls[0].Args); got != "{}" {
		t.Errorf("Args = %q, want {}", got)
	}
}

func TestErrorMapping(t *testing.T) {
	up := harness.StartServer(t, harness.Options{HTTP: true, Tools: harness.DefaultTools(t)})
	for _, tc := range []struct {
		err     *contracts.CallError
		outcome contracts.EntryOutcome
	}{
		{&contracts.CallError{Err: contracts.ErrDenied, RuleID: "r1", Reason: "denied by rule r1"}, contracts.EntryDenied},
		{&contracts.CallError{Err: contracts.ErrBudgetExceeded, Reason: "per_run budget exceeded", Window: contracts.WindowPerRun}, contracts.EntryBudgetExceeded},
		{&contracts.CallError{Err: contracts.ErrApprovalDenied, Reason: "no", CallID: "fixed"}, contracts.EntryApprovalDenied},
		{&contracts.CallError{Err: contracts.ErrApprovalTimeout}, contracts.EntryApprovalTimeout},
	} {
		s := &fn{f: func(context.Context, *contracts.Call) (json.RawMessage, error) { return nil, tc.err }}
		res, err := harness.NewClient(t, httpProxy(t, s, up)).Call("echo", map[string]any{})
		if err != nil {
			t.Fatal(err)
		}
		m, ok := harness.MetaOf(res)
		if !res.IsError || !ok || m.Outcome != tc.outcome || m.Reason != tc.err.Reason || m.RuleID != tc.err.RuleID || m.CallID == "" {
			t.Errorf("%v: result %s", tc.outcome, j(t, res))
		}
		if tc.err.CallID != "" && m.CallID != tc.err.CallID {
			t.Errorf("CallID %q, want %q", m.CallID, tc.err.CallID)
		}
		if m.CallID != s.calls[0].ID && tc.err.CallID == "" {
			t.Errorf("CallID %q, want call id %q", m.CallID, s.calls[0].ID)
		}
		if got := res.Content[0].(*mcp.TextContent).Text; got != tc.err.Error() {
			t.Errorf("text %q, want %q", got, tc.err.Error())
		}
	}

	s := &fn{f: func(context.Context, *contracts.Call) (json.RawMessage, error) { return nil, errors.New("boom") }}
	tgt := httpProxy(t, s, up)
	if got := post(t, tgt.URL, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"echo"}}`); got.status != 200 || !strings.Contains(got.body, `"code":-32603`) || !strings.Contains(got.body, "boom") {
		t.Errorf("unknown error: %d %s", got.status, got.body)
	}
}

type reply struct {
	status int
	body   string
}

func post(t *testing.T, url, body string) reply {
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return reply{resp.StatusCode, string(b)}
}

func TestBatchRejected(t *testing.T) {
	up := harness.StartServer(t, harness.Options{HTTP: true, Tools: harness.DefaultTools(t)})
	rec := &fn{f: pass}
	tgt := httpProxy(t, rec, up)
	body := `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}]`
	resp := post(t, tgt.URL, body)
	if resp.status != 400 || len(rec.calls) != 0 {
		t.Errorf("batch: status %d, intercepted %d", resp.status, len(rec.calls))
	}
}
