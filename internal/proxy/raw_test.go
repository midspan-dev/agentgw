package proxy_test

// Adversarial inputs: messages a real MCP client would never send but that an
// agent can. A probe passes when the upstream tool never ran and the
// interceptor never saw the call. Bypass probes use a deny-all interceptor;
// differential probes use a pass-through that records what it saw, so a
// parser difference between proxy and upstream shows as "ran something the
// interceptor did not see". HTTP probes are fully valid 2026-07-28 requests
// (per-request _meta, headers consistent with what the upstream parses), so a
// leak reaches a handler instead of dying at the SDK's own checks.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/midspan-dev/agentgw/internal/harness"
	"github.com/midspan-dev/agentgw/pkg/contracts"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// runLog records every tool execution on the upstream.
type runLog struct {
	mu   sync.Mutex
	list []string
}

func (r *runLog) n() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.list) }

// countingTools are the default tools with a handler that logs executions.
func countingTools(t *testing.T, runs *runLog) []harness.Tool {
	tools := harness.DefaultTools(t)
	for i := range tools {
		tools[i].Handler = func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			runs.mu.Lock()
			runs.list = append(runs.list, req.Params.Name+" "+string(req.Params.Arguments)+" state="+req.Params.RequestState)
			runs.mu.Unlock()
			return harness.Echo(ctx, req)
		}
	}
	return tools
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type rawProxy struct {
	t      *testing.T
	in     io.WriteCloser
	lines  chan string
	stderr *syncBuf
}

func startRaw(t *testing.T, mode string, upCmd ...string) *rawProxy {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), exe, append([]string{helperArg, mode}, upCmd...)...)
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	p := &rawProxy{t: t, in: in, lines: make(chan string, 100), stderr: &syncBuf{}}
	cmd.Stderr = p.stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		sc := bufio.NewScanner(out)
		sc.Buffer(nil, 1<<20)
		for sc.Scan() {
			p.lines <- sc.Text()
		}
		close(p.lines)
	}()
	t.Cleanup(func() { in.Close(); cmd.Wait() })
	return p
}

// send writes s exactly as given.
func (p *rawProxy) send(s string) { io.WriteString(p.in, s) }

func (p *rawProxy) recv() string {
	select {
	case l, ok := <-p.lines:
		if !ok {
			p.t.Fatal("proxy closed stdout")
		}
		return l
	case <-time.After(5 * time.Second):
		p.t.Fatal("timed out waiting for a proxy line")
	}
	return ""
}

// initialize completes the handshake a real upstream requires.
func (p *rawProxy) initialize(version string) {
	p.send(`{"jsonrpc":"2.0","id":"init","method":"initialize","params":{"protocolVersion":"` + version + `","capabilities":{},"clientInfo":{"name":"x","version":"0"}}}` + "\n")
	p.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n")
	p.barrier()
}

// barrier pings and returns every line seen before the ping's response, so the
// caller can tell whether the proxy stayed live (no deadlock) and what it said.
func (p *rawProxy) barrier() []string {
	p.send(`{"jsonrpc":"2.0","id":"barrier","method":"ping"}` + "\n")
	var got []string
	for {
		l := p.recv()
		if strings.Contains(l, `"id":"barrier"`) {
			time.Sleep(100 * time.Millisecond) // let a leaked call finish
			for {
				select {
				case l := <-p.lines:
					got = append(got, l)
				default:
					return got
				}
			}
		}
		got = append(got, l)
	}
}

const (
	callEcho = `{"name":"echo","arguments":{"a":1}}`
	meta     = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{},"io.modelcontextprotocol/clientInfo":{"name":"x","version":"0"}}`
)

// probe is one hostile tools/call. tool is what a case-sensitive upstream
// reads as the tool name (the HTTP Mcp-Name header must agree with it).
// diff probes run with a recording pass-through interceptor, the rest with deny-all.
type probe struct {
	name, body, tool string
	diff, stdioOnly  bool
	httpOnly         bool
}

func probes() []probe {
	call := func(id, params string) string {
		return `{"jsonrpc":"2.0","id":` + id + `,"method":"tools/call","params":{` + params + `}}`
	}
	return []probe{
		{name: "cased Method", tool: "echo", body: `{"jsonrpc":"2.0","id":2,"method":"tools/call","Method":"ping","params":{"name":"echo","arguments":{"a":1},` + meta + `}}`},
		{name: "cased Name", tool: "search", diff: true, body: call("5", `"name":"search","Name":"echo","arguments":{"query":"q"},`+meta)},
		{name: "cased Arguments", tool: "echo", diff: true, body: call("6", `"name":"echo","arguments":{"a":"evil"},"Arguments":{"a":"safe"},`+meta)},
		{name: "duplicate name", tool: "search", diff: true, body: call("6", `"name":"echo","name":"search","arguments":{},`+meta)},
		{name: "duplicate arguments", tool: "echo", diff: true, body: call("6", `"name":"echo","arguments":{"a":"evil"},"arguments":{"a":"safe"},`+meta)},
		{name: "task member", tool: "echo", diff: true, body: call("8", `"name":"echo","arguments":{"a":1},"task":{"ttl":1},`+meta)},
		{name: "unknown member", tool: "echo", diff: true, body: call("8", `"name":"echo","arguments":{"a":1},"extra":1,`+meta)},
		{name: "huge number in arguments", tool: "echo", body: call("9", `"name":"echo","arguments":{"n":1e400},`+meta)},
		{name: "huge negative nested in inputResponses", tool: "echo", body: call("9", `"name":"echo","arguments":{},"inputResponses":{"k":{"content":{"n":[-1e400]}}},`+meta)},
		{name: "key collision top level", tool: "echo", body: call("9", `"name":"echo","arguments":{"Amount":1,"amount":2},`+meta)},
		{name: "key collision nested", tool: "echo", body: call("9", `"name":"echo","arguments":{"a":{"X":1,"x":2}},`+meta)},
		{name: "key collision in array", tool: "echo", body: call("9", `"name":"echo","arguments":{"a":[{"k":1},{"k":1,"K":2}]},`+meta)},
		{name: "key collision in inputResponses", tool: "echo", body: call("9", `"name":"echo","arguments":{},"inputResponses":{"k":{"A":1,"a":2}},`+meta)},
		{name: "key collision NFC only", tool: "echo", body: call("9", `"name":"echo","arguments":{"\u00e9":1,"e\u0301":2},`+meta)},
		{name: "args array", tool: "echo", diff: true, body: call("1", `"name":"echo","arguments":[1],`+meta)},
		{name: "error member", tool: "echo", body: `{"jsonrpc":"2.0","id":7,"method":"tools/call","error":"x","params":{"name":"echo","arguments":{"a":1},` + meta + `}}`},
		{name: "batch", tool: "echo", body: `[{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{"a":1},` + meta + `}}]`},
		{name: "cr joined", tool: "echo", body: `{"jsonrpc":"2.0","method":"notifications/x"}` + "\r" + call("3", `"name":"echo","arguments":{"a":1},`+meta)},
		{name: "two objects", tool: "echo", body: `{"jsonrpc":"2.0","method":"notifications/x"}{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"a":1},` + meta + `}}`},
	}
}

func TestStdioBypassProbes(t *testing.T) {
	for _, pr := range probes() {
		if pr.httpOnly {
			continue
		}
		t.Run(pr.name, func(t *testing.T) {
			var runs runLog
			up := harness.StartServer(t, harness.Options{Tools: countingTools(t, &runs)})
			mode := "deny"
			if pr.diff {
				mode = "passrec"
			}
			p := startRaw(t, mode, up.Command...)
			p.initialize("2025-03-26") // under which the SDK upstream would accept a batch
			p.send(pr.body + "\n")
			p.barrier()
			if runs.n() != 0 {
				t.Errorf("upstream ran %v", runs.list)
			}
			if saw := p.stderr.String(); strings.Contains(saw, "SAW") {
				t.Errorf("interceptor saw a hostile call: %s", saw)
			}
		})
	}
}

func TestStdioFloatID(t *testing.T) {
	var runs runLog
	up := harness.StartServer(t, harness.Options{Tools: countingTools(t, &runs)})
	p := startRaw(t, "deny", up.Command...)
	p.send(`{"jsonrpc":"2.0","id":1.0,"method":"tools/call","params":` + callEcho + `}` + "\n")
	l := p.recv()
	if !strings.Contains(l, `"id":1.0`) || !strings.Contains(l, `"outcome":"denied"`) || runs.n() != 0 {
		t.Errorf("got %s, ran %d", l, runs.n())
	}
}

// With a proxy-owned upstream id the upstream's canonical "1" still reaches the waiting call.
func TestStdioFloatIDPassThrough(t *testing.T) {
	var runs runLog
	up := harness.StartServer(t, harness.Options{Tools: countingTools(t, &runs)})
	p := startRaw(t, "pass", up.Command...)
	p.initialize("2025-11-25")
	p.send(`{"jsonrpc":"2.0","id":1.0,"method":"tools/call","params":` + callEcho + `}` + "\n")
	l := p.recv()
	if !strings.HasPrefix(l, `{"jsonrpc":"2.0","id":1.0,"result":`) || !strings.Contains(l, `{\"a\":1}`) {
		t.Errorf("got %s", l)
	}
	if got := p.barrier(); len(got) != 0 {
		t.Errorf("stray output %v", got)
	}
}

func TestStdioIDReuseWhileHeld(t *testing.T) {
	var runs runLog
	up := harness.StartServer(t, harness.Options{Tools: countingTools(t, &runs)})
	p := startRaw(t, "slowpass", up.Command...)
	p.initialize("2025-11-25")
	p.send(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":` + callEcho + `}` + "\n")
	p.send(`{"jsonrpc":"2.0","id":9,"method":"tools/list"}` + "\n")
	p.send(`{"jsonrpc":"2.0","id":9.0,"method":"tools/list"}` + "\n") // the same id once canonicalised
	a, b, last := p.recv(), p.recv(), p.recv()
	if !strings.Contains(a, "-32600") || !strings.Contains(b, "-32600") {
		t.Errorf("reused id: got %s | %s, want two -32600 errors", a, b)
	}
	if strings.Contains(last, "tools\"") || !strings.Contains(last, `{\"a\":1}`) || runs.n() != 1 {
		t.Errorf("held call must get its own result once: %s (ran %d)", last, runs.n())
	}
}

func TestStdioDuplicateUpstreamResponse(t *testing.T) {
	p := startRaw(t, "pass", os.Args[0], helperArg, "dupup")
	p.send(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}` + "\n")
	p.send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n")
	got := p.barrier()
	if len(got) != 2 { // one response per request; the duplicates are dropped and nothing deadlocks
		t.Errorf("got %d lines, want 2: %v", len(got), got)
	}
}

func TestStdioUpstreamMessagesAreReserialized(t *testing.T) {
	p := startRaw(t, "pass", os.Args[0], helperArg, "evilup")
	p.send(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n")
	var note string
	for _, l := range p.barrier() {
		if strings.Contains(l, "notifications/message") {
			note = l
		}
	}
	if note == "" || strings.Contains(note, `"Id"`) || strings.Contains(note, `"Result"`) || strings.Contains(note, `"Method"`) {
		t.Errorf("upstream notification not re-serialized: %q", note)
	}
}

func TestStdioNilResultIsError(t *testing.T) {
	up := harness.StartServer(t, harness.Options{Tools: harness.DefaultTools(t)})
	p := startRaw(t, "nilnil", up.Command...)
	p.send(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}` + "\n")
	if l := p.recv(); !strings.Contains(l, `"code":-32603`) {
		t.Errorf("got %s", l)
	}
}

func TestStdioErrorMapping(t *testing.T) {
	up := harness.StartServer(t, harness.Options{Tools: harness.DefaultTools(t)})
	res, err := harness.NewClient(t, stdioProxy(t, "deny", up)).Call("echo", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	m, ok := harness.MetaOf(res)
	if !res.IsError || !ok || m.Outcome != contracts.EntryDenied || m.RuleID != "r1" || m.CallID == "" {
		t.Errorf("denied: %+v", res)
	}
	p := startRaw(t, "boom", up.Command...)
	p.send(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}` + "\n")
	if l := p.recv(); !strings.Contains(l, `"code":-32603`) || !strings.Contains(l, "boom") {
		t.Errorf("unknown error: %s", l)
	}
}

func TestStdioCancel(t *testing.T) {
	up := harness.StartServer(t, harness.Options{Tools: harness.DefaultTools(t)})
	p := startRaw(t, "hold", up.Command...)
	p.send(`{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"echo"}}` + "\n")
	p.send(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":5.0}}` + "\n")
	if l := p.recv(); !strings.Contains(l, "cancelled-seen") {
		t.Errorf("held call was not cancelled: %s", l)
	}
}

// httpCall posts a body with the headers a real 2026-07-28 client sends for tool.
func httpCall(t *testing.T, url, body, tool string) reply {
	req, _ := http.NewRequestWithContext(t.Context(), "POST", url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", tool)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return reply{resp.StatusCode, string(b)}
}

func TestHTTPBypassProbes(t *testing.T) {
	for _, pr := range probes() {
		if pr.stdioOnly {
			continue
		}
		t.Run(pr.name, func(t *testing.T) {
			var runs runLog
			up := harness.StartServer(t, harness.Options{HTTP: true, Tools: countingTools(t, &runs)})
			rec := &fn{f: modes["deny"]}
			if pr.diff {
				rec.f = pass
			}
			httpCall(t, httpProxy(t, rec, up).URL, pr.body, pr.tool)
			time.Sleep(100 * time.Millisecond)
			if runs.n() != 0 {
				t.Errorf("upstream ran %v", runs.list)
			}
			if len(rec.calls) != 0 {
				t.Errorf("interceptor saw %s %s", rec.calls[0].Tool, rec.calls[0].Args)
			}
		})
	}
}

// The upstream's canonical id (1) must find the call that arrived with id 1.0, and only the interceptor's result may reach the client.
func TestHTTPFloatID(t *testing.T) {
	up := harness.StartServer(t, harness.Options{HTTP: true, Tools: harness.DefaultTools(t)})
	marker := &fn{f: func(ctx context.Context, c *contracts.Call) (json.RawMessage, error) {
		if _, err := c.Forward(ctx); err != nil {
			return nil, err
		}
		return json.RawMessage(`{"content":[{"type":"text","text":"INTERCEPTOR"}]}`), nil
	}}
	got := httpCall(t, httpProxy(t, marker, up).URL,
		`{"jsonrpc":"2.0","id":1.0,"method":"tools/call","params":{"name":"echo","arguments":{"a":1},`+meta+`}}`, "echo")
	if !strings.Contains(got.body, "INTERCEPTOR") || !strings.Contains(got.body, `"id":1.0`) || strings.Contains(got.body, `{\"a\":1}`) {
		t.Errorf("got %d %s", got.status, got.body)
	}
}

func TestHTTPClientGivesUpOnHeldCall(t *testing.T) {
	up := harness.StartServer(t, harness.Options{HTTP: true, Tools: harness.DefaultTools(t)})
	tgt := httpProxy(t, &fn{f: modes["hold"]}, up)
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", tgt.URL, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if _, err := http.DefaultClient.Do(req); err == nil {
		t.Error("held call returned before the client gave up")
	}
}

// The upstream answers on one path and query only; every request type must reach it.
func TestHTTPRoutesToExactURL(t *testing.T) {
	up := harness.StartServer(t, harness.Options{HTTP: true, Tools: harness.DefaultTools(t)})
	target, _ := url.Parse(up.URL)
	var other atomic.Int64
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/only" || r.URL.RawQuery != "k=v" {
			other.Add(1)
			http.NotFound(w, r)
			return
		}
		r.URL.Path, r.URL.RawQuery = "/", ""
		httputil.NewSingleHostReverseProxy(target).ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)
	c := harness.NewClient(t, httpProxyURL(t, &fn{f: pass}, front.URL+"/only?k=v"))
	if _, err := c.ListTools(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Call("echo", map[string]any{"a": 1}); err != nil {
		t.Fatal(err)
	}
	if other.Load() != 0 {
		t.Errorf("%d request(s) went to the wrong path or query", other.Load())
	}
}

// A 3xx from the upstream is an error for the call, never followed.
func TestHTTPDoesNotFollowRedirects(t *testing.T) {
	var hits atomic.Int64
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	t.Cleanup(elsewhere.Close)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(front.Close)
	got := httpCall(t, httpProxyURL(t, &fn{f: pass}, front.URL).URL,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{},`+meta+`}}`, "echo")
	if hits.Load() != 0 || !strings.Contains(got.body, `"code":-32603`) {
		t.Errorf("redirect followed (%d hits) or not an error: %s", hits.Load(), got.body)
	}
}

func TestHTTPPassthroughRedirectRefused(t *testing.T) {
	var hits atomic.Int64
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	t.Cleanup(elsewhere.Close)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(front.Close)
	req, _ := http.NewRequestWithContext(t.Context(), "POST", httpProxyURL(t, &fn{f: pass}, front.URL).URL,
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 || hits.Load() != 0 {
		t.Errorf("status %d, %d hits: the redirect must be an error, not relayed or followed", resp.StatusCode, hits.Load())
	}
}

// The MRTR members the contract allows reach Call and the upstream as parsed.
func TestHTTPMRTRMembers(t *testing.T) {
	var runs runLog
	up := harness.StartServer(t, harness.Options{HTTP: true, Tools: countingTools(t, &runs)})
	rec := &fn{f: pass}
	got := httpCall(t, httpProxy(t, rec, up).URL,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"a":1},"requestState":"s1","inputResponses":{"k":{"action":"accept"}},`+meta+`}}`, "echo")
	if len(rec.calls) != 1 || rec.calls[0].RequestState != "s1" || string(rec.calls[0].InputResponses) != `{"k":{"action":"accept"}}` {
		t.Fatalf("call: %+v (%d %s)", rec.calls, got.status, got.body)
	}
	if runs.n() != 1 || !strings.Contains(runs.list[0], "state=s1") {
		t.Errorf("upstream saw %v", runs.list)
	}
}

// A tool declaring x-mcp-header: the client's Mcp-Param-Region header must reach the
// upstream, which checks it against the args the proxy re-serialized.
func TestHTTPParamHeaders(t *testing.T) {
	var runs runLog
	tools := countingTools(t, &runs)
	tools = append(tools, harness.Tool{Name: "regional", Description: "x",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"region":{"type":"string","x-mcp-header":"Region"}}}`),
		Handler: func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			runs.mu.Lock()
			runs.list = append(runs.list, "regional "+string(req.Params.Arguments))
			runs.mu.Unlock()
			return harness.Echo(ctx, req)
		}})
	up := harness.StartServer(t, harness.Options{HTTP: true, Tools: tools})
	tgt := httpProxy(t, &fn{f: pass}, up)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"regional","arguments":{"region":"eu"},` + meta + `}}`
	do := func(region string) reply {
		req, _ := http.NewRequestWithContext(t.Context(), "POST", tgt.URL, strings.NewReader(body))
		for k, v := range map[string]string{"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
			"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call", "Mcp-Name": "regional", "Mcp-Param-Region": region} {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return reply{resp.StatusCode, string(b)}
	}
	if got := do("eu"); !strings.Contains(got.body, `"result"`) || strings.Contains(got.body, `"error"`) || runs.n() != 1 {
		t.Errorf("correct header: %d %s (ran %d)", got.status, got.body, runs.n())
	}
	if got := do("us"); runs.n() != 1 {
		t.Errorf("lying header ran the tool: %d %s", got.status, got.body)
	}
}

// A 3xx is a Forward error even when its body is a well-formed result for the proxy's own id.
func TestHTTPRedirectBodyIsNotAResult(t *testing.T) {
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m struct{ ID json.RawMessage }
		json.NewDecoder(r.Body).Decode(&m)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Location", "http://example.invalid/")
		w.WriteHeader(http.StatusTemporaryRedirect)
		w.Write([]byte(`{"jsonrpc":"2.0","id":` + string(m.ID) + `,"result":{"content":[{"type":"text","text":"SMUGGLED"}]}}`))
	}))
	t.Cleanup(front.Close)
	got := httpCall(t, httpProxyURL(t, &fn{f: pass}, front.URL).URL,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{},`+meta+`}}`, "echo")
	if strings.Contains(got.body, "SMUGGLED") || !strings.Contains(got.body, `"code":-32603`) {
		t.Errorf("got %s", got.body)
	}
}

func TestHTTPNonPostBodyIsNotForwarded(t *testing.T) {
	var seen atomic.Int64
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen.Add(int64(len(b)))
	}))
	t.Cleanup(front.Close)
	tgt := httpProxyURL(t, &fn{f: pass}, front.URL)
	req, _ := http.NewRequestWithContext(t.Context(), "DELETE", tgt.URL, strings.NewReader("secret client bytes"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if seen.Load() != 0 {
		t.Errorf("upstream received %d body bytes", seen.Load())
	}
}

// 1e300 is large but finite and must still pass on both transports.
func TestStdioFiniteLargeNumberPasses(t *testing.T) {
	var runs runLog
	up := harness.StartServer(t, harness.Options{Tools: countingTools(t, &runs)})
	p := startRaw(t, "pass", up.Command...)
	p.initialize("2025-11-25")
	p.send(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"n":1e300}}}` + "\n")
	if l := p.recv(); !strings.Contains(l, `"result"`) || runs.n() != 1 {
		t.Errorf("got %s (ran %d)", l, runs.n())
	}
}

func TestHTTPFiniteLargeNumberPasses(t *testing.T) {
	var runs runLog
	up := harness.StartServer(t, harness.Options{HTTP: true, Tools: countingTools(t, &runs)})
	got := httpCall(t, httpProxy(t, &fn{f: pass}, up).URL,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"n":1e300},`+meta+`}}`, "echo")
	if !strings.Contains(got.body, `"result"`) || runs.n() != 1 {
		t.Errorf("got %d %s (ran %d)", got.status, got.body, runs.n())
	}
}

func TestStdioErrNotSent(t *testing.T) {
	up := harness.StartServer(t, harness.Options{Tools: harness.DefaultTools(t)})
	p := startRaw(t, "nsCancelled", up.Command...)
	p.send(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}` + "\n")
	if l := p.recv(); !strings.Contains(l, "notsent=true") {
		t.Errorf("ctx done before the write: %s", l)
	}
	// The write happened and the upstream never answers: a deadline now is not provably unsent.
	p = startRaw(t, "nsAfterWrite", os.Args[0], helperArg, "silentup")
	p.send(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo"}}` + "\n")
	if l := p.recv(); !strings.Contains(l, "notsent=false deadline=true") {
		t.Errorf("ctx done after the write: %s", l)
	}
}

// forwardErr runs a call through an HTTP proxy whose interceptor hands back Forward's error.
func forwardErr(t *testing.T, upURL string, ctxFor func(context.Context) (context.Context, context.CancelFunc)) error {
	var got error
	rec := &fn{f: func(ctx context.Context, c *contracts.Call) (json.RawMessage, error) {
		fctx, cancel := ctxFor(ctx)
		defer cancel()
		_, got = c.Forward(fctx)
		return nil, &contracts.CallError{Err: contracts.ErrDenied}
	}}
	httpCall(t, httpProxyURL(t, rec, upURL).URL,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{},`+meta+`}}`, "echo")
	return got
}

func TestHTTPErrNotSent(t *testing.T) {
	same := func(ctx context.Context) (context.Context, context.CancelFunc) { return context.WithCancel(ctx) }
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	t.Cleanup(slow.Close)
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close() // connection refused

	for _, tc := range []struct {
		name    string
		url     string
		ctx     func(context.Context) (context.Context, context.CancelFunc)
		notSent bool
	}{
		{"dial failure", closed.URL, same, true},
		{"ctx done before the write", slow.URL, func(ctx context.Context) (context.Context, context.CancelFunc) {
			c, cancel := context.WithCancel(ctx)
			cancel()
			return c, cancel
		}, true},
		{"deadline after the request was sent", slow.URL, func(ctx context.Context) (context.Context, context.CancelFunc) {
			return context.WithTimeout(ctx, 200*time.Millisecond)
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := forwardErr(t, tc.url, tc.ctx)
			if err == nil || errors.Is(err, contracts.ErrNotSent) != tc.notSent {
				t.Errorf("err = %v, want ErrNotSent=%v", err, tc.notSent)
			}
		})
	}
	// The upstream answered, with a redirect: the request was sent.
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/x", http.StatusTemporaryRedirect) }))
	t.Cleanup(redir.Close)
	if err := forwardErr(t, redir.URL, same); err == nil || errors.Is(err, contracts.ErrNotSent) {
		t.Errorf("3xx: err = %v, want a non-ErrNotSent error", err)
	}
}
