// Package harness is the shared end-to-end test substrate: a fake MCP server,
// a fake MCP client, and golden ledger fixtures. Both sides use the official
// MCP Go SDK so tests exercise real protocol framing.
//
// It knows nothing about policy, budgets, ledgers or approvals.
package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/midspan-dev/agentgw/pkg/contracts"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Target is where an MCP server can be reached: a process command speaking
// MCP on stdio, or a Streamable HTTP URL. Exactly one is set.
type Target struct {
	Command []string
	URL     string
}

// Tool is one fake tool. The JSON form is the file format of testdata/tools/.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	// Cost is attached to successful results as _meta.cost unless the handler
	// already set one.
	Cost *Cost `json:"cost,omitempty"`
	// LatencyMS delays every call before the handler runs.
	LatencyMS int `json:"latency_ms,omitempty"`
	// Handler defaults to Echo when nil. It receives the SDK request, whose
	// Session can send progress notifications.
	Handler mcp.ToolHandler `json:"-"`
}

// Cost is the per-tool _meta.cost (contracts/cost-meta.md section 1).
type Cost struct {
	Amount float64 `json:"amount"`
	// AmountArg, when set, takes the amount from this numeric argument instead.
	AmountArg string `json:"amount_arg,omitempty"`
	Currency  string `json:"currency"`
}

// Options configures StartServer.
type Options struct {
	HTTP  bool // Streamable HTTP; stdio when false
	Tools []Tool
	// FailNext makes the next N tools/call requests return a JSON-RPC error.
	FailNext int
}

const bridgeArg = "-agentgw-harness-bridge"

// The stdio target re-executes the current test binary as a bridge between
// its stdio and the in-process server's unix socket, so handlers stay in-process.
func init() {
	if len(os.Args) == 3 && os.Args[1] == bridgeArg {
		os.Exit(bridge(os.Args[2]))
	}
}

func bridge(sock string) int {
	c, err := net.Dial("unix", sock)
	if err != nil {
		fmt.Fprintln(os.Stderr, "harness bridge:", err)
		return 1
	}
	go func() {
		io.Copy(c, os.Stdin)
		c.(*net.UnixConn).CloseWrite()
	}()
	io.Copy(os.Stdout, c)
	return 0
}

// StartServer starts an in-process MCP server serving opts.Tools and returns
// its target. The server stops when the test ends.
func StartServer(t testing.TB, opts Options) Target {
	t.Helper()
	srv := mcp.NewServer(&mcp.Implementation{Name: "agentgw-harness", Version: "v0"}, nil)
	var fail atomic.Int64
	fail.Store(int64(opts.FailNext))
	for _, tool := range opts.Tools {
		srv.AddTool(&mcp.Tool{Name: tool.Name, Description: tool.Description, InputSchema: tool.InputSchema}, wrap(tool, &fail))
	}

	if opts.HTTP {
		// Stateless: the SDK's stateful handler only speaks pre-2026-07-28 versions (docs/adr/0008).
		hs := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv },
			&mcp.StreamableHTTPOptions{Stateless: true}))
		t.Cleanup(hs.Close)
		return Target{URL: hs.URL}
	}

	// Short temp dir: unix socket paths are limited to ~104 bytes.
	dir, err := os.MkdirTemp("", "agh")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close(); os.RemoveAll(dir) })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			if _, err := srv.Connect(context.Background(), &mcp.IOTransport{Reader: c, Writer: c}, nil); err != nil {
				c.Close()
			}
		}
	}()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return Target{Command: []string{exe, bridgeArg, ln.Addr().String()}}
}

// wrap applies failure injection, latency and _meta.cost around the handler.
func wrap(tool Tool, fail *atomic.Int64) mcp.ToolHandler {
	h := tool.Handler
	if h == nil {
		h = Echo
	}
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if fail.Add(-1) >= 0 {
			return nil, errors.New("harness: injected failure")
		}
		if tool.LatencyMS > 0 {
			select {
			case <-time.After(time.Duration(tool.LatencyMS) * time.Millisecond):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		res, err := h(ctx, req)
		if err != nil || res == nil || res.IsError || tool.Cost == nil {
			return res, err
		}
		if _, ok := res.Meta["cost"]; ok {
			return res, nil
		}
		amount := tool.Cost.Amount
		if tool.Cost.AmountArg != "" {
			var args map[string]any
			json.Unmarshal(req.Params.Arguments, &args)
			v, ok := args[tool.Cost.AmountArg].(float64)
			if !ok {
				return nil, fmt.Errorf("harness: %s: argument %q must be a number to compute _meta.cost", tool.Name, tool.Cost.AmountArg)
			}
			amount = v
		}
		if res.Meta == nil {
			res.Meta = mcp.Meta{}
		}
		res.Meta["cost"] = map[string]any{"amount": amount, "currency": tool.Cost.Currency}
		return res, nil
	}
}

// Echo is the default handler: one text item holding the arguments as
// compact JSON with sorted keys ("{}" when absent).
func Echo(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	args := map[string]any{}
	if len(req.Params.Arguments) > 0 {
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return nil, err
		}
	}
	b, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil
}

// Refuse builds the tool error a gateway returns for a refused call
// (contracts/cost-meta.md section 2). text should be CallError.Error().
func Refuse(m contracts.GatewayMeta, text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: text}},
		IsError: true,
		Meta:    mcp.Meta{"agentgw": m},
	}
}

// MetaOf reads _meta.agentgw from a result the client received.
func MetaOf(res *mcp.CallToolResult) (contracts.GatewayMeta, bool) {
	var m contracts.GatewayMeta
	v, ok := res.Meta["agentgw"]
	if !ok {
		return m, false
	}
	b, err := json.Marshal(v)
	return m, err == nil && json.Unmarshal(b, &m) == nil
}

// testdata is the repo's testdata/ directory, located from this source file.
func testdata() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "testdata")
}

// DefaultTools loads every tool in testdata/tools/, sorted by file name.
// Handlers are nil (Echo); replace them per tool as needed.
func DefaultTools(t testing.TB) []Tool {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(testdata(), "tools", "*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("harness: no tool fixtures: %v", err)
	}
	var tools []Tool
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var tool Tool
		if err := json.Unmarshal(b, &tool); err != nil {
			t.Fatalf("harness: %s: %v", f, err)
		}
		tools = append(tools, tool)
	}
	return tools
}

// Client is an MCP client session plus the progress notifications it received.
type Client struct {
	*mcp.ClientSession
	// Progress receives every progress notification, buffered.
	Progress chan *mcp.ProgressNotificationParams
	t        testing.TB
}

// NewClient connects to target and closes the session when the test ends.
func NewClient(t testing.TB, target Target) *Client {
	t.Helper()
	c := &Client{Progress: make(chan *mcp.ProgressNotificationParams, 256), t: t}
	cl := mcp.NewClient(&mcp.Implementation{Name: "agentgw-harness-client", Version: "v0"}, &mcp.ClientOptions{
		ProgressNotificationHandler: func(_ context.Context, r *mcp.ProgressNotificationClientRequest) {
			select {
			case c.Progress <- r.Params:
			default: // shortcut: drops notifications past 256 unread, upgrade if a test needs more
			}
		},
	})
	var tr mcp.Transport
	switch {
	case target.URL != "":
		tr = &mcp.StreamableClientTransport{Endpoint: target.URL}
	case len(target.Command) > 0:
		tr = &mcp.CommandTransport{Command: exec.Command(target.Command[0], target.Command[1:]...)}
	default:
		t.Fatal("harness: empty target")
	}
	s, err := cl.Connect(t.Context(), tr, nil)
	if err != nil {
		t.Fatalf("harness: connect: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	c.ClientSession = s
	return c
}

// Call calls a tool with args.
func (c *Client) Call(name string, args any) (*mcp.CallToolResult, error) {
	return c.CallWithProgress(name, args, nil)
}

// CallWithProgress calls a tool with args and, when token is non-nil, a
// progressToken; notifications arrive on c.Progress.
func (c *Client) CallWithProgress(name string, args any, token any) (*mcp.CallToolResult, error) {
	p := &mcp.CallToolParams{Name: name, Arguments: args}
	if token != nil {
		p.SetProgressToken(token)
	}
	return c.CallTool(c.t.Context(), p)
}

// ignored are the ledger fields Golden does not compare.
var ignored = [][]string{
	{"id"}, {"ts"}, {"call_id"}, {"prev_hash"}, {"sig"}, {"signer"},
	{"principal", "run_id"}, {"principal", "session_id"},
	{"decision", "policy_version"}, {"decision", "approval"}, {"decision", "grant_id"},
}

// Golden compares the `type: entry` lines of the ledger at ledgerPath, in
// order, against testdata/golden/<name>.jsonl, ignoring volatile fields and
// result.error on outcome-error lines.
func Golden(t testing.TB, name, ledgerPath string) {
	t.Helper()
	want := entries(t, filepath.Join(testdata(), "golden", name+".jsonl"))
	got := entries(t, ledgerPath)
	if len(got) != len(want) {
		t.Fatalf("golden %s: %d entries, want %d", name, len(got), len(want))
	}
	for i := range want {
		if !reflect.DeepEqual(want[i], got[i]) {
			w, _ := json.Marshal(want[i])
			g, _ := json.Marshal(got[i])
			t.Errorf("golden %s entry %d:\nwant %s\ngot  %s", name, i+1, w, g)
		}
	}
}

// entries reads the entry lines of a JSONL ledger with ignored fields removed.
func entries(t testing.TB, path string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for n, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("%s:%d: %v", path, n+1, err)
		}
		switch m["type"] {
		case contracts.LineTypeEntry:
		case contracts.LineTypeCheckpoint:
			continue
		default:
			t.Fatalf("%s:%d: unknown line type %v", path, n+1, m["type"])
			continue
		}
		for _, f := range ignored {
			obj := m
			if len(f) == 2 {
				obj, _ = m[f[0]].(map[string]any)
			}
			delete(obj, f[len(f)-1])
		}
		if r, ok := m["result"].(map[string]any); ok && m["outcome"] == string(contracts.EntryError) {
			delete(r, "error") // upstream error text is not ours to pin (docs/adr/0008)
		}
		out = append(out, m)
	}
	return out
}
