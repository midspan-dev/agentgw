package harness

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gowebpki/jcs"
	"github.com/midspan-dev/agentgw/pkg/contracts"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

func text(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) != 1 {
		t.Fatalf("content: %+v", res.Content)
	}
	return res.Content[0].(*mcp.TextContent).Text
}

func TestE2EEcho(t *testing.T) {
	for _, http := range []bool{false, true} {
		t.Run(map[bool]string{false: "stdio", true: "http"}[http], func(t *testing.T) {
			c := NewClient(t, StartServer(t, Options{HTTP: http, Tools: DefaultTools(t)}))
			lt, err := c.ListTools(t.Context(), nil)
			if err != nil || len(lt.Tools) != 5 {
				t.Fatalf("list tools: %v %+v", err, lt)
			}
			res, err := c.Call("echo", map[string]any{"b": 2, "a": "x"})
			if err != nil {
				t.Fatal(err)
			}
			// The serverInfo meta proves both transports run protocol 2026-07-28.
			if got := text(t, res); got != `{"a":"x","b":2}` || res.IsError || res.Meta["io.modelcontextprotocol/serverInfo"] == nil {
				t.Fatalf("echo: %q %+v", got, res)
			}
		})
	}
}

func TestE2ECostMeta(t *testing.T) {
	c := NewClient(t, StartServer(t, Options{Tools: DefaultTools(t)}))
	for tool, want := range map[string]float64{"search": 0.005, "refund": 42.5} {
		res, err := c.Call(tool, map[string]any{"amount": 42.5})
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]any{"amount": want, "currency": "USD"}
		if !reflect.DeepEqual(res.Meta["cost"], want) {
			t.Errorf("%s: _meta.cost = %v, want %v", tool, res.Meta["cost"], want)
		}
	}
	// A cost that cannot be computed fails loudly instead of dropping _meta.cost.
	for _, args := range []map[string]any{{"amount": "50"}, {"charge": "ch_1"}} {
		res, err := c.Call("refund", args)
		if err == nil && !res.IsError && res.Meta["cost"] == nil {
			t.Errorf("refund %v: successful result without cost", args)
		}
	}
}

func TestE2EHandlerProgressAndMeta(t *testing.T) {
	for _, http := range []bool{false, true} {
		t.Run(map[bool]string{false: "stdio", true: "http"}[http], func(t *testing.T) {
			tools := DefaultTools(t)
			for i := range tools {
				if tools[i].Name == "search" {
					tools[i].Handler = func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
						if tok := req.Params.GetProgressToken(); tok != nil {
							req.Session.NotifyProgress(ctx, &mcp.ProgressNotificationParams{ProgressToken: tok, Message: "waiting", Progress: 1})
						}
						res := Refuse(contracts.GatewayMeta{Outcome: contracts.EntryBudgetExceeded, Reason: "r", CallID: "c1"}, "agentgw: budget exceeded: r")
						res.Meta["x"] = "kept"
						return res, nil
					}
				}
			}
			c := NewClient(t, StartServer(t, Options{HTTP: http, Tools: tools}))
			res, err := c.CallWithProgress("search", nil, "tok-1")
			if err != nil {
				t.Fatal(err)
			}
			m, ok := MetaOf(res)
			if !ok || m.Outcome != contracts.EntryBudgetExceeded || m.CallID != "c1" || res.Meta["x"] != "kept" || !res.IsError {
				t.Fatalf("meta: %+v %+v", m, res)
			}
			if _, ok := res.Meta["cost"]; ok {
				t.Fatal("cost attached to a tool error")
			}
			select {
			case p := <-c.Progress:
				if p.Message != "waiting" || p.ProgressToken != "tok-1" {
					t.Fatalf("progress: %+v", p)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("no progress notification")
			}
		})
	}
}

func TestE2EFailNext(t *testing.T) {
	c := NewClient(t, StartServer(t, Options{Tools: DefaultTools(t), FailNext: 2}))
	for i := range 3 {
		_, err := c.Call("echo", nil)
		if (err != nil) != (i < 2) {
			t.Fatalf("call %d: err = %v", i, err)
		}
	}
}

func TestE2ELatency(t *testing.T) {
	tools := []Tool{{Name: "slowish", InputSchema: json.RawMessage(`{"type":"object"}`), LatencyMS: 200}}
	c := NewClient(t, StartServer(t, Options{Tools: tools}))
	start := time.Now()
	if _, err := c.Call("slowish", nil); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < 200*time.Millisecond {
		t.Fatalf("returned after %v", d)
	}
}

func TestGoldenSelf(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	src, err := os.ReadFile(filepath.Join(testdata(), "golden", "allow.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	// Change ignored fields and add a checkpoint line: still matches.
	mutated := strings.ReplaceAll(string(src), `"run_id":"run-1"`, `"run_id":"other"`)
	mutated = `{"type":"checkpoint","version":"1"}` + "\n" + mutated
	os.WriteFile(path, []byte(mutated), 0o600)
	Golden(t, "allow", path)

	ft := &fakeT{TB: t}
	os.WriteFile(path, bytes.Replace(src, []byte(`"outcome":"ok"`), []byte(`"outcome":"error"`), 1), 0o600)
	Golden(ft, "allow", path)
	if !ft.failed {
		t.Fatal("Golden accepted a changed outcome")
	}

	// Only checkpoint lines are skipped; any other type, or none, is fatal.
	for _, stray := range []string{`{"type":"Entry","version":"1"}`, `{"version":"1"}`} {
		ft = &fakeT{TB: t}
		os.WriteFile(path, []byte(stray+"\n"+string(src)), 0o600)
		Golden(ft, "allow", path)
		if !ft.failed {
			t.Fatalf("Golden accepted stray line %s", stray)
		}
	}

	// result.error is ignored on outcome-error lines only.
	src, err = os.ReadFile(filepath.Join(testdata(), "golden", "error.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(path, bytes.Replace(src, []byte(`"error":"harness: injected failure"`), []byte(`"error":"something else"`), 1), 0o600)
	Golden(t, "error", path)
	ft = &fakeT{TB: t}
	src, _ = os.ReadFile(filepath.Join(testdata(), "golden", "deny.jsonl"))
	os.WriteFile(path, bytes.Replace(src, []byte(`by rule no-destructive"`), []byte(`by rule other"`), 1), 0o600)
	Golden(ft, "deny", path)
	if !ft.failed {
		t.Fatal("Golden accepted a changed result.error on a denied line")
	}
}

type fakeT struct {
	testing.TB
	failed bool
}

func (f *fakeT) Errorf(string, ...any) { f.failed = true }
func (f *fakeT) Fatalf(string, ...any) { f.failed = true }

func sha(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	c, err := jcs.Transform(b)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(c)
	return hex.EncodeToString(s[:])
}

// Every golden line validates against the ledger-entry schema, its hashes
// are the hashes of its args and content, and its content is what the
// harness tool actually returns.
func TestGoldenFiles(t *testing.T) {
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	schemas, _ := filepath.Glob("../../contracts/schemas/*.schema.json")
	for _, f := range schemas {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.AddResource("https://agentgw.dev/schemas/v1/"+filepath.Base(f), doc); err != nil {
			t.Fatal(err)
		}
	}
	schema, err := c.Compile("https://agentgw.dev/schemas/v1/ledger-entry.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	client := NewClient(t, StartServer(t, Options{Tools: DefaultTools(t)}))

	want := map[string]int{"allow": 5, "deny": 1, "approval": 1, "budget": 3, "timeout": 1, "error": 1}
	files, _ := filepath.Glob(filepath.Join(testdata(), "golden", "*.jsonl"))
	if len(files) != len(want) {
		t.Fatalf("golden files: %v", files)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
		name := strings.TrimSuffix(filepath.Base(f), ".jsonl")
		if len(lines) != want[name] {
			t.Errorf("%s: %d lines, want %d", name, len(lines), want[name])
		}
		for i, line := range lines {
			doc, err := jsonschema.UnmarshalJSON(strings.NewReader(line))
			if err != nil {
				t.Fatalf("%s:%d: %v", name, i+1, err)
			}
			if err := schema.Validate(doc); err != nil {
				t.Errorf("%s:%d: %v", name, i+1, err)
			}
			var e contracts.Entry
			if err := json.Unmarshal([]byte(line), &e); err != nil {
				t.Fatalf("%s:%d: %v", name, i+1, err)
			}
			if h := sha(t, e.Action.Args); h != e.Action.ArgsHash {
				t.Errorf("%s:%d: args_hash want %s", name, i+1, h)
			}
			if string(e.Result.Content) == "null" {
				continue
			}
			if h := sha(t, e.Result.Content); h != e.Result.ResultHash {
				t.Errorf("%s:%d: result_hash want %s", name, i+1, h)
			}
			res, err := client.Call(e.Action.Tool, e.Action.Args)
			if err != nil {
				t.Fatal(err)
			}
			// Strip the protocol envelope per docs/adr/0008, independently of the ledger.
			var got map[string]any
			var wantContent any
			b, _ := json.Marshal(res)
			json.Unmarshal(b, &got)
			if got["resultType"] == nil {
				t.Errorf("%s:%d: no resultType: is the server on 2026-07-28?", name, i+1)
			}
			delete(got, "resultType")
			if meta, ok := got["_meta"].(map[string]any); ok {
				for k := range meta {
					if strings.HasPrefix(k, "io.modelcontextprotocol/") {
						delete(meta, k)
					}
				}
				if len(meta) == 0 {
					delete(got, "_meta")
				}
			}
			json.Unmarshal(e.Result.Content, &wantContent)
			if !reflect.DeepEqual(any(got), wantContent) {
				t.Errorf("%s:%d: content want %s", name, i+1, b)
			}
		}
	}
}
