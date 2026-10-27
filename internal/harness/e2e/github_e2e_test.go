package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/midspan-dev/agentgw/internal/harness"
	"github.com/midspan-dev/agentgw/pkg/contracts"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// fakeGitHub serves the three endpoints the gateway uses: comment list,
// comment create and collaborator permission.
type fakeGitHub struct {
	mu       sync.Mutex
	reqs     int
	comments []map[string]any
	bots     map[int]bool
}

func newFakeGitHub(t *testing.T) (*fakeGitHub, *httptest.Server) {
	f := &fakeGitHub{bots: map[int]bool{}}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return f, srv
}

// addLocked appends a comment; created_at ticks one second per comment.
func (f *fakeGitHub) addLocked(login, typ, body string) map[string]any {
	id := 1000 + len(f.comments)
	c := map[string]any{
		"id": id, "body": body, "html_url": fmt.Sprintf("https://github.com/o/r/issues/7#issuecomment-%d", id),
		"created_at": time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC).Add(time.Duration(len(f.comments)+1) * time.Second).Format(time.RFC3339),
		"user":       map[string]any{"login": login, "type": typ},
	}
	f.comments = append(f.comments, c)
	return c
}

func (f *fakeGitHub) userSays(login, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addLocked(login, "User", body)
}

// userSays2 adds two comments under one lock so one poll sees both.
func (f *fakeGitHub) userSays2(login string, bodies ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, b := range bodies {
		f.addLocked(login, "User", b)
	}
}

func (f *fakeGitHub) requests() int { f.mu.Lock(); defer f.mu.Unlock(); return f.reqs }

// botBodies returns what the gateway posted.
func (f *fakeGitHub) botBodies() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for i, c := range f.comments {
		if f.bots[i] {
			out = append(out, c["body"].(string))
		}
	}
	return out
}

func (f *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs++
	switch {
	case r.URL.Path == "/repos/o/r/issues/7/comments" && r.Method == "POST":
		var in struct{ Body string }
		json.NewDecoder(r.Body).Decode(&in)
		c := f.addLocked("gw", "Bot", in.Body)
		f.bots[len(f.comments)-1] = true
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(c)
	case r.URL.Path == "/repos/o/r/issues/7/comments":
		since, _ := time.Parse(time.RFC3339, r.URL.Query().Get("since"))
		out := []map[string]any{}
		for _, c := range f.comments {
			if at, _ := time.Parse(time.RFC3339, c["created_at"].(string)); at.After(since) {
				out = append(out, c)
			}
		}
		json.NewEncoder(w).Encode(out)
	case r.URL.Path == "/repos/o/r/collaborators/alice/permission":
		fmt.Fprint(w, `{"permission":"read","role_name":"write"}`)
	default:
		w.WriteHeader(404)
	}
}

func ghWait(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(30 * time.Second); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

var refRe = regexp.MustCompile(`<!-- agentgw ref=([A-Z0-9]{8}) -->`)

func TestE2EGitHubApprovalThroughRun(t *testing.T) {
	f, srv := newFakeGitHub(t)
	t.Setenv("GITHUB_API_URL", srv.URL)
	t.Setenv("GITHUB_TOKEN", "test-token")

	target := harness.StartServer(t, harness.Options{Tools: harness.DefaultTools(t)})
	g := setup(t, map[string]any{"name": "harness", "command": target.Command}, "", "60s")
	raw, err := os.ReadFile(g.cfg)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["approvals"].(map[string]any)["github"] = map[string]any{"repo": "o/r", "issue": 7, "poll_interval": "5s"}
	b, _ := json.Marshal(cfg)
	write(t, g.cfg, b)
	g.client = harness.NewClient(t, harness.Target{Command: []string{bin, "run", "--config", g.cfg}})

	res, err := g.client.Call("echo", map[string]any{"n": 1})
	okText(t, res, err, `{"n":1}`)

	if n := f.requests(); n != 0 {
		t.Fatalf("fake GitHub saw %d requests before the first refund", n)
	}
	type result struct {
		res *mcp.CallToolResult
		err error
	}
	refund := func(charge string) chan result {
		c := make(chan result, 1)
		go func() {
			r, e := g.client.Call("refund", map[string]any{"amount": 50, "charge": charge})
			c <- result{r, e}
		}()
		return c
	}
	// Both refunds are held at once; each ref is found by its charge in the request comment.
	ca, cb := refund("ch_A"), refund("ch_B")
	refFor := func(charge string) string {
		var ref string
		ghWait(t, "request comment for "+charge, func() bool {
			for _, b := range f.botBodies() {
				if m := refRe.FindStringSubmatch(b); m != nil && strings.Contains(b, charge) {
					ref = m[1]
					return true
				}
			}
			return false
		})
		return ref
	}
	refA, refB := refFor("ch_A"), refFor("ch_B")
	// Both replies are in the comment list before the next poll reads it.
	f.userSays2("alice", "/approve "+refA, "/deny "+refB+" nope")
	ra, rb := <-ca, <-cb
	okText(t, ra.res, ra.err, `{"amount":50,"charge":"ch_A"}`)
	refused(t, rb.res, rb.err, contracts.EntryApprovalDenied, "refunds-need-approval", "agentgw: approval denied: nope")
	ghWait(t, "outcome comment", func() bool {
		for _, b := range f.botBodies() {
			if strings.Contains(b, "approved by @alice") {
				return true
			}
		}
		return false
	})

	var held []contracts.Entry
	for _, e := range g.entries() {
		if e.Decision.Outcome == contracts.OutcomeRequireApproval {
			held = append(held, e)
		}
	}
	if len(held) != 2 {
		t.Fatalf("want 2 require_approval entries, got %d", len(held))
	}
	var ok, denied int
	for _, e := range held {
		switch e.Outcome {
		case contracts.EntryOK:
			ok++
			if a := e.Decision.Approval; a == nil || a.Via == nil || a.Via.User != "alice" || a.Via.Surface != "github" {
				t.Fatalf("approved entry approval %+v", a)
			}
		case contracts.EntryApprovalDenied:
			denied++
		}
	}
	if ok != 1 || denied != 1 {
		t.Fatalf("want one ok and one denied entry, got %d and %d", ok, denied)
	}
	// Entry order follows completion, so find the denied one by outcome.
	for _, e := range held {
		if e.Outcome == contracts.EntryApprovalDenied {
			if a := e.Decision.Approval; a == nil || a.Decision != contracts.DecisionDenied || a.Via == nil || a.Via.User != "alice" {
				t.Fatalf("denied entry approval %+v", a)
			}
			if e.Result.ResultHash != "" {
				t.Fatalf("denied call has an upstream result: %+v", e.Result)
			}
		}
	}
	if out := g.cli("verify"); !strings.HasPrefix(out, "ok: ") {
		t.Fatalf("verify: %q", out)
	}
}
