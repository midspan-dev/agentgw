package ghapproval

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/midspan-dev/agentgw/internal/approval"
	"github.com/midspan-dev/agentgw/pkg/contracts"
)

const (
	commentsPath = "/repos/o/r/issues/7/comments"
	pageSize     = 100
)

// fakeGH implements the three endpoints the poller uses. Its clock ticks one
// second per created comment, so creation order is strict.
type fakeGH struct {
	mu          sync.Mutex
	srv         *httptest.Server
	comments    []ghComment
	perms       map[string]string // login -> role_name; absent: 404
	reqs        []string          // "METHOD uri"
	tick        int
	hold        bool // 500 on comment GET and POST
	ignoreSince bool
	failPage2   int
	rateLimit   bool // next request: 403 Retry-After 2
	permLimit   bool // next permission lookup: 403 Retry-After 2
	forbid      bool // next request: plain 403
	gw          map[int64]bool
	blankLogin  int // next N POST responses omit the author login
	gwLogin     string // login and type the gateway's comments are posted as
	gwType      string
}

func newFake(t *testing.T) *fakeGH {
	f := &fakeGH{perms: map[string]string{}, gw: map[int64]bool{}, gwLogin: "gw", gwType: "Bot"}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

var epoch = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

func (f *fakeGH) addLocked(login, typ, body string) ghComment {
	f.tick++
	c := ghComment{ID: int64(1000 + len(f.comments)), Body: body, CreatedAt: epoch.Add(time.Duration(f.tick) * time.Second)}
	c.HTMLURL = fmt.Sprintf("https://github.com/o/r/issues/7#issuecomment-%d", c.ID)
	c.User.Login, c.User.Type = login, typ
	f.comments = append(f.comments, c)
	return c
}

func (f *fakeGH) add(login, typ, body string) ghComment {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.addLocked(login, typ, body)
}

func (f *fakeGH) edit(id int64, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.comments {
		if f.comments[i].ID == id {
			f.comments[i].Body = body
		}
	}
}

func (f *fakeGH) setHold(v bool) { f.mu.Lock(); f.hold = v; f.mu.Unlock() }

func (f *fakeGH) count(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.reqs {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}

// bots returns the bodies the gateway posted.
func (f *fakeGH) bots() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, c := range f.comments {
		if f.gw[c.ID] {
			out = append(out, c.Body)
		}
	}
	return out
}

func (f *fakeGH) botsWith(sub string) int {
	n := 0
	for _, b := range f.bots() {
		if strings.Contains(b, sub) {
			n++
		}
	}
	return n
}

func (f *fakeGH) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, r.Method+" "+r.URL.RequestURI())
	if f.rateLimit {
		f.rateLimit = false
		w.Header().Set("Retry-After", "2")
		w.WriteHeader(403)
		return
	}
	if f.forbid {
		f.forbid = false
		// Every GitHub response carries these; a 403 with budget left is not a rate limit.
		w.Header().Set("X-RateLimit-Remaining", "4999")
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))
		w.WriteHeader(403)
		return
	}
	if f.permLimit && strings.HasSuffix(r.URL.Path, "/permission") {
		f.permLimit = false
		w.Header().Set("Retry-After", "2")
		w.WriteHeader(403)
		return
	}
	switch {
	case r.URL.Path == commentsPath && f.hold:
		w.WriteHeader(500)
	case r.URL.Path == commentsPath && r.Method == "POST":
		var in struct{ Body string }
		json.NewDecoder(r.Body).Decode(&in)
		if len(in.Body) > 65536 {
			w.WriteHeader(422)
			return
		}
		c := f.addLocked(f.gwLogin, f.gwType, in.Body)
		f.gw[c.ID] = true
		if f.blankLogin > 0 {
			f.blankLogin--
			c.User.Login = ""
		}
		w.WriteHeader(201)
		json.NewEncoder(w).Encode(c)
	case r.URL.Path == commentsPath:
		since, _ := time.Parse(time.RFC3339, r.URL.Query().Get("since"))
		var match []ghComment
		for _, c := range f.comments {
			// GitHub may treat since as exclusive; be strict.
			if f.ignoreSince || c.CreatedAt.After(since) {
				match = append(match, c)
			}
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		page = max(page, 1)
		if page == 2 && f.failPage2 > 0 {
			f.failPage2--
			w.WriteHeader(500)
			return
		}
		lo, hi := min((page-1)*pageSize, len(match)), min(page*pageSize, len(match))
		if hi < len(match) {
			q := r.URL.Query()
			q.Set("page", strconv.Itoa(page+1))
			w.Header().Set("Link", fmt.Sprintf(`<%s%s?%s>; rel="next"`, f.srv.URL, commentsPath, q.Encode()))
		}
		json.NewEncoder(w).Encode(match[lo:hi])
	case strings.HasPrefix(r.URL.Path, "/repos/o/r/collaborators/") && strings.HasSuffix(r.URL.Path, "/permission"):
		login := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/repos/o/r/collaborators/"), "/permission")
		role, ok := f.perms[login]
		if role == "500" {
			w.WriteHeader(500)
			return
		}
		if !ok {
			w.WriteHeader(404)
			return
		}
		fmt.Fprintf(w, `{"permission":"read","role_name":%q}`, role)
	default:
		w.WriteHeader(404)
	}
}

// settle waits until the poller has fetched comments three more times.
func (f *fakeGH) settle(t *testing.T) {
	t.Helper()
	n := f.count("GET " + commentsPath)
	waitFor(t, "three more polls", func() bool { return f.count("GET "+commentsPath) >= n+3 })
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

type env struct {
	t     *testing.T
	f     *fakeGH
	store *approval.Store
	opts  Options
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	tok := filepath.Join(dir, "tok")
	if err := approval.GenerateToken(tok); err != nil {
		t.Fatal(err)
	}
	s, err := approval.Open(filepath.Join(dir, "state.db"), tok)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	f := newFake(t)
	return &env{t: t, f: f, store: s, opts: Options{
		Config: contracts.GitHubApprovals{Repo: "o/r", Issue: 7, MinPermission: "write", PollInterval: "10ms", TokenEnv: "GITHUB_TOKEN"},
		Token:  "tok", APIBase: f.srv.URL, Store: s,
	}}
}

// start runs the poller until the test ends.
func (e *env) start() {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { Run(ctx, e.opts); close(done) }()
	e.t.Cleanup(func() { cancel(); <-done })
}

func (e *env) request(tool string, timeout int) (id, ref string) {
	e.t.Helper()
	id, err := e.store.Request(context.Background(), contracts.ApprovalRequest{
		CallID: "c-" + tool, Principal: contracts.Principal{AgentID: "agent-1"}, Server: "srv", Tool: tool,
		ArgsHash: "hash-" + tool, Args: json.RawMessage(`{"amount": 50}`),
		EstimatedCost: contracts.Money{Micros: 500000, Currency: "USD"}, RuleID: "rule-1",
		Spec: contracts.ApprovalSpec{TimeoutSeconds: timeout},
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return id, strings.ToUpper(id[len(id)-8:])
}

// announced waits for the request comment for ref.
func (e *env) announced(ref string) {
	e.t.Helper()
	waitFor(e.t, "request comment", func() bool { return e.f.botsWith("Ref: "+ref) > 0 })
}

func (e *env) wait(id string) (*contracts.ApprovalDecision, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return e.store.Wait(ctx, id, func(string) {})
}

func (e *env) pending() int {
	l, _ := e.store.List(context.Background())
	return len(l)
}
