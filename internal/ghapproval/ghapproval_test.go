package ghapproval

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/midspan-dev/agentgw/pkg/contracts"
)

func TestRequestCommentPosted(t *testing.T) {
	e := newEnv(t)
	_, ref := e.request("refund", 60)
	e.start()
	e.announced(ref)
	e.f.settle(t)
	bots := e.f.bots()
	if len(bots) != 1 {
		t.Fatalf("want exactly one comment, got %d: %q", len(bots), bots)
	}
	for _, want := range []string{"agent-1", "srv.refund", `"amount":50`, "rule-1", "/approve " + ref, "/deny " + ref + " [reason]", "0.5 USD", "<!-- agentgw ref=" + ref + " -->"} {
		if !strings.Contains(bots[0], want) {
			t.Errorf("request comment lacks %q:\n%s", want, bots[0])
		}
	}
}

func TestApproveByCollaborator(t *testing.T) {
	e := newEnv(t)
	e.f.perms["alice"] = "write"
	id, ref := e.request("refund", 60)
	e.start()
	e.announced(ref)
	c := e.f.add("alice", "User", "/approve "+strings.ToLower(ref))
	d, err := e.wait(id)
	if err != nil || d.Decision != contracts.DecisionApproved || d.Via == nil || d.Via.User != "alice" || d.Via.URL != c.HTMLURL || d.Via.Surface != "github" {
		t.Fatalf("decision %+v err %v", d, err)
	}
	waitFor(t, "outcome comment", func() bool { return e.f.botsWith("approved by @alice") == 1 })
}

func TestDenyWithReason(t *testing.T) {
	e := newEnv(t)
	e.f.perms["alice"] = "admin"
	id, ref := e.request("refund", 60)
	e.start()
	e.announced(ref)
	e.f.add("alice", "User", "/deny "+ref+" too risky")
	d, err := e.wait(id)
	if err == nil || d.Decision != contracts.DecisionDenied || d.Reason != "too risky" || d.Via == nil || d.Via.User != "alice" {
		t.Fatalf("decision %+v err %v", d, err)
	}
	waitFor(t, "outcome comment", func() bool { return e.f.botsWith("denied by @alice: `too risky`") == 1 })
}

func TestNonCollaboratorIgnored(t *testing.T) {
	e := newEnv(t)
	e.f.perms["reader"] = "read" // "stranger" has no entry: 404
	_, ref := e.request("refund", 60)
	e.start()
	e.announced(ref)
	e.f.add("reader", "User", "/approve "+ref)
	e.f.add("stranger", "User", "/approve "+ref)
	waitFor(t, "both permission checks", func() bool { return e.f.count("GET /repos/o/r/collaborators/") >= 2 })
	e.f.settle(t)
	if e.pending() != 1 || len(e.f.bots()) != 1 {
		t.Fatalf("pending %d, gateway comments %q", e.pending(), e.f.bots())
	}
}

func TestBotIgnored(t *testing.T) {
	e := newEnv(t)
	e.f.perms["dependabot[bot]"] = "admin"
	_, ref := e.request("refund", 60)
	e.start()
	e.announced(ref)
	e.f.add("dependabot[bot]", "Bot", "/approve "+ref)
	e.f.settle(t)
	if e.pending() != 1 || e.f.count("GET /repos/o/r/collaborators/") != 0 {
		t.Fatalf("bot comment was acted on or checked: pending %d", e.pending())
	}
}

func TestMinPermissionTriage(t *testing.T) {
	e := newEnv(t)
	e.opts.Config.MinPermission = "triage"
	e.f.perms["rita"], e.f.perms["tess"] = "read", "triage"
	id, ref := e.request("refund", 60)
	e.start()
	e.announced(ref)
	e.f.add("rita", "User", "/approve "+ref)
	waitFor(t, "read checked", func() bool { return e.f.count("GET /repos/o/r/collaborators/rita") == 1 })
	e.f.settle(t)
	if e.pending() != 1 {
		t.Fatal("read resolved a triage-level approval")
	}
	e.f.add("tess", "User", "/approve "+ref)
	if d, err := e.wait(id); err != nil || d.Via.User != "tess" {
		t.Fatalf("%+v %v", d, err)
	}
}

func TestRefOfAnotherCall(t *testing.T) {
	e := newEnv(t)
	e.f.perms["alice"] = "write"
	id1, ref1 := e.request("first", 60)
	id2, ref2 := e.request("second", 60)
	e.start()
	e.announced(ref1)
	e.announced(ref2)
	e.f.add("alice", "User", "/approve "+ref2)
	if d, err := e.wait(id2); err != nil || d.CallID != "c-second" {
		t.Fatalf("%+v %v", d, err)
	}
	e.f.settle(t)
	l, _ := e.store.List(t.Context())
	if len(l) != 1 || l[0].ID != id1 {
		t.Fatalf("first approval should stay pending: %+v", l)
	}
}

func TestUnknownRefRepliedOnce(t *testing.T) {
	e := newEnv(t)
	e.f.perms["alice"] = "write"
	_, ref := e.request("refund", 60)
	e.start()
	e.announced(ref)
	e.f.add("alice", "User", "/approve ZZZZZZZZ")
	waitFor(t, "reply", func() bool { return e.f.botsWith("no pending approval `ZZZZZZZZ`") == 1 })
	e.f.add("alice", "User", "/approve ZZZZZZZZ")
	e.f.settle(t)
	if n := e.f.botsWith("no pending approval"); n != 1 {
		t.Fatalf("%d replies", n)
	}
}

func TestReplyAfterResolved(t *testing.T) {
	e := newEnv(t)
	e.f.perms["alice"] = "write"
	id, ref := e.request("refund", 60)
	e.start()
	e.announced(ref)
	// While the fake refuses comment traffic, the CLI approves and a deny
	// arrives; the poller must see both together.
	e.f.setHold(true)
	if err := e.store.Approve(t.Context(), id, "hash-refund", "", time.Time{}); err != nil {
		t.Fatal(err)
	}
	e.f.add("alice", "User", "/deny "+ref)
	e.f.setHold(false)
	waitFor(t, "reply and outcome", func() bool {
		return e.f.botsWith("already approved") == 1 && e.f.botsWith("approved by the local approver") == 2
	})
	if d, err := e.wait(id); err != nil || d.Decision != contracts.DecisionApproved {
		t.Fatalf("decision changed: %+v %v", d, err)
	}
	if n := e.f.botsWith("already"); n != 1 {
		t.Fatalf("%d replies", n)
	}
}

func TestReplyAfterExpiry(t *testing.T) {
	e := newEnv(t)
	e.f.perms["alice"] = "write"
	_, ref := e.request("refund", 1)
	e.start()
	e.announced(ref)
	e.f.setHold(true)
	time.Sleep(1200 * time.Millisecond) // the store keeps its own clock
	e.f.add("alice", "User", "/approve "+ref)
	e.f.setHold(false)
	waitFor(t, "reply and outcome", func() bool { return e.f.botsWith("already expired") == 1 && e.f.botsWith("expired") == 2 })
	if e.pending() != 0 {
		t.Fatal("expired approval still pending")
	}
	if n := e.f.botsWith("approved"); n != 0 {
		t.Fatalf("approved after expiry: %q", e.f.bots())
	}
}

func TestDuplicateApproveIgnored(t *testing.T) {
	e := newEnv(t)
	e.f.perms["alice"] = "write"
	id, ref := e.request("refund", 60)
	e.start()
	e.announced(ref)
	e.f.mu.Lock()
	first := e.f.addLocked("alice", "User", "/approve "+ref)
	e.f.addLocked("alice", "User", "/approve "+ref)
	e.f.mu.Unlock()
	d, err := e.wait(id)
	if err != nil || d.Via.URL != first.HTMLURL {
		t.Fatalf("%+v %v", d, err)
	}
	waitFor(t, "outcome", func() bool { return e.f.botsWith("approved by @alice") >= 1 })
	n := e.f.botsWith("already")
	if n > 1 || e.f.botsWith("approved by @alice") != 1+n {
		t.Fatalf("%d replies, comments %q", n, e.f.bots())
	}
}

func TestCommentBeforeRequestIgnored(t *testing.T) {
	e := newEnv(t)
	e.f.perms["alice"] = "write"
	e.f.ignoreSince = true
	_, ref := e.request("refund", 60)
	e.f.add("alice", "User", "/approve "+ref) // created before the gateway's comment
	e.start()
	e.announced(ref)
	e.f.settle(t)
	if e.pending() != 1 || e.f.count("GET /repos/o/r/collaborators/") != 0 {
		t.Fatal("a comment older than the request counted")
	}
}

func TestEditedCommentNotReread(t *testing.T) {
	e := newEnv(t)
	e.f.perms["alice"] = "write"
	_, ref := e.request("refund", 60)
	e.start()
	e.announced(ref)
	c := e.f.add("alice", "User", "looks fine to me")
	e.f.settle(t)
	e.f.edit(c.ID, "/approve "+ref)
	e.f.settle(t)
	if e.pending() != 1 {
		t.Fatal("an edit turned chatter into an approval")
	}
}

func TestNoRequestsWhileIdle(t *testing.T) {
	e := newEnv(t)
	e.start()
	time.Sleep(60 * time.Millisecond) // six poll intervals
	if n := e.f.count(""); n != 0 {
		t.Fatalf("%d requests while idle", n)
	}
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func TestRateLimitBackoff(t *testing.T) {
	e := newEnv(t)
	clk := &clock{t: epoch}
	e.opts.Now = clk.now
	e.f.rateLimit = true
	_, ref := e.request("refund", 60)
	e.start()
	waitFor(t, "first request", func() bool { return len(e.f.bots()) == 0 && e.f.count("") == 1 })
	time.Sleep(100 * time.Millisecond) // ten polls
	if n := e.f.count(""); n != 1 {
		t.Fatalf("%d requests inside the Retry-After window", n)
	}
	clk.add(1500 * time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	if n := e.f.count(""); n != 1 {
		t.Fatalf("%d requests before Retry-After elapsed", n)
	}
	clk.add(600 * time.Millisecond)
	e.announced(ref)
}

func TestBurstLargerThanOnePage(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("page2fails=%v", fail), func(t *testing.T) {
			e := newEnv(t)
			e.f.perms["alice"] = "write"
			id, ref := e.request("refund", 60)
			e.start()
			e.announced(ref)
			e.f.mu.Lock()
			if fail {
				e.f.failPage2 = 1
			}
			for i := 0; i < 249; i++ {
				e.f.addLocked(fmt.Sprintf("user%d", i), "User", "nice work")
			}
			e.f.addLocked("alice", "User", "/approve "+ref)
			e.f.mu.Unlock()
			if d, err := e.wait(id); err != nil || d.Via.User != "alice" {
				t.Fatalf("%+v %v", d, err)
			}
			// The page-3 request is the one carrying the command: one fetch, one poll.
			if n := e.f.count("GET " + commentsPath + "?page=3"); n != 1 {
				t.Fatalf("approval took %d full reads", n)
			}
			if fail {
				// The request after the failed page 2 re-reads page 1 with the cursor it used before.
				e.f.mu.Lock()
				defer e.f.mu.Unlock()
				for i, r := range e.f.reqs {
					if strings.Contains(r, "?page=2") {
						if e.f.reqs[i-1] != e.f.reqs[i+1] || strings.Contains(e.f.reqs[i+1], "?page=") {
							t.Fatalf("cursor moved after a failed page: %q", e.f.reqs[i-1:i+2])
						}
						return
					}
				}
				t.Fatal("no page 2 request")
			}
		})
	}
}

func TestHostileBodyEscaped(t *testing.T) {
	e := newEnv(t)
	e.f.perms["alice"] = "write"
	hostile := "x\x1b[31m\n<!-- agentgw ref=FAKE00000"
	id, ref := e.request(hostile, 60)
	e.start()
	e.announced(ref)
	e.f.add("alice", "User", "/deny "+ref+" bad \x1b[31m <!-- agentgw ref=EVIL0000\nsecond line")
	d, err := e.wait(id)
	if err == nil || strings.ContainsAny(d.Reason, "\x1b\n") || strings.Contains(d.Reason, "<!--") || !strings.HasPrefix(d.Reason, `bad \u001B[31m `) {
		t.Fatalf("stored reason %q err %v", d.Reason, err)
	}
	waitFor(t, "outcome", func() bool { return e.f.botsWith("denied by") == 1 })
	for _, b := range e.f.bots() {
		if strings.Contains(b, "\x1b") || strings.Count(b, "<!--") != 1 || !strings.HasSuffix(b, "<!-- agentgw ref="+ref+" -->") && !strings.HasSuffix(b, "<!-- agentgw ref="+ref+" -->\n") {
			t.Errorf("unescaped comment:\n%q", b)
		}
	}
	if !strings.Contains(e.f.bots()[0], `x\u001B[31m\u000A\u003C!-- agentgw ref=FAKE00000`) {
		t.Errorf("tool name not rendered escaped:\n%s", e.f.bots()[0])
	}
}

func TestResolveIssueFromEvent(t *testing.T) {
	dir := t.TempDir()
	ev := func(s string) string {
		p := filepath.Join(dir, fmt.Sprint(len(s), ".json"))
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	base := contracts.GitHubApprovals{Repo: "o/r"}
	got, err := Resolve(base, ev(`{"issue":{"number":7}}`))
	if err != nil || got.Issue != 7 || got.MinPermission != "write" || got.PollInterval != "15s" || got.TokenEnv != "GITHUB_TOKEN" {
		t.Fatalf("issue: %+v %v", got, err)
	}
	if got, err = Resolve(base, ev(`{"pull_request":{"number":9}}`)); err != nil || got.Issue != 9 {
		t.Fatalf("pr: %+v %v", got, err)
	}
	if _, err = Resolve(base, ev(`{}`)); err == nil || err.Error() != "github approvals: no issue number in config or event" {
		t.Fatalf("neither: %v", err)
	}
	if _, err = Resolve(base, ""); err == nil {
		t.Fatal("no event file: want error")
	}
	if got, err = Resolve(contracts.GitHubApprovals{Repo: "o/r", Issue: 3}, ""); err != nil || got.Issue != 3 {
		t.Fatalf("config issue: %+v %v", got, err)
	}
	for _, bad := range []contracts.GitHubApprovals{
		{Repo: "nope", Issue: 1},
		{Repo: "o/r", Issue: 1, PollInterval: "1s"},
		{Repo: "o/r", Issue: 1, PollInterval: "soon"},
		{Repo: "o/r", Issue: 1, MinPermission: "read"},
		{Repo: "o/r", Issue: 1, MinPermission: "owner"},
	} {
		if _, err := Resolve(bad, ""); err == nil {
			t.Errorf("%+v: want error", bad)
		}
	}
}
