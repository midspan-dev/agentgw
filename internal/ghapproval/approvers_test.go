package ghapproval

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/midspan-dev/agentgw/pkg/contracts"
)

// requestNamed holds a call whose rule names approvers.
func (e *env) requestNamed(tool string, approvers ...string) (id, ref string) {
	e.t.Helper()
	id, err := e.store.Request(context.Background(), contracts.ApprovalRequest{
		CallID: "c-" + tool, Principal: contracts.Principal{AgentID: "agent-1"}, Server: "srv", Tool: tool,
		ArgsHash: "hash-" + tool, Args: json.RawMessage(`{"amount": 50}`), RuleID: "rule-1",
		Spec: contracts.ApprovalSpec{TimeoutSeconds: 60, Approvers: approvers},
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return id, strings.ToUpper(id[len(id)-8:])
}

func TestUnnamedApproverRefused(t *testing.T) {
	e := newEnv(t)
	e.f.perms["bob"], e.f.perms["ALICE"] = "write", "write"
	var logs []string
	var mu sync.Mutex
	e.opts.Logf = func(f string, a ...any) { mu.Lock(); logs = append(logs, fmt.Sprintf(f, a...)); mu.Unlock() }
	count := func(sub string) int {
		mu.Lock()
		defer mu.Unlock()
		return strings.Count(strings.Join(logs, "\n"), sub)
	}
	id, ref := e.requestNamed("refund", "alice", "carol@example.com")
	e.start()
	e.announced(ref)
	e.f.add("bob", "User", "/approve "+ref)
	e.f.add("bob", "User", "/approve "+ref)
	waitFor(t, "both ignored", func() bool {
		return count("github approvals: ignoring approve from bob: not a named approver") == 2
	})
	e.f.settle(t)
	if e.pending() != 1 || e.f.botsWith("only `alice`, `carol@example.com` may approve `"+ref+"`") != 1 || e.f.botsWith("may approve") != 1 {
		t.Fatalf("pending %d, comments %q", e.pending(), e.f.bots())
	}
	// A listed login in different case approves.
	e.f.add("ALICE", "User", "/approve "+ref)
	d, err := e.wait(id)
	if err != nil || d.Decision != contracts.DecisionApproved || d.Via == nil || d.Via.User != "ALICE" {
		t.Fatalf("%+v %v", d, err)
	}
}

func TestNamedApproverBelowMinRole(t *testing.T) {
	e := newEnv(t)
	e.f.perms["alice"] = "read"
	_, ref := e.requestNamed("refund", "alice")
	e.start()
	e.announced(ref)
	e.f.add("alice", "User", "/approve "+ref)
	waitFor(t, "role checked", func() bool { return e.f.count("GET /repos/o/r/collaborators/alice") >= 1 })
	e.f.settle(t)
	if e.pending() != 1 || e.f.botsWith("may approve") != 0 {
		t.Fatalf("pending %d, comments %q", e.pending(), e.f.bots())
	}
}

func TestEmailOnlyApproversCannotComment(t *testing.T) {
	e := newEnv(t)
	e.f.perms["alice"] = "admin"
	_, ref := e.requestNamed("refund", "alice@example.com")
	e.start()
	e.announced(ref)
	e.f.add("alice", "User", "/approve "+ref)
	waitFor(t, "reply", func() bool { return e.f.botsWith("may approve") == 1 })
	if e.pending() != 1 || e.f.botsWith("cannot be approved by comment") != 1 {
		t.Fatalf("pending %d, comments %q", e.pending(), e.f.bots())
	}
	req := e.f.bots()[0] // the request comment itself
	if !strings.Contains(req, "- Approvers: `alice@example.com`") || strings.Contains(req, "@alice@example.com") {
		t.Fatalf("request comment: %q", req)
	}
}

func TestNamedDeny(t *testing.T) {
	e := newEnv(t)
	e.f.perms["alice"], e.f.perms["bob"] = "write", "write"
	id, ref := e.requestNamed("refund", "alice")
	e.start()
	e.announced(ref)
	if e.f.botsWith("- Approvers: @alice\n") != 1 {
		t.Fatalf("request comment: %q", e.f.bots())
	}
	e.f.add("bob", "User", "/deny "+ref+" no")
	waitFor(t, "reply", func() bool { return e.f.botsWith("only `alice` may approve") == 1 })
	if e.pending() != 1 {
		t.Fatal("unlisted deny resolved")
	}
	e.f.add("alice", "User", "/deny "+ref+" no")
	if d, err := e.wait(id); err == nil || d.Decision != contracts.DecisionDenied || d.Via.User != "alice" {
		t.Fatalf("%+v %v", d, err)
	}
}
