package watch

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
	"unicode/utf8"

	"github.com/midspan-dev/agentgw/internal/approval"
	"github.com/midspan-dev/agentgw/pkg/contracts"
)

func TestEscape(t *testing.T) {
	bad := []string{"\x1b", "\x1b[31m", "\x1b]0;x\x07", "\r", "\n", "\t", "\x7f", "\u0085", "\u009b",
		"\u202e", "\u2066", "\u200d", "\u2028", "\ufeff", "\xff", "\U000E0041"}
	for _, s := range bad {
		got := Escape("a" + s + "b")
		for _, r := range got {
			if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x202e || r == 0x2066 || r == 0x200d || r == 0x2028 || r == 0xfeff || r == 0xE0041 {
				t.Errorf("%q survived as %q", s, got)
			}
		}
		if !strings.HasPrefix(got, "a") || !strings.HasSuffix(got, "b") || got == "a"+s+"b" {
			t.Errorf("%q -> %q", s, got)
		}
	}
	if got := Escape("\xff\u202e\U000E0041"); got != `\xFF\u202E\U000E0041` {
		t.Errorf("got %s", got)
	}
	for _, s := range []string{"abc XYZ 09", "é", "日本", "😀"} {
		if Escape(s) != s {
			t.Errorf("%q changed to %q", s, Escape(s))
		}
	}
	long := strings.Repeat("x", 3000)
	if c := cut(long); len(c) > 2200 || !strings.Contains(c, "(3000 bytes, sha256 ") {
		t.Errorf("cut: %q", c[len(c)-80:])
	}
}

// hostile is a string with every kind of terminal-active content.
const hostile = "A\x1b[31m\x1b]0;pwned\x07\r\n\t\u0085\u009b\u202e\u2066\u200d\u2028\ufeff\xffZ"

type sink struct{ bytes.Buffer }

func newW(t *testing.T) (*watcher, *sink, *contracts.Config) {
	t.Helper()
	dir := t.TempDir()
	cfg := &contracts.Config{
		PolicyPath: filepath.Join(dir, "policy.yaml"), KeyPath: filepath.Join(dir, "ledger.key"),
		StatePath: filepath.Join(dir, "agentgw.db"),
		Ledger:    contracts.LedgerConfig{Path: filepath.Join(dir, "ledger.jsonl")},
	}
	cfg.Approvals.CLI.TokenPath = filepath.Join(dir, "approver.key")
	if err := approval.GenerateToken(cfg.Approvals.CLI.TokenPath); err != nil {
		t.Fatal(err)
	}
	out := &sink{}
	w := &watcher{o: Options{Config: cfg}, out: out, now: func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.Local) }}
	return w, out, cfg
}

func noControls(t *testing.T, name, s string) {
	t.Helper()
	if !utf8.ValidString(s) {
		t.Errorf("%s: invalid utf8", name)
	}
	for _, r := range s {
		if (r < 0x20 && r != '\n') || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x202e || r == 0x2066 || r == 0x200d || r == 0x2028 || r == 0xfeff {
			t.Errorf("%s: control rune %U in %q", name, r, s)
		}
	}
	if strings.Contains(s, "\x1b") {
		t.Errorf("%s: ESC in output", name)
	}
}

func TestRenderEscapesEveryField(t *testing.T) {
	fields := []string{"server", "tool", "rule", "version", "agent", "owner", "runid", "id", "hash", "args", "error", "reason", "approver", "outcome", "currency"}
	for _, f := range fields {
		t.Run(f, func(t *testing.T) {
			w, out, _ := newW(t)
			h := func(name string) string {
				if name == f {
					return hostile
				}
				return "ok"
			}
			e := &contracts.Entry{
				Action:   contracts.EntryAction{Server: h("server"), Tool: h("tool")},
				Decision: contracts.EntryDecision{Outcome: contracts.OutcomeRequireApproval, RuleID: h("rule"), PolicyVersion: h("version"), GrantID: "g", Approval: &contracts.ApprovalDecision{Decision: contracts.DecisionDenied, ApproverID: h("approver"), Reason: h("reason")}},
				Outcome:  contracts.EntryError,
				Result:   contracts.EntryResult{Error: h("error")},
				Cost:     contracts.EntryCost{Actual: contracts.Money{Micros: 5, Currency: h("currency")}},
			}
			if f == "outcome" {
				e.Outcome = contracts.EntryOutcome(hostile)
			}
			w.renderEntry(e, true)
			w.lastVer = "" // render again with hostile as the previous version too
			w.renderEntry(e, true)
			args, _ := json.Marshal(map[string]string{"k" + h("args"): h("args")})
			w.showCard(&card{n: 1, p: contracts.PendingApproval{ID: h("id"), ExpiresAt: time.Now(), Request: contracts.ApprovalRequest{
				Principal: contracts.Principal{AgentID: h("agent"), Owner: h("owner"), RunID: h("runid")},
				Server:    h("server"), Tool: h("tool"), ArgsHash: h("hash"), Args: args, RuleID: h("rule"),
				EstimatedCost: contracts.Money{Micros: 1, Currency: h("currency")},
			}}})
			w.canAct = true
			w.showCard(&card{n: 2, p: contracts.PendingApproval{ID: h("id"), Request: contracts.ApprovalRequest{Args: json.RawMessage(hostile)}}})
			noControls(t, f, out.String())
		})
	}
}

func TestTail(t *testing.T) {
	w, out, cfg := newW(t)
	path := cfg.Ledger.Path
	e := contracts.Entry{Type: "entry", Action: contracts.EntryAction{Server: "s", Tool: "t"}, Outcome: "ok",
		Decision: contracts.EntryDecision{Outcome: "allow", RuleID: "r", PolicyVersion: "aaaaaaaa11"}}
	line, _ := json.Marshal(e)
	os.WriteFile(path, append(line, '\n'), 0o600)
	ents, _ := w.pollLedger()
	if len(ents) != 1 || w.entries != 1 {
		t.Fatalf("got %d entries", len(ents))
	}
	// partial last line: waits.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.Write(line[:10])
	if ents, _ := w.pollLedger(); len(ents) != 0 || out.Len() != 0 {
		t.Fatalf("partial line produced %d entries, output %q", len(ents), out)
	}
	f.Write(append(line[10:], '\n'))
	if ents, _ := w.pollLedger(); len(ents) != 1 {
		t.Fatal("completed line not read")
	}
	// unparseable line: one status line.
	f.WriteString("not json\n")
	f.Close()
	w.pollLedger()
	w.pollLedger()
	if s := out.String(); strings.Count(s, "line 3: unparseable") != 1 {
		t.Fatalf("output %q", s)
	}
	// truncation.
	os.WriteFile(path, append(line, '\n'), 0o600)
	ents, replaced := w.pollLedger()
	if !replaced || len(ents) != 1 || !strings.Contains(out.String(), "file replaced; re-reading") {
		t.Fatalf("replaced=%v ents=%d out=%q", replaced, len(ents), out)
	}
}

func TestVersionChange(t *testing.T) {
	w, out, _ := newW(t)
	for _, v := range []string{"aaaaaaaa11", "cccccccc22", "bbbbbbbb33"} {
		w.renderEntry(&contracts.Entry{Decision: contracts.EntryDecision{Outcome: "allow", PolicyVersion: v}}, true)
	}
	if n := strings.Count(out.String(), "policy version changed cccccccc -> bbbbbbbb"); n != 1 || strings.Count(out.String(), "policy version changed") != 2 {
		t.Fatalf("output %q", out)
	}
}

func TestPolicyStatus(t *testing.T) {
	w, out, cfg := newW(t)
	good := "version: \"1\"\ncurrency: USD\nrules:\n  - id: allow-all\n    effect: allow\n    tools: [\"*\"]\n"
	os.WriteFile(cfg.PolicyPath, []byte(good), 0o600)
	w.pollPolicy(true)
	if !strings.Contains(out.String(), "compiles, version ") {
		t.Fatalf("startup: %q", out)
	}
	os.WriteFile(cfg.PolicyPath, []byte("rules: ["), 0o600)
	w.pollPolicy(false)
	if !strings.Contains(out.String(), "policy.yaml changed: INVALID, gateway keeps the last valid policy: ") {
		t.Fatalf("invalid: %q", out)
	}
	out.Reset()
	w.pollPolicy(false)
	if out.Len() != 0 {
		t.Fatalf("unchanged file printed %q", out)
	}
	os.WriteFile(cfg.PolicyPath, []byte(good+"\n"), 0o600)
	w.pollPolicy(false)
	if !strings.Contains(out.String(), "policy.yaml changed: compiles, version ") {
		t.Fatalf("valid: %q", out)
	}
	os.Remove(cfg.PolicyPath)
	w.pollPolicy(false)
	if !strings.Contains(out.String(), "missing; the gateway keeps the policy it started with") {
		t.Fatalf("missing: %q", out)
	}
}

func req(tool string) contracts.ApprovalRequest {
	return contracts.ApprovalRequest{CallID: "c", Server: "s", Tool: tool, ArgsHash: strings.Repeat("ab", 32),
		Args: json.RawMessage(`{"x":1}`), RuleID: "r", Spec: contracts.ApprovalSpec{TimeoutSeconds: 60}}
}

func TestAnswers(t *testing.T) {
	w, out, cfg := newW(t)
	ctx := context.Background()
	w.openStore()
	defer w.store.Close()
	if !w.canAct {
		t.Fatal(out.String())
	}
	id1, _ := w.store.Request(ctx, req("one"))
	id2, _ := w.store.Request(ctx, req("two"))
	w.pollApprovals(ctx)
	if !strings.Contains(out.String(), "── approval 1 ") || !strings.Contains(out.String(), "── approval 2 ") {
		t.Fatalf("cards: %q", out)
	}
	w.answer(ctx, "a")
	if !strings.Contains(out.String(), "2 approvals pending; say a 1 or a 2") {
		t.Fatalf("bare answer: %q", out)
	}
	w.answer(ctx, "a 2")
	d, err := w.store.Wait(ctx, id2, func(string) {})
	if err != nil || d.Decision != "approved" || d.ArgsHash != req("").ArgsHash {
		t.Fatalf("a 2: %+v %v", d, err)
	}
	w.answer(ctx, "d 1 because")
	d, err = w.store.Wait(ctx, id1, func(string) {})
	if d == nil || d.Decision != "denied" || d.Reason != "because" || err == nil {
		t.Fatalf("d 1: %+v %v", d, err)
	}
	if !strings.Contains(out.String(), id2+" by you") || !strings.Contains(out.String(), id1+" by you") {
		t.Fatalf("outcome lines: %q", out)
	}
	// ErrNotPending: another process decides first; no retry, card dropped.
	id3, _ := w.store.Request(ctx, req("three"))
	w.pollApprovals(ctx)
	if !strings.Contains(out.String(), "── approval 3 ") {
		t.Fatalf("numbers reused after the list emptied: %q", out)
	}
	other, _ := approval.Open(cfg.StatePath, cfg.Approvals.CLI.TokenPath)
	defer other.Close()
	if err := other.Approve(ctx, id3, req("").ArgsHash, "", time.Time{}); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	w.answer(ctx, "a")
	if !strings.Contains(out.String(), id3+" not pending (expired or already decided)") || len(w.cards) != 0 {
		t.Fatalf("not pending: %q cards=%d", out, len(w.cards))
	}
	w.answer(ctx, "a")
	if !strings.Contains(out.String(), "nothing pending") {
		t.Fatalf("retry: %q", out)
	}
}

func TestExpiredAndReadOnly(t *testing.T) {
	w, out, cfg := newW(t)
	w.o.NoInput = true
	ctx := context.Background()
	w.openStore()
	defer w.store.Close()
	if w.canAct || !strings.Contains(out.String(), "unavailable (--no-input); showing approvals only") {
		t.Fatalf("status: %q", out)
	}
	other, _ := approval.Open(cfg.StatePath, cfg.Approvals.CLI.TokenPath)
	defer other.Close()
	r := req("one")
	r.Spec.TimeoutSeconds = 1
	id, _ := other.Request(ctx, r)
	w.pollApprovals(ctx)
	if !strings.Contains(out.String(), "decide with: agentgw approvals approve "+id+" "+r.ArgsHash) {
		t.Fatalf("card: %q", out)
	}
	// The read-only store holds a throwaway key; an answer must not decide.
	w.answer(ctx, "a")
	if !strings.Contains(out.String(), "approver unavailable") {
		t.Fatalf("read-only answer: %q", out)
	}
	if list, _ := other.List(ctx); len(list) != 1 || list[0].ID != id {
		t.Fatalf("read-only answer decided: %+v", list)
	}
	time.Sleep(1100 * time.Millisecond)
	w.pollApprovals(ctx)
	if strings.Count(out.String(), "expired  "+id) != 1 {
		t.Fatalf("expired: %q", out)
	}
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// An input line over 64 KiB is reported and dropped; the approver keeps
// reading, so the next answer still decides.
func TestHugeInputLineKeepsApprover(t *testing.T) {
	_, _, cfg := newW(t)
	pr, pw := io.Pipe()
	out := &lockedBuf{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, Options{Config: cfg, Poll: 10 * time.Millisecond}, pr, out) }()
	defer func() { cancel(); pw.Close(); <-done }()
	wait := func(what string) {
		t.Helper()
		for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
			if strings.Contains(out.String(), what) {
				return
			}
		}
		t.Fatalf("no %q in:\n%s", what, out.String())
	}
	wait("approver ready")
	io.WriteString(pw, strings.Repeat("x", 70000)+"\n")
	wait("input line over 64 KiB ignored; answer again")
	store, err := approval.Open(cfg.StatePath, cfg.Approvals.CLI.TokenPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	id, err := store.Request(ctx, req("one"))
	if err != nil {
		t.Fatal(err)
	}
	wait("── approval 1 ")
	io.WriteString(pw, "a\n")
	wait(id + " by you")
}

// col is the rune column of sub in s; "…" is one column but three bytes.
func col(s, sub string) int { return utf8.RuneCountInString(s[:strings.Index(s, sub)]) }

// Every outcome fits its column, so rule and version line up under the
// header; long tool names are cut by rune, long rule ids are kept whole.
func TestRowColumns(t *testing.T) {
	head := row("time", "decision", "tool", "outcome", "rule", "version")
	at := strings.Index(head, "rule")
	for _, outcome := range []string{"ok", "approval_timeout", "budget_exceeded"} {
		if got := strings.Index(row("14:02:11", "hold", "s.t", outcome, "r", "v 1"), " r "); got+1 != at {
			t.Errorf("%s: rule at %d, header at %d", outcome, got+1, at)
		}
	}
	long := row("14:02:11", "allow", "github.create_pull_request_review_comment", "ok", "r", "v 1")
	if !strings.Contains(long, "github.create_pull_request_r…") || col(long, " ok ") != col(head, " outcome ") {
		t.Errorf("long tool not cut to its column: %q", long)
	}
	if got := fit("日本語のツール名がとても長い", 5); got != "日本語の…" {
		t.Errorf("cut by bytes, not runes: %q", got)
	}
	if r := row("t", "deny", "s.t", "denied", "a-very-long-rule-id-that-explains-it", "v 1"); !strings.Contains(r, "a-very-long-rule-id-that-explains-it v 1") {
		t.Errorf("rule id cut: %q", r)
	}
}
