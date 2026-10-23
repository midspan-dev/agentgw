// Package watch implements `agentgw watch`: a line-mode monitor that tails the
// ledger, shows pending approvals as cards and records the human's answers.
// Every untrusted value goes through esc before formatting, and every line
// leaves through emit, which escapes once more (docs/adr/0010 decision 5).
package watch

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/midspan-dev/agentgw/internal/approval"
	"github.com/midspan-dev/agentgw/internal/ledger"
	"github.com/midspan-dev/agentgw/internal/policy"
	"github.com/midspan-dev/agentgw/pkg/contracts"
)

const (
	colRed   = "\x1b[31m"
	colReset = "\x1b[0m"

	verifyEvery = 5 * time.Second
	rule        = "──────────────────────────────────────────────────────────────────────"
)

// Options configures Run. Config paths are already resolved.
type Options struct {
	Config     *contracts.Config
	ConfigPath string
	NoInput    bool
	NoColor    bool
	Since      int // entries shown on start; 0 none, -1 all
	IsTTY      bool
	Poll       time.Duration // default 500 ms
	Now        func() time.Time
}

type card struct {
	n int
	p contracts.PendingApproval
}

type watcher struct {
	o   Options
	out io.Writer
	now func() time.Time

	// ledger tail
	off             int64
	buf             []byte
	line            int
	entries, cps    int
	seen, announced bool
	dirty           bool
	lastVerify      time.Time
	lastVer         string
	// policy
	polSig  string
	polInit bool
	// approvals
	store    *approval.Store
	canAct   bool
	cards    []*card
	nCards   int
	listBusy bool
}

// maxAnswer bounds one input line; tooLong stands for a longer one (it
// contains a newline, so no real line can equal it).
const (
	maxAnswer = 64 << 10
	tooLong   = "\n"
)

// Run prints the status block and then watches until ctx ends.
func Run(ctx context.Context, o Options, in io.Reader, out io.Writer) error {
	w := &watcher{o: o, out: out, now: o.Now}
	if w.now == nil {
		w.now = time.Now
	}
	poll := o.Poll
	if poll <= 0 {
		poll = 500 * time.Millisecond
	}
	cfg := o.Config
	w.emit("", "agentgw watch  config "+esc(o.ConfigPath))

	initial, _ := w.pollLedger()
	if w.seen {
		w.verify(true)
	} else {
		w.status("ledger", fmt.Sprintf("%s  not created yet; it appears on the first tool call (is the server registered? claude mcp get %s)", esc(cfg.Ledger.Path), esc(firstUpstream(cfg))), "")
		w.announced = true
	}
	w.pollPolicy(true)
	w.openStore()
	defer func() {
		if w.store != nil {
			w.store.Close()
		}
	}()
	w.emit("", "\n"+row("time", "decision", "tool", "outcome", "rule", "version"))
	emitFrom := 0
	if o.Since >= 0 && len(initial) > o.Since {
		emitFrom = len(initial) - o.Since
	}
	for i := range initial {
		w.renderEntry(&initial[i], i >= emitFrom)
	}

	answers := make(chan string)
	if w.canAct && in != nil {
		go func() {
			defer close(answers)
			rd := bufio.NewReaderSize(in, maxAnswer)
			for {
				line, err := rd.ReadSlice('\n')
				a := strings.TrimRight(string(line), "\r\n")
				if err == bufio.ErrBufferFull {
					// Drop the rest of an over-long line and keep reading, so
					// one paste cannot silently end the approver.
					for err == bufio.ErrBufferFull {
						_, err = rd.ReadSlice('\n')
					}
					a = tooLong
				}
				if a != "" || err == nil {
					select {
					case answers <- a:
					case <-ctx.Done():
						return
					}
				}
				if err != nil {
					return
				}
			}
		}()
	}
	tick := time.NewTicker(poll)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case a, ok := <-answers:
			if !ok {
				answers = nil
				continue
			}
			if a == tooLong {
				w.emit("", fmt.Sprintf("input line over %d KiB ignored; answer again", maxAnswer>>10))
				continue
			}
			w.answer(ctx, a)
		case <-tick.C:
			w.pollApprovals(ctx)
			ents, replaced := w.pollLedger()
			for i := range ents {
				w.renderEntry(&ents[i], true)
			}
			w.pollPolicy(false)
			if w.dirty && (replaced || w.now().Sub(w.lastVerify) >= verifyEvery) {
				w.verify(false)
			}
		}
	}
}

func firstUpstream(c *contracts.Config) string {
	if len(c.Upstreams) > 0 {
		return c.Upstreams[0].Name
	}
	return "<name>"
}

// emit is the single output path. Each line is escaped again here, so a value
// that skipped esc still cannot reach the terminal as a control sequence.
func (w *watcher) emit(colour, text string) {
	var b bytes.Buffer
	for _, l := range strings.Split(text, "\n") {
		if colour != "" && w.o.IsTTY && !w.o.NoColor {
			b.WriteString(colour + Escape(l) + colReset + "\n")
		} else {
			b.WriteString(Escape(l) + "\n")
		}
	}
	w.out.Write(b.Bytes())
}

func (w *watcher) status(name, text, colour string) {
	w.emit(colour, fmt.Sprintf("%-8s %s", name, text))
}

// row lays out a call line, or the header, in fixed-width columns. Values
// must already be escaped. Long tool names are cut (the card shows them in
// full); rule ids are never cut, since they explain the decision, so a long
// one only pushes the version right.
// shortcut: widths count runes, so wide (CJK) characters still shift a line; measure display width if that shows up.
func row(time, decision, tool, outcome, rule, version string) string {
	return fmt.Sprintf("%-8s  %s %s %s %s %s", time, fit(decision, 8), fit(tool, 29), fit(outcome, 16), fmt.Sprintf("%-22s", rule), version)
}

func fit(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return fmt.Sprintf("%-*s", n, s)
}

// event prints a timestamped line.
func (w *watcher) event(name, text, colour string) {
	w.emit(colour, fmt.Sprintf("%s  %-8s %s", w.now().Format("15:04:05"), name, text))
}

// ---- ledger ----

// pollLedger reads new complete lines and returns the entries among them.
func (w *watcher) pollLedger() (entries []contracts.Entry, replaced bool) {
	path := w.o.Config.Ledger.Path
	st, err := os.Stat(path)
	if err != nil {
		if w.seen {
			w.reset()
			w.event("ledger", "file replaced; re-reading", "")
			replaced = true
		}
		return nil, replaced
	}
	if st.Size() < w.off {
		w.reset()
		w.event("ledger", "file replaced; re-reading", "")
		replaced = true
	}
	w.seen = true
	if st.Size() == w.off {
		return nil, replaced
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, replaced
	}
	defer f.Close()
	f.Seek(w.off, io.SeekStart)
	data, _ := io.ReadAll(f)
	w.off += int64(len(data))
	w.buf = append(w.buf, data...)
	bad := func(why string) {
		w.event("ledger", fmt.Sprintf("line %d: unparseable (%s)", w.line, esc(why)), "")
	}
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		l := w.buf[:i]
		w.buf = w.buf[i+1:]
		w.line++
		w.dirty = true
		var head struct{ Type string }
		if err := json.Unmarshal(l, &head); err != nil {
			bad(err.Error())
			continue
		}
		switch head.Type {
		case contracts.LineTypeEntry:
			var e contracts.Entry
			if err := json.Unmarshal(l, &e); err != nil {
				bad(err.Error())
				continue
			}
			w.entries++
			entries = append(entries, e)
		case contracts.LineTypeCheckpoint:
			var c contracts.Checkpoint
			if err := json.Unmarshal(l, &c); err != nil {
				bad(err.Error())
				continue
			}
			w.cps++
		default:
			bad("unknown type " + head.Type)
		}
	}
	return entries, replaced
}

func (w *watcher) reset() {
	w.off, w.buf, w.line, w.entries, w.cps = 0, nil, 0, 0, 0
	w.seen, w.dirty = false, true
}

// verify checks the complete lines read so far (never a half-written tail).
func (w *watcher) verify(startup bool) {
	w.lastVerify, w.dirty = w.now(), false
	path := w.o.Config.Ledger.Path
	res, colour := "", ""
	key, err := ledger.LoadKey(w.o.Config.KeyPath)
	f, ferr := os.Open(path)
	switch {
	case err != nil:
		res = "cannot verify: " + esc(err.Error())
	case ferr != nil:
		res = "cannot verify: " + esc(ferr.Error())
	default:
		rep := ledger.Verify(io.NewSectionReader(f, 0, w.off-int64(len(w.buf))), key.Public().(ed25519.PublicKey))
		if rep.OK {
			res = "verified ok"
		} else {
			res, colour = fmt.Sprintf("VERIFY FAILED at line %d: %s", rep.Line, esc(rep.Reason)), colRed
		}
	}
	if f != nil {
		f.Close()
	}
	if startup {
		w.status("ledger", fmt.Sprintf("%s  %d entries, %d checkpoints, %s", esc(path), w.entries, w.cps, res), colour)
	} else {
		w.event("ledger", fmt.Sprintf("%d entries, %s", w.entries, res), colour)
	}
}

func short(s string) string {
	if len(s) > 8 {
		s = s[:8]
	}
	return s
}

func (w *watcher) renderEntry(e *contracts.Entry, show bool) {
	ver := e.Decision.PolicyVersion
	if show && w.lastVer != "" && ver != "" && ver != w.lastVer {
		w.event("policy", fmt.Sprintf("policy version changed %s -> %s", esc(short(w.lastVer)), esc(short(ver))), "")
	}
	if ver != "" {
		w.lastVer = ver
	}
	if !show {
		return
	}
	dec := string(e.Decision.Outcome)
	if e.Decision.Outcome == contracts.OutcomeRequireApproval {
		dec = "hold"
	}
	var extra []string
	if a := e.Decision.Approval; a != nil {
		if a.Decision == contracts.DecisionApproved {
			extra = append(extra, "approved")
		} else {
			s := "denied by " + esc(short(a.ApproverID))
			if a.Reason != "" {
				s += ": " + esc(a.Reason)
			}
			extra = append(extra, s)
		}
	}
	if e.Decision.GrantID != "" {
		extra = append(extra, "grant")
	}
	if m := e.Cost.Actual; m.Micros != 0 {
		extra = append(extra, money(m))
	}
	if e.Outcome == contracts.EntryError && e.Result.Error != "" {
		r := e.Result.Error
		if len(r) > 60 {
			r = r[:60]
		}
		extra = append(extra, esc(r))
	}
	w.emit("", strings.TrimRight(row(w.now().Format("15:04:05"), esc(dec), esc(e.Action.Server+"."+e.Action.Tool),
		esc(string(e.Outcome)), esc(e.Decision.RuleID), "v "+esc(short(ver))+"  "+strings.Join(extra, " ")), " "))
}

func money(m contracts.Money) string {
	return strconv.FormatFloat(float64(m.Micros)/contracts.MicrosPerUnit, 'f', -1, 64) + " " + esc(m.Currency)
}

// ---- policy ----

func (w *watcher) pollPolicy(startup bool) {
	path := w.o.Config.PolicyPath
	st, err := os.Stat(path)
	sig := "missing"
	if err == nil {
		sig = fmt.Sprintf("%d/%d", st.ModTime().UnixNano(), st.Size())
	}
	if w.polInit && sig == w.polSig {
		return
	}
	w.polInit, w.polSig = true, sig
	res, colour := "", ""
	if err != nil {
		res = esc(path) + " missing; the gateway keeps the policy it started with"
	} else {
		src, rerr := os.ReadFile(path)
		var p *policy.Policy
		if rerr == nil {
			if filepath.Ext(path) == ".cedar" {
				p, rerr = policy.LoadCedar(src)
			} else {
				p, rerr = policy.Compile(src)
			}
		}
		if rerr != nil {
			res, colour = "INVALID, gateway keeps the last valid policy: "+esc(strings.ReplaceAll(rerr.Error(), "\n", " ")), colRed
		} else {
			res = "compiles, version " + esc(short(p.Version()))
		}
	}
	switch {
	case startup && err != nil:
		w.status("policy", res, colour)
	case startup:
		w.status("policy", fmt.Sprintf("%s   %s", esc(path), res), colour)
	case err != nil:
		w.event("policy", res, colour)
	case colour == "":
		w.event("policy", fmt.Sprintf("%s changed: %s (gateway applies it on the next call)", esc(filepath.Base(path)), res), "")
	default:
		w.event("policy", fmt.Sprintf("%s changed: %s", esc(filepath.Base(path)), res), colour)
	}
}

// ---- approvals ----

// openStore opens the approval store and prints the approver status line.
// The store only takes a token path, so when the real token is not wanted
// (--no-input) or unusable, a throwaway key opens it for List and is deleted
// at once; it never decides anything (contract gap: no read-only Open).
func (w *watcher) openStore() {
	cfg := w.o.Config
	reason := "--no-input"
	if !w.o.NoInput {
		s, err := approval.Open(cfg.StatePath, cfg.Approvals.CLI.TokenPath)
		if err == nil {
			w.store, w.canAct = s, true
			w.status("approver", fmt.Sprintf("ready (%s)             press a/d when a call is held; Ctrl-C to quit", esc(filepath.Base(cfg.Approvals.CLI.TokenPath))), "")
			return
		}
		reason = err.Error()
	}
	dir, err := os.MkdirTemp("", "agentgw-watch")
	if err == nil {
		defer os.RemoveAll(dir)
		tok := filepath.Join(dir, "k")
		if err = approval.GenerateToken(tok); err == nil {
			w.store, err = approval.Open(cfg.StatePath, tok)
		}
	}
	if err != nil {
		reason += "; cannot open approvals: " + err.Error()
	}
	w.status("approver", fmt.Sprintf("unavailable (%s); showing approvals only", esc(reason)), "")
}

func (w *watcher) pollApprovals(ctx context.Context) {
	if w.store == nil {
		return
	}
	list, err := w.store.List(ctx)
	if err != nil {
		if !w.listBusy && ctx.Err() == nil {
			w.status("approvals", "database busy; retrying", "")
			w.listBusy = true
		}
		return
	}
	w.listBusy = false
	live := map[string]bool{}
	for _, p := range list {
		live[p.ID] = true
		if w.find(p.ID) == nil {
			w.nCards++ // never reused in a session: `a 1` cannot reach a later call
			c := &card{n: w.nCards, p: p}
			w.cards = append(w.cards, c)
			w.showCard(c)
		}
	}
	for _, c := range append([]*card(nil), w.cards...) {
		if !live[c.p.ID] {
			w.drop(c)
			w.event("expired", esc(c.p.ID), "")
		}
	}
}

func (w *watcher) find(id string) *card {
	for _, c := range w.cards {
		if c.p.ID == id {
			return c
		}
	}
	return nil
}

func (w *watcher) drop(c *card) {
	for i, x := range w.cards {
		if x == c {
			w.cards = append(w.cards[:i], w.cards[i+1:]...)
			return
		}
	}
}

func (w *watcher) showCard(c *card) {
	r := c.p.Request
	tool := esc(r.Server + "." + r.Tool)
	w.emit("", strings.TrimRight(row(w.now().Format("15:04:05"), "hold", tool, "pending", esc(r.RuleID), ""), " "))
	cost := "0 " + esc(r.EstimatedCost.Currency) + " (unpriced)"
	if r.EstimatedCost.Micros != 0 {
		cost = money(r.EstimatedCost)
	}
	run := r.Principal.RunID
	if len(run) > 7 {
		run = run[:7] + "…"
	}
	secs := r.Spec.TimeoutSeconds
	dur := fmt.Sprintf("%ds", secs)
	if secs > 0 && secs%60 == 0 {
		dur = fmt.Sprintf("%dm", secs/60)
	}
	head := fmt.Sprintf("── approval %d ", c.n)
	var b strings.Builder
	fmt.Fprintf(&b, "\n%s%s\n", head, strings.Repeat("─", 70-len([]rune(head))))
	fmt.Fprintf(&b, "id         %s\n", esc(c.p.ID))
	fmt.Fprintf(&b, "agent      %s   owner %s   run %s\n", esc(r.Principal.AgentID), esc(r.Principal.Owner), esc(run))
	fmt.Fprintf(&b, "tool       %s\n", tool)
	fmt.Fprintf(&b, "rule       %s   expires %s (%s)\n", esc(r.RuleID), c.p.ExpiresAt.Local().Format("15:04:05"), dur)
	fmt.Fprintf(&b, "cost       %s\n", cost)
	fmt.Fprintf(&b, "args hash  %s\n", esc(r.ArgsHash))
	fmt.Fprintf(&b, "args       %s\n", prettyArgs(r.Args))
	if w.canAct {
		b.WriteString("answer     a = approve once, d = deny, a 1 / d 1 when several are pending\n")
	} else {
		fmt.Fprintf(&b, "decide with: agentgw approvals approve %s %s\n", esc(c.p.ID), esc(r.ArgsHash))
	}
	b.WriteString(rule)
	w.emit("", b.String())
}

// prettyArgs indents the stored (redacted) args, escaping one line at a time
// because Escape would turn the layout newlines into \u000A.
func prettyArgs(raw json.RawMessage) string {
	var pretty bytes.Buffer
	s := string(raw)
	if json.Indent(&pretty, raw, "           ", "  ") == nil {
		s = pretty.String()
	}
	parts := strings.Split(cut(s), "\n") // JSON strings never hold a raw newline
	for i := range parts {
		parts[i] = Escape(parts[i])
	}
	return strings.Join(parts, "\n")
}

func (w *watcher) answer(ctx context.Context, line string) {
	f := strings.Fields(line)
	if len(f) == 0 {
		return
	}
	verb, rest := f[0], f[1:]
	if !w.canAct {
		// The read-only store may hold a throwaway key; it must never decide.
		w.emit("", "approver unavailable; decide with agentgw approvals approve|deny")
		return
	}
	if verb != "a" && verb != "d" {
		w.emit("", "say a or d (a 1, d 1 reason)")
		return
	}
	if len(w.cards) == 0 {
		w.emit("", "nothing pending")
		return
	}
	var c *card
	if len(rest) > 0 {
		if n, err := strconv.Atoi(rest[0]); err == nil {
			for _, x := range w.cards {
				if x.n == n {
					c = x
				}
			}
			if c == nil {
				w.emit("", fmt.Sprintf("no approval %d pending", n))
				return
			}
			rest = rest[1:]
		}
	}
	if c == nil {
		if len(w.cards) > 1 {
			var ns []string
			for _, x := range w.cards {
				ns = append(ns, fmt.Sprintf("%s %d", verb, x.n))
			}
			w.emit("", fmt.Sprintf("%d approvals pending; say %s", len(w.cards), strings.Join(ns, " or ")))
			return
		}
		c = w.cards[0]
	}
	var err error
	// id and hash come from the store's own record, not from anything displayed.
	if verb == "a" {
		err = w.store.Approve(ctx, c.p.ID, c.p.Request.ArgsHash, "", time.Time{})
	} else {
		err = w.store.Deny(ctx, c.p.ID, c.p.Request.ArgsHash, strings.Join(rest, " "))
	}
	switch {
	case err == nil:
		w.drop(c)
		w.event(map[string]string{"a": "approved", "d": "denied"}[verb], esc(c.p.ID)+" by you", "")
	case errors.Is(err, approval.ErrNotPending):
		w.drop(c)
		w.event("approval", esc(c.p.ID)+" not pending (expired or already decided)", "")
	default:
		w.event("approval", "could not record decision: "+esc(err.Error())+"; try again", "")
	}
}
