// Package ghapproval resolves held calls from GitHub issue or PR comments
// (docs/adr/0011). It is a poller: outbound HTTPS only, for a gateway on a
// CI runner that accepts no inbound connections.
package ghapproval

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/midspan-dev/agentgw/internal/approval"
	"github.com/midspan-dev/agentgw/internal/watch"
	"github.com/midspan-dev/agentgw/pkg/contracts"
)

// Options configures Run. Config must come from Resolve.
type Options struct {
	Config  contracts.GitHubApprovals
	Token   string
	APIBase string // empty: $GITHUB_API_URL, else https://api.github.com
	Store   *approval.Store
	Logf    func(string, ...any) // nil: discard
	Now     func() time.Time     // nil: time.Now
	HTTP    *http.Client         // nil: 30 s timeout, never follows redirects
}

var (
	repoRe    = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	loginRe   = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)
	commandRe = regexp.MustCompile(`^/(approve|deny)\s+([A-Za-z0-9]{8})(\s+(.*))?$`)
	nextRe    = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)
	roleRank  = map[string]int{"read": 0, "triage": 1, "write": 2, "maintain": 3, "admin": 4}
)

const (
	maxValue  = 2048
	maxReason = 200
	maxSpan   = 300
)

// Resolve applies defaults, validates cfg, and reads the issue number from
// the Actions event file at eventPath when cfg.Issue is 0.
func Resolve(cfg contracts.GitHubApprovals, eventPath string) (contracts.GitHubApprovals, error) {
	if !repoRe.MatchString(cfg.Repo) {
		return cfg, fmt.Errorf("github approvals: repo %q is not owner/name", cfg.Repo)
	}
	if cfg.MinPermission == "" {
		cfg.MinPermission = "write"
	}
	if r, ok := roleRank[cfg.MinPermission]; !ok || r == 0 {
		return cfg, fmt.Errorf("github approvals: min_permission %q is not one of triage, write, maintain, admin", cfg.MinPermission)
	}
	if cfg.PollInterval == "" {
		cfg.PollInterval = "15s"
	}
	if d, err := time.ParseDuration(cfg.PollInterval); err != nil || d < 5*time.Second {
		return cfg, fmt.Errorf("github approvals: poll_interval %q must be a duration of at least 5s", cfg.PollInterval)
	}
	if cfg.TokenEnv == "" {
		cfg.TokenEnv = "GITHUB_TOKEN"
	}
	if cfg.Issue < 0 {
		return cfg, fmt.Errorf("github approvals: issue %d is negative", cfg.Issue)
	}
	if cfg.Issue == 0 {
		var ev struct {
			Issue       struct{ Number int } `json:"issue"`
			PullRequest struct{ Number int } `json:"pull_request"`
		}
		if b, err := os.ReadFile(eventPath); err == nil {
			_ = json.Unmarshal(b, &ev)
		}
		if cfg.Issue = ev.Issue.Number; cfg.Issue == 0 {
			cfg.Issue = ev.PullRequest.Number
		}
		if cfg.Issue == 0 {
			return cfg, errors.New("github approvals: no issue number in config or event")
		}
	}
	return cfg, nil
}

type ghComment struct {
	ID        int64     `json:"id"`
	Body      string    `json:"body"`
	HTMLURL   string    `json:"html_url"`
	CreatedAt time.Time `json:"created_at"`
	User      struct {
		Login string `json:"login"`
		Type  string `json:"type"`
	} `json:"user"`
}

// held is an announced approval.
type held struct {
	pa      contracts.PendingApproval
	created time.Time // the request comment's created_at
}

type poller struct {
	o        Options
	api      string
	interval time.Duration
	minRank  int
	held     map[string]*held // approval id -> request comment
	seen     map[int64]bool   // comment ids already evaluated
	replied  map[string]bool  // one reply per approval id, or per unknown ref
	cursor   time.Time
	self     string // login of the token, learned from our own comments; "" is unknown
	tries    map[int64]int
	warned   bool
	resumeAt time.Time // rate-limit backoff, in Now time
}

// Run polls until ctx ends. Nothing is requested while no approval is pending.
func Run(ctx context.Context, o Options) error {
	c := o.Config
	if o.Token == "" {
		return errors.New("github approvals: empty token")
	}
	if c.Issue <= 0 || c.Repo == "" {
		return errors.New("github approvals: Config must come from Resolve")
	}
	p := &poller{o: o, held: map[string]*held{}, seen: map[int64]bool{}, tries: map[int64]int{}, replied: map[string]bool{}}
	var err error
	if p.interval, err = time.ParseDuration(c.PollInterval); err != nil {
		return fmt.Errorf("github approvals: poll_interval: %w", err)
	}
	p.minRank = roleRank[c.MinPermission]
	if p.o.Logf == nil {
		p.o.Logf = func(string, ...any) {}
	}
	if p.o.Now == nil {
		p.o.Now = time.Now
	}
	if p.o.HTTP == nil {
		p.o.HTTP = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if p.api = o.APIBase; p.api == "" {
		p.api = os.Getenv("GITHUB_API_URL")
	}
	if p.api == "" {
		p.api = "https://api.github.com"
	}
	p.api = strings.TrimRight(p.api, "/")

	for {
		p.poll(ctx)
		select {
		case <-ctx.Done():
			p.farewell()
			return nil
		case <-time.After(p.interval):
		}
	}
}

func (p *poller) issuePath() string {
	return fmt.Sprintf("/repos/%s/issues/%d/comments", p.o.Config.Repo, p.o.Config.Issue)
}

func (p *poller) poll(ctx context.Context) {
	list, err := p.o.Store.List(ctx)
	if err != nil {
		p.o.Logf("github approvals: list: %v", err)
		return
	}
	if len(list) == 0 && len(p.held) == 0 {
		return
	}
	for _, pa := range list {
		if p.held[pa.ID] == nil {
			p.announce(ctx, pa)
		}
	}
	if len(p.held) > 0 {
		p.readComments(ctx)
	}
	live := map[string]bool{}
	for _, pa := range list {
		live[pa.ID] = true
	}
	for id := range p.held {
		if !live[id] {
			p.outcome(ctx, id)
		}
	}
}

func ref(id string) string { return strings.ToUpper(id[max(0, len(id)-8):]) }

func (p *poller) announce(ctx context.Context, pa contracts.PendingApproval) {
	var c ghComment
	if err := p.do(ctx, "POST", p.api+p.issuePath(), map[string]string{"body": requestBody(pa)}, &c, nil); err != nil {
		return // retried next poll; the approval expires on its own
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = p.o.Now()
	}
	p.seen[c.ID] = true
	p.learn(c)
	p.held[pa.ID] = &held{pa: pa, created: c.CreatedAt}
	if p.cursor.IsZero() {
		p.cursor = c.CreatedAt
	}
}

// readComments drains every page since the cursor; the cursor moves, and
// comments are evaluated, only when all pages arrived.
func (p *poller) readComments(ctx context.Context) {
	u := p.api + p.issuePath() + "?per_page=100"
	if !p.cursor.IsZero() {
		u += "&since=" + url.QueryEscape(p.cursor.Add(-time.Second).UTC().Format(time.RFC3339))
	}
	var all []ghComment
	for u != "" {
		var page []ghComment
		var hdr http.Header
		if err := p.do(ctx, "GET", u, nil, &page, &hdr); err != nil {
			return
		}
		all = append(all, page...)
		u = ""
		if m := nextRe.FindStringSubmatch(hdr.Get("Link")); m != nil {
			if !strings.HasPrefix(m[1], p.api+"/") { // never send the token elsewhere
				p.o.Logf("github approvals: ignoring next link off the API base")
				return
			}
			u = m[1]
		}
	}
	for _, c := range all {
		if p.evaluate(ctx, c) {
			return // retry from this comment next poll; the cursor stays before it
		}
		if c.CreatedAt.After(p.cursor) {
			p.cursor = c.CreatedAt
		}
	}
}

// evaluate acts on one comment, once. It returns true when the comment could
// not be judged (rate limit, server error) and must be looked at again.
func (p *poller) evaluate(ctx context.Context, c ghComment) (retry bool) {
	if p.seen[c.ID] {
		return false
	}
	// Bots never count; neither does the token's own login (a user token is
	// also what the agent's GitHub tools post with).
	if c.User.Type != "User" {
		p.seen[c.ID] = true
		return false
	}
	if p.self == "" { // evaluate nothing until we know which login is ours
		if !p.warned {
			p.warned = true
			p.o.Logf("github approvals: own login unknown, not evaluating commands")
		}
		return true
	}
	if strings.EqualFold(c.User.Login, p.self) {
		p.seen[c.ID] = true
		return false
	}
	body, _, _ := strings.Cut(c.Body, "\n")
	m := commandRe.FindStringSubmatch(strings.TrimRight(body, "\r"))
	if m == nil {
		p.seen[c.ID] = true
		return false
	}
	cmd, r := m[1], strings.ToUpper(m[2])
	var id string
	var h *held
	for i, x := range p.held {
		if ref(i) == r {
			if h != nil {
				h = nil
				break
			}
			id, h = i, x
		}
	}
	if h != nil && c.CreatedAt.Before(h.created) {
		p.seen[c.ID] = true
		return false
	}
	ok, final := p.permitted(ctx, c.User.Login)
	if !final {
		return p.again(c)
	}
	p.seen[c.ID] = true
	if !ok {
		p.o.Logf("github approvals: ignoring %s from unpermitted user", cmd)
		return false
	}
	if h == nil {
		if !p.replied["ref:"+r] {
			p.replied["ref:"+r] = true
			p.comment(ctx, fmt.Sprintf("no pending approval `%s`", r), r)
		}
		return false
	}
	if ap := h.pa.Request.Spec.Approvers; len(ap) > 0 && !named(ap, c.User.Login) {
		p.o.Logf("github approvals: ignoring %s from %s: not a named approver", cmd, c.User.Login)
		if !p.replied["named:"+id] {
			p.replied["named:"+id] = true
			spans := make([]string, len(ap))
			for i, a := range ap {
				spans[i] = span(a)
			}
			p.comment(ctx, fmt.Sprintf("only %s may approve %s", strings.Join(spans, ", "), span(r)), r)
		}
		return false
	}
	via := contracts.DecisionVia{Surface: "github", User: c.User.Login, URL: c.HTMLURL}
	var err error
	if cmd == "approve" {
		err = p.o.Store.ApproveVia(ctx, id, h.pa.Request.ArgsHash, via)
	} else {
		reason := esc(strings.TrimSpace(m[4]))
		if rs := []rune(reason); len(rs) > maxReason {
			reason = string(rs[:maxReason])
		}
		err = p.o.Store.DenyVia(ctx, id, h.pa.Request.ArgsHash, reason, via)
	}
	switch {
	case errors.Is(err, approval.ErrNotPending):
		if !p.replied[id] {
			p.replied[id] = true
			p.comment(ctx, "already "+p.state(ctx, id), r)
		}
	case errors.Is(err, approval.ErrArgsHashMismatch):
		p.o.Logf("github approvals: decide: %v", err)
	case err != nil:
		p.o.Logf("github approvals: decide: %v", err)
		return p.again(c)
	}
	return false
}

// again says whether to retry c next poll. Failures outside a rate-limit
// backoff count; after three, c is dropped so it cannot block the batch.
func (p *poller) again(c ghComment) bool {
	if p.o.Now().Before(p.resumeAt) {
		return true
	}
	if p.tries[c.ID]++; p.tries[c.ID] < 3 {
		return true
	}
	p.seen[c.ID] = true
	p.o.Logf("github approvals: dropped comment %d from %s after 3 failed polls", c.ID, c.User.Login)
	return false
}

func (p *poller) learn(c ghComment) {
	if p.self == "" {
		p.self = c.User.Login
	}
}

// state describes how id was resolved, for replies and outcome comments.
func (p *poller) state(ctx context.Context, id string) string {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	d, err := p.o.Store.Wait(ctx, id, func(string) {})
	switch {
	case errors.Is(err, contracts.ErrApprovalTimeout):
		return "expired"
	case d == nil:
		return "resolved"
	}
	by := "the local approver"
	if d.Via != nil {
		by = "@" + esc(d.Via.User) // GitHub logins are [A-Za-z0-9-]
	}
	if d.Decision == contracts.DecisionApproved {
		return "approved by " + by
	}
	if d.Reason != "" {
		return "denied by " + by + ": " + span(d.Reason)
	}
	return "denied by " + by
}

func (p *poller) outcome(ctx context.Context, id string) {
	if p.comment(ctx, p.state(ctx, id), ref(id)) {
		delete(p.held, id)
	}
}

func (p *poller) farewell() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if list, err := p.o.Store.List(ctx); err == nil && len(list) > 0 {
		p.comment(ctx, fmt.Sprintf("run ended, %d approvals still pending", len(list)), "")
	}
}

// permitted reports whether login may decide. final is false when the lookup
// failed in a way that says nothing about the user (anything but 200 or 404).
func (p *poller) permitted(ctx context.Context, login string) (ok, final bool) {
	var raw struct {
		Permission string `json:"permission"`
		RoleName   string `json:"role_name"`
	}
	if err := p.do(ctx, "GET", p.api+"/repos/"+p.o.Config.Repo+"/collaborators/"+url.PathEscape(login)+"/permission", nil, &raw, nil); err != nil {
		var se statusErr
		return false, errors.As(err, &se) && se == 404
	}
	role := raw.RoleName
	if role == "" {
		role = raw.Permission
	}
	rank, known := roleRank[role]
	return known && rank >= p.minRank, true
}

// comment posts body plus the gateway marker; ref "" omits the ref.
func (p *poller) comment(ctx context.Context, body, r string) bool {
	var c ghComment
	if p.do(ctx, "POST", p.api+p.issuePath(), map[string]string{"body": body + "\n\n" + marker(r)}, &c, nil) != nil {
		return false
	}
	p.seen[c.ID] = true
	p.learn(c)
	return true
}

// named reports whether login is one of the policy's approvers. Entries that
// are not GitHub logins (emails, say) never match.
func named(approvers []string, login string) bool {
	for _, a := range approvers {
		if loginRe.MatchString(a) && strings.EqualFold(a, login) {
			return true
		}
	}
	return false
}

// approversLine names the policy's approvers in the request comment. Logins
// come from the operator's policy, so they may be @mentioned.
func approversLine(ap []string) string {
	if len(ap) == 0 {
		return ""
	}
	var parts []string
	for _, a := range ap {
		if loginRe.MatchString(a) {
			parts = append(parts, "@"+a)
		} else {
			parts = append(parts, span(a))
		}
	}
	line := "- Approvers: " + strings.Join(parts, ", ")
	if !slices.ContainsFunc(ap, loginRe.MatchString) {
		line += " (none is a GitHub login: this call cannot be approved by comment and will expire unless decided from the terminal with `agentgw approvals` or `agentgw watch`)"
	}
	return line + "\n"
}

func marker(r string) string { return "<!-- agentgw ref=" + r + " -->" }

var errBackoff = errors.New("rate limited")

type statusErr int

func (e statusErr) Error() string { return fmt.Sprintf("status %d", int(e)) }

// do makes one API call. It logs status codes and paths only, never the token.
func (p *poller) do(ctx context.Context, method, u string, in, out any, hdr *http.Header) error {
	if p.o.Now().Before(p.resumeAt) {
		return errBackoff
	}
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.o.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "agentgw")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.o.HTTP.Do(req)
	path := strings.TrimPrefix(u, p.api)
	if err != nil {
		p.o.Logf("github approvals: %s %s: request failed", method, path)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 403 || resp.StatusCode == 429 {
		// GitHub sends X-RateLimit-Reset on every response, so only Retry-After
		// or an exhausted quota make a 403 a rate limit.
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil {
			p.resumeAt = p.o.Now().Add(time.Duration(s) * time.Second)
		} else if s, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil && resp.Header.Get("X-RateLimit-Remaining") == "0" {
			p.resumeAt = time.Unix(s, 0)
		}
	}
	if resp.StatusCode/100 != 2 {
		p.o.Logf("github approvals: %s %s: status %d", method, path, resp.StatusCode)
		return statusErr(resp.StatusCode)
	}
	if hdr != nil {
		*hdr = resp.Header
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		p.o.Logf("github approvals: %s %s: bad response body", method, path)
		return err
	}
	return nil
}

// esc is the only way an untrusted value enters a comment or the ledger.
func esc(s string) string {
	// Escape leaves "<!--" alone; break it so a value cannot forge the marker.
	return strings.ReplaceAll(watch.Escape(s), "<!--", "\\u003C!--")
}

// span renders an untrusted value inert: cut, escaped, and inside a code span
// whose backtick run is longer than any run in the value.
func span(s string) string {
	if rs := []rune(s); len(rs) > maxSpan {
		s = fmt.Sprintf("%s… (%d bytes)", string(rs[:maxSpan]), len(s))
	}
	v := esc(s)
	n, run := 0, 0
	for _, r := range v {
		if run = run + 1; r != '`' {
			run = 0
		}
		n = max(n, run)
	}
	f := strings.Repeat("`", n+1)
	if strings.HasPrefix(v, "`") || strings.HasSuffix(v, "`") {
		v = " " + v + " "
	}
	return f + v + f
}

func cut(s string) string {
	if len(s) <= maxValue {
		return s
	}
	n := maxValue
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return fmt.Sprintf("%s… (%d bytes)", s[:n], len(s))
}

func requestBody(pa contracts.PendingApproval) string {
	r := pa.Request
	args := string(r.Args)
	var buf bytes.Buffer
	if json.Compact(&buf, r.Args) == nil {
		args = buf.String()
	}
	args = esc(cut(args))
	fence := "```"
	for strings.Contains(args, fence) {
		fence += "`"
	}
	cost := strconv.FormatFloat(float64(r.EstimatedCost.Micros)/contracts.MicrosPerUnit, 'f', -1, 64) + " " + esc(r.EstimatedCost.Currency)
	rf := ref(pa.ID)
	return fmt.Sprintf("**agentgw is holding a tool call for approval**\n\n"+
		"- Agent: %s\n- Tool: %s\n- Estimated cost: %s\n- Rule: %s\n%s- Expires: %s\n- Ref: %s\n\n"+
		"Arguments (redacted):\n\n%sjson\n%s\n%s\n\n"+
		"Reply with one of:\n\n    /approve %s\n    /deny %s [reason]\n\n%s",
		span(r.Principal.AgentID), span(r.Server+"."+r.Tool), cost, span(r.RuleID), approversLine(r.Spec.Approvers),
		pa.ExpiresAt.UTC().Format(time.RFC3339), rf, fence, args, fence, rf, rf, marker(rf))
}
