// Command agentgw is the agent action gateway CLI.
//
//	agentgw run       [--config f] [--agent id] [--run id] [--server name] [-- cmd args...]
//	agentgw serve     [--config f] [--agent id] [--run id]
//	agentgw verify    [--config f] [<ledger.jsonl> <pubkey-hex>]
//	agentgw approvals list|init [--config f]
//	agentgw approvals approve [--config f] [--scope run|agent] [--until RFC3339] <id> <args-hash>
//	agentgw approvals deny [--config f] [--reason text] <id> <args-hash>
//	agentgw keygen    [--config f]
//	agentgw version
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/midspan-dev/agentgw/internal/approval"
	"github.com/midspan-dev/agentgw/internal/budget"
	"github.com/midspan-dev/agentgw/internal/ledger"
	"github.com/midspan-dev/agentgw/internal/pipeline"
	"github.com/midspan-dev/agentgw/internal/policy"
	"github.com/midspan-dev/agentgw/internal/policy/reload"
	"github.com/midspan-dev/agentgw/internal/proxy"
	"github.com/midspan-dev/agentgw/pkg/contracts"
	"github.com/oklog/ulid/v2"
)

var version = "dev"

const usage = `usage:
  agentgw run       [--config f] [--agent id] [--run id] [--server name] [-- cmd args...]
  agentgw serve     [--config f] [--agent id] [--run id]
  agentgw verify    [--config f] [<ledger.jsonl> <pubkey-hex>]
  agentgw approvals list|init [--config f]
  agentgw approvals approve [--config f] [--scope run|agent] [--until RFC3339] <id> <args-hash>
  agentgw approvals deny [--config f] [--reason text] <id> <args-hash>
  agentgw keygen    [--config f]
  agentgw version
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stdout)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "agentgw:", err)
		os.Exit(1)
	}
}

var errUsage = errors.New("bad usage")

// commands are subcommands registered by other files in this package from
// init(); names must not collide with the built-in cases in run().
var commands = map[string]func(ctx context.Context, args []string, out io.Writer) error{}

// extraUsage holds one usage line per registered command, appended sorted.
var extraUsage []string

func usageText() string {
	extra := append([]string(nil), extraUsage...)
	sort.Strings(extra)
	s := usage
	for _, l := range extra {
		s += l + "\n"
	}
	return s
}

func printUsage() { fmt.Fprint(os.Stderr, usageText()) }

func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		printUsage()
		return errUsage
	}
	cmd, args := args[0], args[1:]
	switch cmd {
	case "run", "serve":
		return gateway(ctx, cmd, args)
	case "verify":
		return verify(args, out)
	case "approvals":
		return approvals(ctx, args, out)
	case "keygen":
		fs, cfgPath := flags("keygen")
		if err := fs.Parse(args); err != nil {
			return err
		}
		cfg, err := loadConfig(*cfgPath)
		if err != nil {
			return err
		}
		pub, err := ledger.GenerateKey(cfg.KeyPath)
		if err != nil {
			return err
		}
		fmt.Fprintln(out, hex.EncodeToString(pub))
		return nil
	case "version":
		fmt.Fprintln(out, "agentgw", version)
		return nil
	}
	if f, ok := commands[cmd]; ok {
		return f(ctx, args, out)
	}
	printUsage()
	return errUsage
}

func flags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	return fs, fs.String("config", "agentgw.yaml", "config file (YAML or JSON)")
}

// gateway runs `run` (stdio) or `serve` (HTTP) until the client or ctx ends it.
func gateway(ctx context.Context, mode string, args []string) error {
	fs, cfgPath := flags(mode)
	agent := fs.String("agent", "", "agent id (overrides config agent.id)")
	runID := fs.String("run", "", "run id (default: a fresh ULID)")
	server := fs.String("server", "", "run: upstream name (with -- cmd, default \"default\")")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	who := contracts.Principal{AgentID: cfg.Agent.ID, Owner: cfg.Agent.Owner, RunID: *runID}
	if *agent != "" {
		who.AgentID = *agent
	}
	if who.RunID == "" {
		who.RunID = ulid.Make().String()
	}

	src, err := os.ReadFile(cfg.PolicyPath)
	if err != nil {
		return err
	}
	var pol *policy.Policy
	if filepath.Ext(cfg.PolicyPath) == ".cedar" {
		pol, err = policy.LoadCedar(src)
	} else {
		pol, err = policy.Compile(src)
	}
	if err != nil {
		return err
	}
	for _, l := range pol.Limits() {
		if l.Limit.Currency != cfg.Currency {
			return fmt.Errorf("policy budget currency %s differs from config currency %s", l.Limit.Currency, cfg.Currency)
		}
	}
	key, err := ledger.LoadKey(cfg.KeyPath)
	if err != nil {
		return err
	}
	led, err := ledger.Open(cfg.Ledger, key, cfg.Redaction)
	if err != nil {
		return err
	}
	defer led.Close()
	bud, err := budget.Open(cfg.StatePath, pol.Limits())
	if err != nil {
		return err
	}
	defer bud.Close()
	appr, err := approval.Open(cfg.StatePath, cfg.Approvals.CLI.TokenPath)
	if err != nil {
		return err
	}
	defer appr.Close()

	ic := &tracked{ic: pipeline.New(pipeline.Deps{
		Principal: who, Pricer: budget.NewPricer(cfg.Prices, cfg.Currency), Decider: reload.New(cfg.PolicyPath, pol, os.Stderr, time.Now, reload.WithCurrency(cfg.Currency)),
		Budget: bud, Ledger: led, Approver: appr, Currency: cfg.Currency,
	})}
	// The proxy returns without waiting for in-flight calls; finish them (they
	// end on ctx cancel and record detached) before the stores above close.
	defer ic.drain()

	if mode == "serve" {
		if cfg.Listen == "" {
			return errors.New("serve: config listen is empty")
		}
		var routes []proxy.Route
		for _, u := range cfg.Upstreams {
			if u.URL != "" {
				routes = append(routes, proxy.Route{Name: u.Name, Path: u.Path, URL: u.URL})
			}
		}
		if len(routes) == 0 {
			return errors.New("serve: no url upstreams in config")
		}
		return proxy.HTTP(ctx, cfg.Listen, routes, ic)
	}

	name, command := *server, fs.Args()
	if len(command) > 0 {
		if name == "" {
			name = "default"
		}
	} else {
		var found []contracts.Upstream
		for _, u := range cfg.Upstreams {
			if len(u.Command) > 0 && (name == "" || u.Name == name) {
				found = append(found, u)
			}
		}
		if len(found) != 1 {
			return errors.New("run: need exactly one command upstream (pick one with --server, or pass -- cmd)")
		}
		name, command = found[0].Name, found[0].Command
	}
	return proxy.Stdio(ctx, name, command, ic)
}

func verify(args []string, out io.Writer) error {
	fs, cfgPath := flags("verify")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var path string
	var pub ed25519.PublicKey
	switch fs.NArg() {
	case 2:
		path = fs.Arg(0)
		b, err := hex.DecodeString(fs.Arg(1))
		if err != nil || len(b) != ed25519.PublicKeySize {
			return errors.New("verify: public key must be 64 hex characters")
		}
		pub = b
	case 0:
		cfg, err := loadConfig(*cfgPath)
		if err != nil {
			return err
		}
		key, err := ledger.LoadKey(cfg.KeyPath)
		if err != nil {
			return err
		}
		path, pub = cfg.Ledger.Path, key.Public().(ed25519.PublicKey)
	default:
		return errUsage
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	rep := ledger.Verify(f, pub)
	if !rep.OK {
		return fmt.Errorf("verify: FAIL at line %d: %s (%d entries, %d checkpoints verified before it)",
			rep.Line, rep.Reason, rep.Entries, rep.Checkpoints)
	}
	fmt.Fprintf(out, "ok: %d entries, %d checkpoints\n", rep.Entries, rep.Checkpoints)
	return nil
}

func approvals(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 {
		return errUsage
	}
	sub, args := args[0], args[1:]
	fs, cfgPath := flags("approvals " + sub)
	scope := fs.String("scope", "", "approve: also issue a grant, run or agent")
	until := fs.String("until", "", "approve: grant expiry, RFC 3339 (required for agent scope)")
	reason := fs.String("reason", "", "deny: reason shown to the agent")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	token := cfg.Approvals.CLI.TokenPath
	if sub == "init" {
		if _, err := os.Stat(token); err == nil {
			return fmt.Errorf("approvals init: %s already exists", token)
		}
		return approval.GenerateToken(token)
	}
	s, err := approval.Open(cfg.StatePath, token)
	if err != nil {
		return err
	}
	defer s.Close()
	switch sub {
	case "list":
		if fs.NArg() != 0 {
			return errUsage
		}
		l, err := s.List(ctx)
		if err != nil {
			return err
		}
		// One line per approval: id, server.tool, args hash, expiry, rule, redacted args.
		for _, p := range l {
			r := p.Request
			fmt.Fprintf(out, "%s\t%s.%s\t%s\t%s\t%s\t%s\n", p.ID, r.Server, r.Tool, r.ArgsHash,
				p.ExpiresAt.UTC().Format(time.RFC3339), r.RuleID, strings.ReplaceAll(string(r.Args), "\n", " "))
		}
		return nil
	case "approve", "deny":
		if fs.NArg() != 2 {
			return errUsage
		}
		id, hash := fs.Arg(0), fs.Arg(1)
		if sub == "deny" {
			return s.Deny(ctx, id, hash, *reason)
		}
		var t time.Time
		if *until != "" {
			if t, err = time.Parse(time.RFC3339, *until); err != nil {
				return fmt.Errorf("--until: %w", err)
			}
		}
		return s.Approve(ctx, id, hash, contracts.GrantScope(*scope), t)
	}
	return errUsage
}

// tracked counts in-flight Intercept calls so shutdown can wait for their
// ledger entries. Calls arriving after drain are refused, never forwarded.
type tracked struct {
	ic     contracts.Interceptor
	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

func (t *tracked) Intercept(ctx context.Context, call *contracts.Call) (json.RawMessage, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, errors.New("agentgw: shutting down")
	}
	t.wg.Add(1)
	t.mu.Unlock()
	defer t.wg.Done()
	return t.ic.Intercept(ctx, call)
}

func (t *tracked) drain() {
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
	t.wg.Wait()
}
