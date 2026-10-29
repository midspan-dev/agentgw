package setup

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/midspan-dev/agentgw/internal/approval"
	"github.com/midspan-dev/agentgw/internal/ledger"
)

// Options configure Run. Zero values mean the defaults in docs/cli.md.
type Options struct {
	Dir, Name, AgentID, Owner, Scope string
	Command                          []string
	NoDiscover, NoRegister, Yes      bool
	Executable                       string                       // agentgw path for the registration
	LookPath                         func(string) (string, error) // default exec.LookPath
	Now                              func() time.Time             // default time.Now
}

var (
	nameBad = regexp.MustCompile(`[^A-Za-z0-9_-]+`)
	nameOK  = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

func defaultName(command []string) string {
	base := ""
	if len(command) > 0 {
		base = command[0]
		for _, a := range command[1:] {
			if !strings.HasPrefix(a, "-") {
				base = a
				break
			}
		}
	}
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	if base = strings.Trim(nameBad.ReplaceAllString(base, "-"), "-"); base == "" {
		return "server"
	}
	return base
}

func envUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	return "user"
}

func defaultOwner() string {
	if out, err := exec.Command("git", "config", "user.email").Output(); err == nil {
		if e := strings.TrimSpace(string(out)); e != "" {
			return e
		}
	}
	h, _ := os.Hostname()
	if h == "" {
		h = "localhost"
	}
	return envUser() + "@" + h
}

// Run sets up the gateway directory and registers the server with Claude Code.
func Run(ctx context.Context, o Options, in io.Reader, out io.Writer) error {
	if o.Dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		o.Dir = filepath.Join(home, ".agentgw")
	}
	dir, err := filepath.Abs(o.Dir)
	if err != nil {
		return err
	}
	if o.Scope == "" {
		o.Scope = "user"
	}
	if o.Scope != "user" && o.Scope != "local" && o.Scope != "project" {
		return fmt.Errorf("--scope must be user, local or project, not %q", o.Scope)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.LookPath == nil {
		o.LookPath = exec.LookPath
	}
	if o.Executable == "" {
		o.Executable = "agentgw"
	}
	if o.Yes && len(o.Command) == 0 {
		return errors.New("no upstream command: pass it after --, for example `agentgw init --yes -- npx -y @modelcontextprotocol/server-everything`")
	}

	fmt.Fprintf(out, "agentgw init: set up a gateway in %s\n\n", dir)
	r := bufio.NewReader(in)
	ask := func(label, def string) (string, error) {
		fmt.Fprintf(out, "%s", label)
		if def != "" {
			fmt.Fprintf(out, " [%s]", def)
		}
		fmt.Fprint(out, ": ")
		line, err := r.ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("reading %s: %w", strings.ToLower(label), err)
		}
		if line = strings.TrimSpace(line); line != "" {
			return line, nil
		}
		return def, nil
	}
	if len(o.Command) == 0 {
		line, err := ask("Upstream MCP server command (what Claude Code would run)", "")
		if err != nil {
			return err
		}
		if o.Command = strings.Fields(line); len(o.Command) == 0 {
			return errors.New("no upstream command given")
		}
	}
	for _, f := range []struct {
		p          *string
		label, def string
	}{
		{&o.Name, "Name for this server", defaultName(o.Command)},
		{&o.AgentID, "Agent id", envUser()},
		{&o.Owner, "Owner (an email or a name)", ""},
	} {
		if *f.p != "" {
			continue
		}
		if f.p == &o.Owner {
			f.def = defaultOwner()
		}
		if o.Yes {
			*f.p = f.def
		} else if *f.p, err = ask(f.label, f.def); err != nil {
			return err
		}
	}
	if !nameOK.MatchString(o.Name) {
		return fmt.Errorf("--name must match [A-Za-z0-9_-]+, not %q", o.Name)
	}
	if !o.Yes {
		fmt.Fprintln(out)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	cfgPath := filepath.Join(dir, "agentgw.yaml")
	kept := false
	// file runs step when path is absent, otherwise prints kept.
	file := func(name string, step func(path string) (string, error)) error {
		p := filepath.Join(dir, name)
		if _, err := os.Lstat(p); err == nil {
			kept = true
			fmt.Fprintf(out, "kept     %s\n", p)
			if name == "agentgw.yaml" {
				fmt.Fprintf(out, "         config kept; edit upstreams in %s to change the server\n", p)
			}
			return nil
		}
		note, err := step(p)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		fmt.Fprintf(out, "created  %s%s\n", p, note)
		return nil
	}
	write := func(b []byte) func(string) (string, error) {
		return func(p string) (string, error) {
			f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
			if err != nil {
				return "", err
			}
			_, err = f.Write(b)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			return "", err
		}
	}
	if err := file("agentgw.yaml", func(p string) (string, error) {
		return write(StarterConfig(o.Name, o.Command, o.AgentID, o.Owner))(p)
	}); err != nil {
		return err
	}
	if err := file("policy.yaml", func(p string) (string, error) {
		var tools []string
		var derr error
		if o.NoDiscover {
			derr = errors.New("discovery skipped (--no-discover)")
		} else {
			fmt.Fprintf(out, "listing tools on %q (up to 2 min; a first npx run downloads the server)\n", o.Name)
			tools, derr = Discover(ctx, o.Command)
		}
		pol := StarterPolicy(o.Name, tools, derr == nil, o.Now())
		if derr != nil {
			fmt.Fprintf(out, "warning: could not list tools from %q: %v; writing the template policy\n", o.Name, derr)
			_, err := write(pol)(p)
			return "", err
		}
		_, err := write(pol)(p)
		return fmt.Sprintf("    (%d tools found on %q; %d need approval)", len(tools), o.Name, countFlagged(tools)), err
	}); err != nil {
		return err
	}
	var h string
	if err := file("ledger.key", func(p string) (string, error) {
		pub, err := ledger.GenerateKey(p)
		if err != nil {
			return "", err
		}
		h = hex.EncodeToString(pub)
		return "     public key " + h[:4] + "…" + h[len(h)-4:], nil
	}); err != nil {
		return err
	}
	if h != "" {
		fmt.Fprintf(out, "         ledger public key (signer in every entry):\n         %s\n", h)
	}
	if err := file("approver.key", func(p string) (string, error) { return "", approval.GenerateToken(p) }); err != nil {
		return err
	}
	if kept {
		fmt.Fprintf(out, "to start over, delete %s\n", dir)
	}
	fmt.Fprintln(out)
	register(ctx, o, cfgPath, out)
	fmt.Fprintf(out, "\nNext: open a second terminal and run `agentgw watch`, then use Claude Code.\nRules live in %s and apply on the next tool call.\n",
		filepath.Join(dir, "policy.yaml"))
	return nil
}

func countFlagged(tools []string) int {
	n := 0
	for _, t := range tools {
		if safeName.MatchString(t) && isDestructive(t) {
			n++
		}
	}
	return n
}

func scopeLine(scope string) string {
	cwd, _ := os.Getwd()
	switch scope {
	case "local":
		return fmt.Sprintf("available only when claude runs from %s (scope local)", cwd)
	case "project":
		return fmt.Sprintf("written to %s/.mcp.json; available to anyone who opens this project (scope project)", cwd)
	}
	return "available in Claude Code from any directory (scope user)"
}

// register never fails init: everything else is already in place.
func register(ctx context.Context, o Options, cfgPath string, out io.Writer) {
	args := []string{"mcp", "add", "--scope", o.Scope, o.Name, "--", o.Executable, "run", "--config", cfgPath, "--server", o.Name}
	cmdline := "claude " + strings.Join(args, " ")
	yourself := func() {
		fmt.Fprintf(out, "register it yourself: %s\n         %s\n", cmdline, scopeLine(o.Scope))
	}
	if o.NoRegister {
		yourself()
		return
	}
	claude, err := o.LookPath("claude")
	if err != nil {
		yourself()
		return
	}
	if got, err := exec.CommandContext(ctx, claude, "mcp", "get", o.Name).CombinedOutput(); err == nil {
		fmt.Fprintf(out, "already registered with Claude Code as %q\n%s", o.Name, got)
		if len(got) > 0 && got[len(got)-1] != '\n' {
			fmt.Fprintln(out)
		}
		return
	}
	if got, err := exec.CommandContext(ctx, claude, args...).CombinedOutput(); err != nil {
		fmt.Fprintf(out, "warning: claude mcp add failed: %v\n%s", err, got)
		yourself()
		return
	}
	fmt.Fprintf(out, "registered with Claude Code: %s\n         %s\n", cmdline, scopeLine(o.Scope))
}
