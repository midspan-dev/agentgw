package main

import (
	"context"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/midspan-dev/agentgw/internal/setup"
)

func init() {
	commands["init"] = initCmd
	extraUsage = append(extraUsage, "  agentgw init [--dir d] [--name n] [--agent id] [--owner o] [--scope user|local|project] [--no-discover] [--no-register] [--yes] [-- cmd args...]")
}

func initCmd(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	var o setup.Options
	fs.StringVar(&o.Dir, "dir", "", "gateway directory (default ~/.agentgw)")
	fs.StringVar(&o.Name, "name", "", "server name (default from the command)")
	fs.StringVar(&o.AgentID, "agent", "", "agent id (default $USER)")
	fs.StringVar(&o.Owner, "owner", "", "owner (default git email or $USER@host)")
	fs.StringVar(&o.Scope, "scope", "", "Claude Code scope: user (default), local or project")
	fs.BoolVar(&o.NoDiscover, "no-discover", false, "do not start the server to list its tools")
	fs.BoolVar(&o.NoRegister, "no-register", false, "print the claude mcp add command instead of running it")
	fs.BoolVar(&o.Yes, "yes", false, "ask nothing; take defaults")
	if err := fs.Parse(args); err != nil {
		return err
	}
	o.Command = fs.Args()
	if st, err := os.Stdin.Stat(); err != nil || st.Mode()&os.ModeCharDevice == 0 {
		o.Yes = true
	}
	o.Executable = registeredExecutable(exec.LookPath)
	return setup.Run(ctx, o, os.Stdin, out)
}

// registeredExecutable is the agentgw path Claude Code will start: the
// agentgw on PATH when it is this binary, otherwise this binary's path as
// started. Never the symlink target: Homebrew's target is a versioned Cellar
// path that `brew upgrade` deletes.
func registeredExecutable(lookPath func(string) (string, error)) string {
	exe, err := os.Executable()
	if err != nil {
		return "agentgw"
	}
	if p, err := lookPath("agentgw"); err == nil {
		if abs, err := filepath.Abs(p); err == nil {
			a, errA := os.Stat(abs)
			b, errB := os.Stat(exe)
			if errA == nil && errB == nil && os.SameFile(a, b) {
				return abs
			}
		}
	}
	return exe
}
