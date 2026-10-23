package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/midspan-dev/agentgw/internal/watch"
)

func init() {
	commands["watch"] = watchCmd
	extraUsage = append(extraUsage, "  agentgw watch     [--config f] [--no-input] [--no-color] [--since N|all]")
}

func watchCmd(ctx context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	cfgFlag := fs.String("config", "", "config file")
	noInput := fs.Bool("no-input", false, "read-only: never open the approver key")
	noColor := fs.Bool("no-color", false, "no colour")
	since := fs.String("since", "10", "ledger entries to show on start (N or all)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	n := -1
	if *since != "all" {
		var err error
		if n, err = strconv.Atoi(*since); err != nil || n < 0 {
			return errors.New("watch: --since takes a number or all")
		}
	}
	path := *cfgFlag
	if path == "" {
		tried := []string{"agentgw.yaml"}
		if home, err := os.UserHomeDir(); err == nil {
			tried = append(tried, filepath.Join(home, ".agentgw", "agentgw.yaml"))
		}
		for _, p := range tried {
			if _, err := os.Stat(p); err == nil {
				path = p
				break
			}
		}
		if path == "" {
			return fmt.Errorf("watch: no config found (tried %v; use --config)", tried)
		}
	}
	cfg, err := loadConfig(path)
	if err != nil {
		return err
	}
	tty := false
	if f, ok := out.(*os.File); ok {
		st, err := f.Stat()
		tty = err == nil && st.Mode()&os.ModeCharDevice != 0
	}
	return watch.Run(ctx, watch.Options{Config: cfg, ConfigPath: path, NoInput: *noInput, NoColor: *noColor,
		Since: n, IsTTY: tty}, os.Stdin, out)
}
