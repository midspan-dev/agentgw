package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/midspan-dev/agentgw/internal/approval"
	"github.com/midspan-dev/agentgw/internal/ghapproval"
	"github.com/midspan-dev/agentgw/pkg/contracts"
)

// startGitHubApprovals starts the comment poller when approvals.github is
// configured (docs/adr/0011). stop cancels it and waits for Run to return.
func startGitHubApprovals(ctx context.Context, cfg *contracts.Config, store *approval.Store) (stop func(), err error) {
	if cfg.Approvals.GitHub == nil {
		return func() {}, nil
	}
	rc, err := ghapproval.Resolve(*cfg.Approvals.GitHub, os.Getenv("GITHUB_EVENT_PATH"))
	if err != nil {
		return nil, err
	}
	tok := os.Getenv(rc.TokenEnv)
	if tok == "" {
		return nil, errors.New("github approvals: $" + rc.TokenEnv + " is empty")
	}
	fmt.Fprintf(os.Stderr, "github approvals: polling %s#%d every %s (min permission %s)\n", rc.Repo, rc.Issue, rc.PollInterval, rc.MinPermission)
	logf := func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) }
	cctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := ghapproval.Run(cctx, ghapproval.Options{Config: rc, Token: tok, Store: store, Logf: logf}); err != nil {
			logf("github approvals: stopped: %v; held calls can no longer be approved by comment and will time out", err)
		}
	}()
	return func() { cancel(); <-done }, nil
}
