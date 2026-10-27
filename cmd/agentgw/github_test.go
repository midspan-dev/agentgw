package main

import (
	"context"
	"strings"
	"testing"

	"github.com/midspan-dev/agentgw/pkg/contracts"
)

func ghCfg(g *contracts.GitHubApprovals) *contracts.Config {
	return &contracts.Config{Approvals: contracts.ApprovalsConfig{GitHub: g}}
}

func TestStartGitHubApprovalsNilBlock(t *testing.T) {
	stop, err := startGitHubApprovals(context.Background(), ghCfg(nil), nil)
	if err != nil || stop == nil {
		t.Fatal(stop == nil, err)
	}
	stop()
}

func TestStartGitHubApprovalsEmptyToken(t *testing.T) {
	t.Setenv("GH_WIRING_TOKEN", "")
	// A nil store would panic if anything started.
	stop, err := startGitHubApprovals(context.Background(), ghCfg(&contracts.GitHubApprovals{Repo: "o/r", Issue: 7, TokenEnv: "GH_WIRING_TOKEN"}), nil)
	if err == nil || !strings.Contains(err.Error(), "GH_WIRING_TOKEN") || stop != nil {
		t.Fatal(stop != nil, err)
	}
}

func TestStartGitHubApprovalsNoIssue(t *testing.T) {
	t.Setenv("GITHUB_EVENT_PATH", "")
	t.Setenv("GITHUB_TOKEN", "x")
	stop, err := startGitHubApprovals(context.Background(), ghCfg(&contracts.GitHubApprovals{Repo: "o/r"}), nil)
	if err == nil || !strings.Contains(err.Error(), "no issue number") || stop != nil {
		t.Fatal(stop != nil, err)
	}
}
