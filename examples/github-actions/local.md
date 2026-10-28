# The laptop run

The same policy and the same pinned GitHub MCP server, with approvals in the
terminal. Needs: Docker, Claude Code, agentgw, and a **separate throwaway
repository** with a fine-grained personal access token scoped to that one
repository with Issues read and write (the approved close needs write). Do not
use the repository that runs the Actions workflow: a personal token is its
owner's identity, so a local agent holding it could post `/approve` on an
Actions approval, and the Actions gateway must not see this repository's
issues.

```sh
cd examples/github-actions
agentgw keygen --config agentgw.local.yaml            # prints the ledger public key
agentgw approvals init --config agentgw.local.yaml
export GITHUB_TOKEN=<your token>
```

Edit `agent.owner` in `agentgw.local.yaml`. In a second terminal, in the same
directory:

```sh
agentgw watch --config agentgw.local.yaml
```

Open an issue on your repository, then run the agent with the same flags as the
workflow (the prompt names the issue; `ANTHROPIC_API_KEY` or your Claude Code
login must be available):

```sh
claude -p "Issue #1 in you/your-repo. $(cat prompt.txt)" \
  --tools "" \
  --disallowedTools Bash Edit Write Read Glob Grep NotebookEdit WebFetch WebSearch Task Agent ListMcpResourcesTool ReadMcpResourceTool \
  --allowedTools "mcp__github" \
  --mcp-config mcp.local.json --strict-mcp-config \
  --permission-mode dontAsk --disable-slash-commands --no-session-persistence
```

Or register it for interactive use: `claude mcp add github -- agentgw run
--config $PWD/agentgw.local.yaml`.

`watch` shows the triage comment as `allow … ok`, then a card for the held
close. Type `a` and Enter to approve it, or `d` to deny. The comment edit is
shown as `deny … denied`. Then:

```sh
agentgw verify --config agentgw.local.yaml
```

Each equivalent call has the same `policy_version`, `outcome` and `rule_id` in
this ledger and in the Actions one.
