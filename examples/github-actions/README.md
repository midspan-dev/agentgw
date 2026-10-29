# One MCP policy, on your laptop and in GitHub Actions

Claude Code triages a new GitHub issue through the official GitHub MCP server,
behind agentgw. The same `policy.yaml` and the same pinned server run twice:

| | laptop | GitHub Actions |
|---|---|---|
| config | `agentgw.local.yaml` | `agentgw.yaml` |
| policy | `policy.yaml` | `policy.yaml` (the same bytes) |
| upstream | `github-mcp-server` v2.0.3 (pinned by digest), issues toolset | the same |
| a held call is approved | in the terminal: `agentgw watch`, press `a` | on the issue: reply `/approve <ref>` |
| proof | `agentgw verify` on `ledger.jsonl` | `agentgw verify` on the `agentgw-ledger` artifact |

The configs differ only in the `approvals` block, the comments and nothing
else (`diff agentgw.yaml agentgw.local.yaml`). The policy has three rules:

- `deny-rewrite-and-repo-writes`: editing comments, sub-issues and every
  repository write are denied. The ledger records `denied` and nothing is sent
  to GitHub.
- `issue-write-needs-approval`: `issue_write` (create, edit, label, assign,
  close) waits for a human. `issue_write` is one tool for all of those, so the
  policy cannot allow labelling and hold closing; everything it does is held.
- `triage`: reads and `add_issue_comment` are allowed.

Approval works while the job is still running; there is no resume after the
runner ends.

## Why the agent has no shell

On a runner, the agent, the gateway, `policy.yaml`, the state database, the
ledger key and the approver key share one machine and one user. An agent that
can run a shell, or read and write files, could read `approver.key` and approve
its own call, edit `policy.yaml`, or rewrite the ledger. So the workflow starts
Claude Code with every built-in tool removed (`--tools ""`) and only the tools
of the wrapped GitHub server allowed (`mcp__github__*`). The agent's only way
to touch anything is through the gateway, and the gateway applies the policy.
[COMPAT.md](COMPAT.md) records the evidence for the exact flags. The
`claude-code-action` is not used: its documented defaults include file tools
and its own GitHub servers, and `allowedTools` adds tools rather than
restricting them.

Never give the GitHub MCP server a personal access token owned by someone who
may approve. The agent can post comments through that server; with such a
token it would post `/approve` as that person. The example uses the job's
`GITHUB_TOKEN`, whose comments are from a Bot and never count as approvals.

## Set up

1. Copy this directory to `examples/github-actions/` in a repository you own
   (a throwaway public repository is fine), and copy
   `examples/github-actions/.github/workflows/triage.yml` to
   `.github/workflows/triage.yml`.
2. Edit `agentgw.yaml`: set `approvals.github.repo` to `your-login/your-repo`
   and `agent.owner` to your email or login.
3. The workflow pins the agentgw release it installs (`AGENTGW_VERSION`,
   0.3.0). Change it to upgrade; it must stay 0.3.0 or later, for GitHub
   approvals and the outcome comment.
4. Generate the two keys on your machine and read their contents:

   ```sh
   cd examples/github-actions
   agentgw keygen --config agentgw.yaml           # prints the ledger public key
   agentgw approvals init --config agentgw.yaml   # writes approver.key
   cat ledger.key approver.key                    # each is one line of hex
   ```

5. In the repository's Settings, Secrets and variables, Actions, create three
   secrets and one variable:
   - secret `AGENTGW_LEDGER_KEY`: the contents of `ledger.key`
   - secret `AGENTGW_APPROVER_KEY`: the contents of `approver.key`
   - secret `ANTHROPIC_API_KEY`: your Anthropic API key
   - variable `AGENTGW_LEDGER_PUBKEY`: the public key `keygen` printed
6. Delete the two key files from your machine, or keep them somewhere safe;
   `.gitignore` already keeps them out of the repository.
7. Enable Actions, then open an issue.

Only issues opened by the repository's owner, members and collaborators start a
run (the workflow checks `author_association`). Every run spends your
`ANTHROPIC_API_KEY` and runner minutes, and the issue text is the agent's input,
so do not widen that gate on a public repository.

Workflow permissions, and why:

- `issues: write`: the agent's triage comment, the issue edit once approved,
  and the gateway's own approval and outcome comments.
- `contents: read`: checkout, to get this directory.
- Nothing else. The check that a commenter may approve calls the collaborator
  permission endpoint, which needs only "Metadata" read, which every
  `GITHUB_TOKEN` has.

The token is not least-privilege for an agent in general (`issues: write` can
do more than this policy allows). The policy, not the token, is what limits
the agent here.

## What to expect

On a new issue the job runs the agent with the prompt in `prompt.txt`:

1. The agent reads the issue and posts a triage comment (`triage`, `ok`).
2. It asks to close the issue. The gateway holds the call and posts a comment
   on the issue with the tool, the redacted arguments, the rule and a short
   reference, plus two lines to copy:

   ```
   /approve 7K3M9QXA
   /deny 7K3M9QXA [reason]
   ```

   Reply with `/approve <ref>` (as a user with write access or better). The
   job continues, the gateway posts an outcome comment
   naming you, and the issue closes. `/deny <ref> because` refuses it. If
   nobody answers within the rule's timeout the call expires and nothing runs.
3. It tries to edit its own comment. The policy denies it: nothing is sent to
   GitHub and the comment is unchanged.
4. The job verifies the ledger, uploads it as the `agentgw-ledger` artifact
   and deletes the keys.

Download the artifact and check it anywhere:

```sh
agentgw verify ledger.jsonl <the public key keygen printed>
```

Only replies from users at or above `min_permission` (default `write`) count,
checked through the GitHub API on every reply. Replies from bots, including the
agent's own comments, are ignored.

## Measure the limit

A held call is one MCP `tools/call` request that stays open until a human
answers. The headless client gives up on a request at some point, and the
policy's `timeout` (10 minutes here) must be shorter than that. To measure it:
run the job, leave the approval unanswered, and note when the client reports an
error in the job log and the ledger. Set the rule's `timeout` below that
number. Then approve a call late, but inside the limit, to see `ok`. In our run
with Claude Code 2.1.310 the client was still waiting when the 10-minute
timeout expired, so 10 minutes is inside the limit.

## The laptop run

See [local.md](local.md). Same policy, same server, approvals in `agentgw
watch`.
