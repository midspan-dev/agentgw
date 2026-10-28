# Run in GitHub Actions

One MCP policy, on your laptop and in GitHub Actions. Claude Code triages a new
issue through the official GitHub MCP server, behind agentgw. A call the policy
holds is approved by a `/approve` comment on the issue while the job is still
running, and the signed ledger of the run is a workflow artifact you can verify
anywhere.

This page proves one thing: the same `policy.yaml` you ran on your laptop makes
the same decisions on a runner. The example is in the
[examples/github-actions](https://github.com/midspan-dev/agentgw/tree/main/examples/github-actions)
directory of the repository.

Needs: a GitHub repository you own, an Anthropic API key, and agentgw (see the
[quickstart](quickstart)) to make two keys and verify the ledger.

## 1. Set up

Copy the example directory into your repository as `examples/github-actions/`
and its `.github/workflows/triage.yml` to `.github/workflows/triage.yml`. Set
`approvals.github.repo` in `agentgw.yaml` to your repository. The workflow pins
the agentgw release it installs (`AGENTGW_VERSION`), which must be 0.3.0-rc.2
or later, the first release that posts the outcome comment this page describes.
Then make the keys:

```sh
cd examples/github-actions
agentgw keygen --config agentgw.yaml           # prints the ledger public key
agentgw approvals init --config agentgw.yaml
cat ledger.key approver.key
```

Create the secrets `AGENTGW_LEDGER_KEY` and `AGENTGW_APPROVER_KEY` (the two
files' contents) and `ANTHROPIC_API_KEY`, and the repository variable
`AGENTGW_LEDGER_PUBKEY` (the printed public key). Enable Actions and open an
issue. Only issues opened by the repository's owner, members and collaborators
start a run (the workflow checks `author_association`): each run spends your
Anthropic key and the issue text is the agent's input, so keep that gate on a
public repository.

The workflow asks for `issues: write` (the agent's comment, the issue edit
once approved, and the gateway's approval comments) and `contents: read`
(checkout). Checking who may approve needs only the "Metadata" permission that
every job token has.

## 2. The run

The policy has three rules: reading and commenting are allowed, any issue edit
or close waits for approval, and rewriting comments and all repository writes are
denied. The agent is told to read the issue, comment, close it, and try once to
edit its own comment.

When it asks to close the issue, the gateway holds the call and comments:

````
**agentgw is holding a tool call for approval**

- Agent: `issue-triage`
- Tool: `github.issue_write`
- Estimated cost: 0 USD
- Rule: `issue-write-needs-approval`
- Expires: 2026-10-27T12:36:14Z
- Ref: 82MCFBZH

Arguments (redacted):

```json
{"issue_number":5,"method":"update","owner":"midspan-dev","repo":"agentgw-gha-demo","state":"closed","state_reason":"not_planned"}
```

Reply with one of:

    /approve 82MCFBZH
    /deny 82MCFBZH [reason]

<!-- agentgw ref=82MCFBZH -->
````

Reply on the issue as someone with write access:

```
/approve <ref>
```

or `/deny <ref> reason`. The job continues, the gateway posts an outcome comment
naming who decided, and the denied comment edit never reaches GitHub. The job
then verifies the ledger and uploads it.

```
ok: 4 entries, 0 checkpoints
```

Approval works while the job is still running; there is no resume after the
runner ends. If nobody answers within the rule's timeout the call expires
and nothing runs.

## 3. Who may approve

The gateway polls the issue's comments (outbound requests only; a runner accepts
no inbound connections). A reply counts only if its author is a user, not a bot
(so neither the job's own token nor another workflow can approve), is not the
gateway's own account, and has a repository role at or above `min_permission`
(default `write`). The gateway checks the role through the GitHub API on every
reply, so a role revoked mid-run takes effect on the next one. Everyone else is
ignored and logged. Each comment is read once; editing it later changes nothing.

Do not give the GitHub MCP server a personal access token owned by an approver.
The agent can post comments through that server, and its `/approve` would carry
your standing. The example uses the job's token, whose comments are from a Bot.

## 4. What this does and does not protect against

The agent has no shell and no file tools: the workflow starts Claude Code with
every built-in tool removed and only the wrapped server's tools allowed. This
matters because on a runner everything shares one machine. An agent with a
shell could read the approver key and approve itself, edit `policy.yaml`, or
rewrite the ledger with the ledger key. The example's `COMPAT.md` records the
check that the agent really has only the intended tools.

The approver signature shows that the process holding the approver key approved
this call with these arguments. It does not by itself show that a particular
GitHub user did; the ledger entry links to the comment, which GitHub keeps. Anyone
who can run arbitrary code on the runner during the job could forge it. The
policy, not the token's scopes, is what limits the agent: the token can do more
than the policy allows.

## 5. Verify

Download the `agentgw-ledger` artifact from the run and check it with the public
key you saved:

```sh
agentgw verify ledger.jsonl <pubkey-hex>
```

Run the same issue on your laptop with the same `policy.yaml` (see `local.md` in
the example) and compare the two ledgers: each equivalent call has the same
`policy_version`, `outcome` and `rule_id`.
