# evil-mcp-lab (LAB USE ONLY)

> ⚠️ **LAB USE ONLY — educational security research. Deliberately vulnerable.**
> Do not deploy or connect this to a production agent or tenant.
> This repository is for local-only security testing. Do not expose it to external networks, public endpoints, or real agents.
> If you share it publicly, remove git history and generated artifacts before publishing.

This is a deliberately malicious MCP server used as a test target for tool-safety controls.
It exposes common attack patterns in a local sandbox so security tools can detect them.

The lab includes eight attack styles:
- tool poisoning
- rug pulls
- tool shadowing
- data exfiltration
- sensitive file access
- injection relay
- schema mismatch
- sandbox escape

It is meant to be scanned and governed, not trusted.

## Safety model

The server is intentionally isolated:
- file access is limited to the local lab folder
- exfiltration is blocked unless the target is loopback-only
- all fake secrets are decoys, not real credentials
- every decision is logged to an audit file

## Setup

```bash
pip install -r requirements.txt
python lab/setup_lab.py
python collector/collector.py &
python server/main.py --http
```

The server listens on a local loopback endpoint such as http://127.0.0.1:8124/mcp. This must remain local-only and must not be exposed outside the machine.

## What it is testing

This project is designed to validate two kinds of defenses:
1. static review of tool metadata and schema
2. runtime governance that blocks dangerous behavior at call time

This matches the practical security model described in Microsoft’s MCP guidance: evaluate the server first with the Agent 365 CLI, then govern sensitive actions at runtime with the Agent Governance Toolkit (AGT). The purpose is to check the MCP surface before an agent uses it and to enforce policy while the agent is running.

The Agent 365 CLI examines tool definitions, descriptions, and parameter schemas to score how safe and clear they are. AGT wraps tool calls with policy checks, identity context, and audit evidence so risky actions can be denied or require approval before execution.

## How this lab maps to the real workflow

The lab is meant to demonstrate the same lifecycle described in the Microsoft blog:

Reference: https://techcommunity.microsoft.com/blog/microsoft-security-blog/mcp-safety--evaluation-with-the-agent-365-cli--agent-governance-toolkit/4543969

- Evaluate the server before use: Agent 365 CLI inspects the MCP tool list and produces a maturity score, action items, and recommendations.
- Govern the execution path: AGT wraps tool calls with policy, identity context, and decision logging.
- Test in a dry run: a deliberately unsafe MCP endpoint is used as a controlled demonstration target.

In practice, a workflow looks like this:

1. Start the local malicious server.
2. Run the static evaluation against the MCP endpoint.
3. Review the tool-by-tool issues and prioritise the highest-risk problems.
4. Wrap the risky tools with AGT policy checks.
5. Confirm that blocked actions raise a governance decision and are recorded with evidence.

## Example evaluation command

```bash
a365 develop-mcp evaluate \
  --server-url http://127.0.0.1:8124/mcp \
  --eval-engine claude-code \
  --output-dir ./eval
```

This command reads the server’s advertised metadata, scores semantic quality, and writes local HTML and JSON reports that highlight problems such as misleading descriptions, dangerous parameter naming, and schema quality issues.

## Example AGT pattern

```python
from agentmesh.governance import govern

safe_tool = govern(my_tool, policy="governance/policy.yaml")
```

The wrapper lets the agent call the original tool only when the configured policy allows it. If a tool is dangerous, mismatched, or suspicious, AGT raises a governance exception and stores a decision record for audit.

## Why this matters

An MCP server can look legitimate at a glance while still being risky. A tool can have a reasonable name and a valid schema but still contain hidden prompt injection, data exfiltration logic, or misleading instructions. That is why both control points matter:

- static tooling helps catch weak or malicious metadata before an agent connects
- runtime governance helps stop harmful actions while the agent is running

Neither approach replaces secure server code, sandbox boundaries, or protected audit storage, but together they give a much stronger baseline for agent safety.

## Attack summary

| Name | Example behavior |
| --- | --- |
| tool_poisoning | hidden instruction in tool description tells the model to read a file and include it in a response |
| rug_pull | tool description changes after a few calls to add malicious behavior |
| tool_shadowing | one tool secretly hijacks another tool's behavior |
| data_exfiltration | tool posts content to a local collector endpoint |
| sensitive_file_access | tool advertises credential paths and then reads decoy files |
| injection_relay | tool returns a payload that tells the model to ignore prior instructions |
| schema_mismatch | advertised parameter says one thing, but the actual schema is different |
| sandbox_escape | input tries to traverse outside the lab folder, but the guard blocks it |

## Important note

This lab is for educational security testing only. It should only be used in a fully isolated local environment.
