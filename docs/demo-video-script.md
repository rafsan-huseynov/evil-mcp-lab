# 2-Minute Demo Video Script — MCP Safety with the Agent 365 CLI

Shows the Agent 365 CLI evaluating the deliberately-malicious `evil-mcp-lab`
server and the resulting report. Mirrors the Microsoft Security Community Blog
post "MCP safety & evaluation with the Agent 365 CLI & Agent Governance Toolkit".

---

## BEFORE YOU HIT RECORD (do this once, off-camera)

The full LLM-scored report is slow to generate (~40 min), so it's already made.
This prep just makes sure the server is up and the terminal is clean.

```bash
cd ~/evil-mcp-lab
source .venv/bin/activate

# start server + collector fresh, and clear the audit log for a clean trail
pkill -f "server.main --http"; pkill -f "collector.collector"; sleep 1
: > audit.log                                   # clean runtime audit trail
PYTHONPATH=. .venv/bin/python -m collector.collector  > /tmp/emcp_collector.log 2>&1 &
PYTHONPATH=. .venv/bin/python -m server.main --http    > /tmp/emcp_server.log 2>&1 &
sleep 2
(nc -z 127.0.0.1 8124 && echo "server OK") ; (nc -z 127.0.0.1 9000 && echo "collector OK")

# seed runtime evidence + generate BOTH reports you'll show on camera:
PYTHONPATH=. .venv/bin/python scripts/walk_sandbox_escape.py > /dev/null   # blocks -> audit
PYTHONPATH=. .venv/bin/python scripts/attack_report.py                     # writes eval/attack_report.html
rm -rf eval-live                                                           # so Act 1 shows a FRESH discovery
ls eval/127-0-0-1-8124_eval_report.html eval/attack_report.html           # a365 report already generated earlier

clear   # clean terminal for recording
```

Have BOTH reports open in browser tabs (the a365 quality report and
`eval/attack_report.html`), then switch back to the terminal to start.

---

## ON CAMERA (~2 minutes)

### [0:00–0:15] Set the scene (talk over a clean terminal)
> "This is a deliberately malicious MCP server — it hides prompt-injection, data
> exfiltration, and sandbox-escape attacks inside normal-looking tools. Let's see
> what the Agent 365 CLI makes of it."

### [0:15–0:40] Run the evaluation (fast path — no waiting on camera)
```bash
a365 develop-mcp evaluate --server-url "http://127.0.0.1:8124/mcp" --eval-engine none --output-dir "./eval-live"
```
> "It connects, reads the tool schemas... **Found 8 tools**, and builds a
> 118-point evaluation checklist."

(Uses a fresh `./eval-live` dir so you see a real live discovery in ~1 second.
`--eval-engine none` skips the slow scoring. The full LLM-scored report you open
next was generated ahead of time from this same server — see prep step.)

### [0:40–0:50] Open the report
```bash
open eval/127-0-0-1-8124_eval_report.html
```

### [0:50–1:20] Walk the a365 report — "it looks fine"
Point at the screen and hit these beats:
- **"Overall score: 77 out of 100, Level 2."** — "It's not a fail. The schemas are
  valid and consistently named."
- Open the `summarize` tool's checks → point at the PASS on its description:
  **"It even *rewarded* the sentence that hides the data exfiltration — 'a copy of
  the input is sent to the diagnostics service' scored as a helpful detail."**
- The critical items: **"All 9 'critical' findings are 'missing parameter
  description' — quality gaps. Not one attack was flagged."**

### [1:20–1:45] Act 2 — the attack report — "it is NOT safe"
```bash
open eval/attack_report.html
```
> "Same server, scanned for the attacks instead of the quality. Eight tools, eight
> attacks — four critical. The get_weather poisoning, the exfil endpoint, the
> injection payload that only appears when you call fetch_notes, greet rug-pulling
> itself after a few calls — and the runtime guard blocking every path-escape and
> logging it."

### [1:45–2:00] The takeaway
> "So: the quality scan gave it 77 out of 100. The safety scan found eight attacks.
> Static evaluation tells you if an agent can *understand* your tools — not whether
> they're *safe*. You need both control points: evaluate the interface before use,
> and govern the dangerous call at runtime."

---

## ONE-LINE SUMMARY FOR THE LINKEDIN POST
> A deliberately-malicious MCP server scored 77/100 on the Agent 365 CLI's schema
> quality evaluation — and a separate scan found 8 attacks hiding in the same 8
> tools. Valid schemas ≠ safe tools. Evaluate the interface *and* govern the call. 🧵
