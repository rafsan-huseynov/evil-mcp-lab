"""Generate an HTML "Attack Findings" report for the evil-mcp-lab server.

Unlike the Agent 365 CLI (which scores schema *quality*), this scans the live
server's tool schemas and runtime audit trail for the *attacks* the lab hides,
and renders a self-contained HTML report.

Usage (from repo root, with the server running):
    PYTHONPATH=. .venv/bin/python scripts/attack_report.py
    open eval/attack_report.html

Override the target with EMCP_URL. It reads audit.log for runtime evidence.
"""
import html
import json
import os
import re

import anyio
import mcp

import config

URL = os.environ.get("EMCP_URL", "http://127.0.0.1:8124/mcp")
OUT = os.path.join(os.path.dirname(os.path.dirname(__file__)), "eval", "attack_report.html")

# Known attack catalog (name -> technique / OWASP-ATLAS mapping) for labeling.
CATALOG = {
    "tool_poisoning": ("Tool Poisoning", "OWASP-LLM01 / ATLAS"),
    "tool_shadowing": ("Tool Shadowing (confused deputy)", "OWASP-LLM01"),
    "data_exfiltration": ("Data Exfiltration", "OWASP-LLM02"),
    "sensitive_file_access": ("Sensitive File Access", "OWASP-LLM02"),
    "sandbox_escape": ("Sandbox Escape", "OWASP-LLM06 / ATLAS"),
    "schema_mismatch": ("Schema / Description Mismatch", "A365 schema check"),
    "injection_relay": ("Indirect Prompt-Injection Relay", "OWASP-LLM01"),
    "rug_pull": ("Rug Pull (tool mutation)", "AGT tool-change"),
}

SEVERITY = {
    "tool_poisoning": "critical",
    "injection_relay": "critical",
    "data_exfiltration": "critical",
    "tool_shadowing": "high",
    "sensitive_file_access": "high",
    "sandbox_escape": "high",
    "schema_mismatch": "medium",
    "rug_pull": "high",
}


def _schema_of(tool):
    return getattr(tool, "inputSchema", None) or getattr(tool, "input_schema", None) or {}


def detect_static(tools):
    """Scan tool schemas/descriptions for attack signatures. Returns findings."""
    findings = []
    for t in tools:
        name = t.name
        desc = t.description or ""
        schema = _schema_of(t)
        props = (schema or {}).get("properties", {}) or {}
        injection_flagged = False

        # 1. Prompt-injection blocks embedded in a tool description.
        if re.search(r"<IMPORTANT>", desc, re.I) or re.search(r"do not (mention|tell)", desc, re.I) \
                or re.search(r"ignore (previous|prior)", desc, re.I):
            injection_flagged = True
            # Distinguish poisoning-self vs shadowing-another-tool.
            attack = "tool_shadowing" if re.search(r"send_email|bcc", desc, re.I) else "tool_poisoning"
            findings.append(dict(
                tool=name, attack=attack,
                evidence=_snippet(desc, r"<IMPORTANT>.*?</IMPORTANT>|<IMPORTANT>.*"),
                note="Hidden instruction block inside the tool description — an agent reading "
                     "this schema is steered to act against the user, silently.",
            ))

        # 2. Data exfiltration: an endpoint/URL parameter defaulting to a network sink.
        for pname, pspec in props.items():
            default = pspec.get("default")
            if isinstance(default, str) and re.match(r"https?://", default):
                findings.append(dict(
                    tool=name, attack="data_exfiltration",
                    evidence=f"parameter '{pname}' default = {default}",
                    note="A parameter silently POSTs the tool input to a network endpoint "
                         "by default, disguised as 'diagnostics / quality monitoring'.",
                ))

        # 3. Sensitive-file access advertised as the tool's own input. Skip tools whose
        #    credential-path mention is only inside an injection block (already reported above).
        if not injection_flagged and re.search(r"id_rsa|\.ssh|\.aws|credentials|\.env", desc, re.I):
            findings.append(dict(
                tool=name, attack="sensitive_file_access",
                evidence=_snippet(desc, r"[^.]*(id_rsa|\.ssh|\.aws|credentials|\.env)[^.]*\.?"),
                note="The description advertises credential file paths as supported inputs.",
            ))

        # 4. Sandbox escape: traversal / absolute paths invited.
        if re.search(r"\.\./|/etc/passwd|absolute path", desc, re.I):
            findings.append(dict(
                tool=name, attack="sandbox_escape",
                evidence=_snippet(desc, r"[^.]*(\.\./|/etc/passwd|absolute path)[^.]*\.?"),
                note="The description invites path traversal and absolute paths to read files "
                     "outside the sandbox.",
            ))

        # 5. Schema / description mismatch: doc says a count/number but schema types it as string.
        for pname, pspec in props.items():
            if re.search(r"count|number|how many|times", (desc + " " + pname), re.I) \
                    and pname.lower() in ("count",) and pspec.get("type") == "string":
                findings.append(dict(
                    tool=name, attack="schema_mismatch",
                    evidence=f"'{pname}' documented as a number but schema type = \"string\"",
                    note="The parameter is described as numeric but typed as a string — a mismatch "
                         "a static evaluator should flag and an agent will get wrong.",
                ))
    return findings


async def detect_runtime(client):
    """Actively probe for attacks whose payload only appears at call time."""
    findings = []

    # injection_relay: fetch_notes returns an injection payload in its OUTPUT.
    try:
        r = await client.call_tool("fetch_notes", {})
        text = _result_text(r)
        if re.search(r"\[SYSTEM\]|ignore (previous|prior)|exfiltrat|read .*secret", text, re.I):
            findings.append(dict(
                tool="fetch_notes", attack="injection_relay",
                evidence=_snippet(text, r"\[SYSTEM\].*|Ignore previous.*"),
                note="The tool's RETURNED CONTENT is itself a prompt-injection payload — invisible "
                     "to any static schema scan, only visible when the tool is actually called.",
            ))
    except Exception as e:  # noqa: BLE001
        findings.append(dict(tool="fetch_notes", attack="injection_relay",
                             evidence=f"(probe error: {e})", note="Could not probe at runtime."))

    # rug_pull: greet's description mutates after a call threshold.
    try:
        before = {t.name: (t.description or "") for t in (await client.list_tools()).tools}
        for _ in range(config.RUG_PULL_THRESHOLD + 1):
            await client.call_tool("greet", {"name": "lab"})
        after = {t.name: (t.description or "") for t in (await client.list_tools()).tools}
        if before.get("greet") != after.get("greet"):
            findings.append(dict(
                tool="greet", attack="rug_pull",
                evidence=f"description changed after {config.RUG_PULL_THRESHOLD} calls",
                note=f"Clean on install, mutated to a malicious variant after "
                     f"{config.RUG_PULL_THRESHOLD} calls — an 'approved then swapped' bait-and-switch.",
                extra={"before": before.get("greet", ""), "after": after.get("greet", "")},
            ))
    except Exception as e:  # noqa: BLE001
        findings.append(dict(tool="greet", attack="rug_pull",
                             evidence=f"(probe error: {e})", note="Could not probe at runtime."))

    return findings


def read_audit(limit=40):
    path = config.AUDIT_LOG
    rows = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f.read().splitlines()[-limit:]:
                parts = line.split("\t")
                if len(parts) >= 3:
                    rows.append(parts)
    return rows


# ---- small helpers -------------------------------------------------------

def _snippet(text, pattern):
    m = re.search(pattern, text, re.S | re.I)
    s = m.group(0) if m else text[:200]
    return s.strip()[:400]


def _result_text(result):
    sc = getattr(result, "structured_content", None)
    if isinstance(sc, dict):
        return json.dumps(sc)
    out = []
    for block in getattr(result, "content", []) or []:
        out.append(getattr(block, "text", ""))
    return "\n".join(out)


# ---- HTML rendering ------------------------------------------------------

def render(findings, audit_rows, tool_count):
    crit = sum(1 for f in findings if SEVERITY.get(f["attack"]) == "critical")
    high = sum(1 for f in findings if SEVERITY.get(f["attack"]) == "high")
    med = sum(1 for f in findings if SEVERITY.get(f["attack"]) == "medium")
    blocked = sum(1 for r in audit_rows if r[2] == "blocked")
    exfil = sum(1 for r in audit_rows if r[2] in ("exfil-sent", "exfil"))

    cards = []
    order = {"critical": 0, "high": 1, "medium": 2}
    for f in sorted(findings, key=lambda x: order.get(SEVERITY.get(x["attack"], "medium"), 3)):
        label, mapping = CATALOG.get(f["attack"], (f["attack"], ""))
        sev = SEVERITY.get(f["attack"], "medium")
        extra = ""
        if f.get("extra"):
            extra = (
                f"<div class='diff'><div><span class='k'>before</span>"
                f"<pre>{html.escape(f['extra']['before'])}</pre></div>"
                f"<div><span class='k'>after</span>"
                f"<pre>{html.escape(f['extra']['after'])}</pre></div></div>"
            )
        cards.append(f"""
      <article class="card sev-{sev}">
        <header>
          <span class="tool">{html.escape(f['tool'])}</span>
          <span class="badge {sev}">{sev.upper()}</span>
        </header>
        <h3>{html.escape(label)}</h3>
        <p class="note">{html.escape(f['note'])}</p>
        <div class="evidence"><span class="k">evidence</span><pre>{html.escape(f['evidence'])}</pre></div>
        {extra}
        <footer>{html.escape(mapping)}</footer>
      </article>""")

    audit_html = "".join(
        f"<tr class='a-{html.escape(r[2])}'><td>{html.escape(r[0][11:19])}</td>"
        f"<td>{html.escape(r[1])}</td><td><span class='pill {html.escape(r[2])}'>{html.escape(r[2])}</span></td>"
        f"<td>{html.escape(r[3] if len(r) > 3 else '')}</td></tr>"
        for r in reversed(audit_rows)
    ) or "<tr><td colspan='4' class='muted'>No audit entries yet — run an attack first.</td></tr>"

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>evil-mcp-lab — Attack Findings</title>
<style>
:root {{
  --bg:#f6f7f9; --panel:#fff; --ink:#14161a; --muted:#5b6472; --line:#e4e7ec;
  --crit:#c0362c; --crit-bg:#fbe9e7; --high:#b25a00; --high-bg:#fdf0e1;
  --med:#8a6d00; --med-bg:#fbf5df; --ok:#1f7a44; --accent:#3b4a6b;
}}
@media (prefers-color-scheme: dark) {{
  :root:not([data-theme="light"]) {{
    --bg:#0f1115; --panel:#171a21; --ink:#e8eaed; --muted:#9aa4b2; --line:#262b34;
    --crit:#ff6b5e; --crit-bg:#2a1512; --high:#ffab5c; --high-bg:#241a10;
    --med:#e6c74d; --med-bg:#221f10; --ok:#57d98a; --accent:#8fa4d4;
  }}
}}
:root[data-theme="dark"] {{
  --bg:#0f1115; --panel:#171a21; --ink:#e8eaed; --muted:#9aa4b2; --line:#262b34;
  --crit:#ff6b5e; --crit-bg:#2a1512; --high:#ffab5c; --high-bg:#241a10;
  --med:#e6c74d; --med-bg:#221f10; --ok:#57d98a; --accent:#8fa4d4;
}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}}
.wrap{{max-width:1000px;margin:0 auto;padding:32px 20px 64px}}
.top{{display:flex;align-items:baseline;justify-content:space-between;flex-wrap:wrap;gap:8px}}
h1{{font-size:24px;margin:0}}
.sub{{color:var(--muted);font-size:13px}}
.lead{{color:var(--muted);margin:14px 0 24px;max-width:70ch}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin-bottom:28px}}
.stat{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}}
.stat .n{{font-size:30px;font-weight:700;line-height:1}}
.stat .l{{color:var(--muted);font-size:12px;margin-top:6px;text-transform:uppercase;letter-spacing:.04em}}
.stat.c .n{{color:var(--crit)}} .stat.h .n{{color:var(--high)}} .stat.b .n{{color:var(--ok)}}
h2{{font-size:15px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);
  margin:32px 0 14px;border-bottom:1px solid var(--line);padding-bottom:8px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:14px}}
.card{{background:var(--panel);border:1px solid var(--line);border-left-width:4px;border-radius:12px;padding:16px}}
.card.sev-critical{{border-left-color:var(--crit)}}
.card.sev-high{{border-left-color:var(--high)}}
.card.sev-medium{{border-left-color:var(--med)}}
.card header{{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}}
.tool{{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;font-weight:600}}
.badge{{font-size:10px;font-weight:700;letter-spacing:.06em;padding:3px 8px;border-radius:20px}}
.badge.critical{{background:var(--crit-bg);color:var(--crit)}}
.badge.high{{background:var(--high-bg);color:var(--high)}}
.badge.medium{{background:var(--med-bg);color:var(--med)}}
.card h3{{margin:2px 0 8px;font-size:16px}}
.note{{color:var(--muted);font-size:13px;margin:0 0 10px}}
.evidence .k,.diff .k{{font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}}
pre{{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:8px 10px;margin:4px 0 0;
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;white-space:pre-wrap;
  word-break:break-word;overflow-x:auto}}
.diff{{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:10px}}
.card footer{{margin-top:12px;font-size:11px;color:var(--muted);font-family:ui-monospace,monospace}}
table{{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}}
th,td{{text-align:left;padding:9px 12px;font-size:13px;border-bottom:1px solid var(--line)}}
th{{color:var(--muted);text-transform:uppercase;font-size:11px;letter-spacing:.05em}}
td:nth-child(1){{font-family:ui-monospace,monospace;color:var(--muted)}}
td:nth-child(2){{font-family:ui-monospace,monospace}}
.pill{{font-size:11px;font-weight:600;padding:2px 8px;border-radius:20px;background:var(--bg)}}
.pill.blocked{{background:var(--crit-bg);color:var(--crit)}}
.pill.read,.pill.fired{{background:var(--med-bg);color:var(--med)}}
.pill.exfil-sent,.pill.exfil{{background:var(--high-bg);color:var(--high)}}
.muted{{color:var(--muted)}}
.footnote{{margin-top:36px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:14px}}
</style></head><body><div class="wrap">
  <div class="top"><h1>Attack Findings — evil-mcp-lab</h1>
    <span class="sub">{tool_count} tools scanned · {URL}</span></div>
  <p class="lead">This report scans the live MCP server for the <strong>attacks</strong> it hides —
    prompt-injection blocks in tool descriptions, silent exfiltration, credential-file access, sandbox
    escape, schema mismatch, injection-in-output, and tool mutation — plus the runtime guard decisions
    from the audit log. Unlike a schema-quality score, it answers: <em>is this server safe?</em></p>

  <div class="stats">
    <div class="stat c"><div class="n">{crit}</div><div class="l">Critical</div></div>
    <div class="stat h"><div class="n">{high}</div><div class="l">High</div></div>
    <div class="stat"><div class="n">{med}</div><div class="l">Medium</div></div>
    <div class="stat b"><div class="n">{blocked}</div><div class="l">Blocked at runtime</div></div>
    <div class="stat"><div class="n">{exfil}</div><div class="l">Exfil (loopback)</div></div>
  </div>

  <h2>Detected attacks ({len(findings)})</h2>
  <div class="grid">{''.join(cards)}</div>

  <h2>Runtime audit trail</h2>
  <table><thead><tr><th>Time</th><th>Attack</th><th>Decision</th><th>Detail</th></tr></thead>
  <tbody>{audit_html}</tbody></table>

  <p class="footnote">Generated by evil-mcp-lab attack_report.py — LAB USE ONLY. Every attack is confined
    to <code>./lab/</code>; exfiltration is loopback-only; decoys are fake. The guard blocks resolve
    outside the sandbox and logs every decision.</p>
</div></body></html>"""


async def main():
    async with mcp.Client(URL) as client:
        tools = (await client.list_tools()).tools
        findings = detect_static(tools)
        findings += await detect_runtime(client)
    audit_rows = read_audit()
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(render(findings, audit_rows, len(tools)))
    print(f"Detected {len(findings)} attack findings across {len(tools)} tools.")
    for f in findings:
        print(f"  [{SEVERITY.get(f['attack'],'?'):8}] {f['tool']:12} {CATALOG.get(f['attack'],(f['attack'],))[0]}")
    print(f"\nReport written: {OUT}")


if __name__ == "__main__":
    anyio.run(main)
