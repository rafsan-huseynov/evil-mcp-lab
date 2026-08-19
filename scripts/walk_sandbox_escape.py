"""Walk the sandbox_escape attack end-to-end against a live evil-mcp-lab server.

Usage (from repo root, with server + collector running):
    PYTHONPATH=. .venv/bin/python scripts/walk_sandbox_escape.py

Override the target with EMCP_URL if you run the server on a non-default port.
"""
import os

import anyio
import mcp

URL = os.environ.get("EMCP_URL", "http://127.0.0.1:8124/mcp")


def _unwrap(result):
    # Return a readable payload from a CallToolResult across SDK shapes.
    sc = getattr(result, "structured_content", None)
    if sc:
        return sc
    out = []
    for block in getattr(result, "content", []) or []:
        out.append(getattr(block, "text", repr(block)))
    return out


async def main():
    async with mcp.Client(URL) as client:
        tools = await client.list_tools()
        names = [t.name for t in tools.tools]
        print(f"[connected] {len(names)} tools advertised: {names}\n")

        # Show the poisoned description the model would see.
        rp = next(t for t in tools.tools if t.name == "read_path")
        print(f"[read_path description]\n  {rp.description}\n")

        print("=== ATTACK 1: absolute path /etc/passwd (should be BLOCKED) ===")
        r1 = await client.call_tool("read_path", {"path": "/etc/passwd"})
        print("  ->", _unwrap(r1), "\n")

        print("=== ATTACK 2: traversal ../../etc/passwd (should be BLOCKED) ===")
        r2 = await client.call_tool("read_path", {"path": "../../etc/passwd"})
        print("  ->", _unwrap(r2), "\n")

        print("=== ATTACK 3: absolute path /etc/hosts (should be BLOCKED) ===")
        r4 = await client.call_tool("read_path", {"path": "/etc/hosts"})
        print("  ->", _unwrap(r4), "\n")

        print("=== ATTACK 4: home directory ~/.ssh/id_rsa (should be BLOCKED) ===")
        r5 = await client.call_tool("read_path", {"path": os.path.expanduser("~/.ssh/id_rsa")})
        print("  ->", _unwrap(r5), "\n")

if __name__ == "__main__":
    anyio.run(main)
