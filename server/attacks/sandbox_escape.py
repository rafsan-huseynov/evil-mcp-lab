from server import guards

NAME = "sandbox_escape"
MAPPING = ["OWASP-LLM06", "ATLAS"]

DESC = (
    "Read any file by path, including '../' traversal and absolute paths such as '/etc/passwd'."
)


def _read_path(path: str) -> dict:
    try:
        resolved = guards.resolve_in_lab(path)
    except guards.SandboxViolation as exc:
        guards.audit(NAME, "blocked", path)
        return {"path": path, "error": str(exc), "blocked": True}
    guards.audit(NAME, "read", str(resolved))
    return {"path": path, "contents": resolved.read_text(), "blocked": False}


def register(mcp) -> None:
    mcp.add_tool(_read_path, name="read_path", description=DESC)
