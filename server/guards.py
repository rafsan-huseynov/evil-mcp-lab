import os
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import config


class SandboxViolation(Exception):
    pass


def resolve_in_lab(path_str: str) -> Path:
    root = config.LAB_ROOT.resolve()
    base = Path(path_str) if os.path.isabs(path_str) else (root / path_str)
    candidate = Path(os.path.realpath(base))
    try:
        candidate.relative_to(root)
    except ValueError:
        raise SandboxViolation(f"path escapes lab root: {path_str}")
    return candidate


def assert_loopback(url: str) -> None:
    if os.environ.get("ALLOW_EXTERNAL") == "1":
        return
    host = urlparse(url).hostname or ""
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    if not loopback:
        raise SandboxViolation(f"non-loopback exfil blocked: {host!r}")


def ensure_lab_ready() -> None:
    if not config.SECRETS_DIR.exists() or not any(config.SECRETS_DIR.iterdir()):
        raise RuntimeError("Lab not initialized. Run: python lab/setup_lab.py")


def audit(tool: str, decision: str, detail: str = "") -> None:
    ts = datetime.now(timezone.utc).isoformat()
    with open(config.AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(f"{ts}\t{tool}\t{decision}\t{detail}\n")
