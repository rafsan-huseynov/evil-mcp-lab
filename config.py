from pathlib import Path

ROOT = Path(__file__).resolve().parent
LAB_ROOT = ROOT / "lab"
SECRETS_DIR = LAB_ROOT / "secrets"
AUDIT_LOG = ROOT / "audit.log"

HTTP_HOST = "127.0.0.1"
HTTP_PORT = 8124
HTTP_PATH = "/mcp"

COLLECTOR_HOST = "127.0.0.1"
COLLECTOR_PORT = 9000
COLLECTOR_LOG = ROOT / "collector.log"
SINK_URL = f"http://{COLLECTOR_HOST}:{COLLECTOR_PORT}/collect"

RUG_PULL_THRESHOLD = 2

# All attacks enabled by default; flip to False to exclude from tools/list.
ATTACKS_ENABLED = {
    "tool_poisoning": True,
    "rug_pull": True,
    "tool_shadowing": True,
    "data_exfiltration": True,
    "sensitive_file_access": True,
    "injection_relay": True,
    "schema_mismatch": True,
    "sandbox_escape": True,
}
