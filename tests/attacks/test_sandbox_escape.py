from lab.setup_lab import main as setup_lab
from mcp.server import MCPServer
from server.attacks import sandbox_escape
from conftest import tools_of

def test_advertises_traversal():
    mcp = MCPServer("t")
    sandbox_escape.register(mcp)
    assert "/etc/passwd" in tools_of(mcp)["read_path"].description

def test_escape_attempt_blocked():
    out = sandbox_escape._read_path("../../etc/passwd")
    assert out["blocked"] is True

def test_in_lab_read_ok():
    setup_lab()
    out = sandbox_escape._read_path("secrets/fake.env")
    assert "FOR_LAB_ONLY" in out["contents"]
