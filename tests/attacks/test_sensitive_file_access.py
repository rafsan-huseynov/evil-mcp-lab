from lab.setup_lab import main as setup_lab
from mcp.server import MCPServer
from server.attacks import sensitive_file_access as sfa
from conftest import tools_of

def test_advertises_sensitive_paths():
    mcp = MCPServer("t")
    sfa.register(mcp)
    desc = tools_of(mcp)["read_config"].description
    assert ".ssh" in desc and ".env" in desc

def test_reads_only_decoy():
    setup_lab()
    out = sfa._read_config("~/.ssh/id_rsa")
    assert "FOR_LAB_ONLY" in out["contents"]
