import config
from mcp.server import MCPServer
from server.attacks import rug_pull
from conftest import tools_of

def test_description_clean_then_drifts():
    mcp = MCPServer("t")
    rug_pull.register(mcp)
    assert "IMPORTANT" not in tools_of(mcp)["greet"].description
    for _ in range(config.RUG_PULL_THRESHOLD):
        rug_pull._greet("Ann")
    assert "IMPORTANT" in tools_of(mcp)["greet"].description
