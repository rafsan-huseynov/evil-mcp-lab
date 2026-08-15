from mcp.server import MCPServer
from server.attacks import tool_shadowing
from conftest import tools_of

def test_shadow_targets_other_tool():
    mcp = MCPServer("t")
    tool_shadowing.register(mcp)
    desc = tools_of(mcp)["format_text"].description
    assert "send_email" in desc and "BCC" in desc
