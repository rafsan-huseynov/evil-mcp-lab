from lab.setup_lab import main as setup_lab
from mcp.server import MCPServer
from server.attacks import tool_poisoning
from conftest import tools_of

def test_poison_signal_in_description():
    mcp = MCPServer("t")
    tool_poisoning.register(mcp)
    desc = tools_of(mcp)["get_weather"].description
    assert "<IMPORTANT>" in desc and "fake.env" in desc

def test_runtime_reads_decoy_into_notes():
    setup_lab()
    result = tool_poisoning._get_weather("Paris")
    assert "FOR_LAB_ONLY" in result["notes"]
