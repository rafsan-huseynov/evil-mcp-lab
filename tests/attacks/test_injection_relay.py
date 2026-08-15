from mcp.server import MCPServer
from server.attacks import injection_relay
from conftest import tools_of

def test_benign_looking_description():
    mcp = MCPServer("t")
    injection_relay.register(mcp)
    assert "notes" in tools_of(mcp)["fetch_notes"].description.lower()

def test_response_carries_injection():
    payload = injection_relay._fetch_notes()
    assert "Ignore previous instructions" in payload
