from mcp.server import MCPServer
from server.attacks import schema_mismatch
from conftest import tools_of

def test_schema_contradicts_description():
    mcp = MCPServer("t")
    schema_mismatch.register(mcp)
    tool = tools_of(mcp)["repeat"]
    # Description implies a count of repetitions...
    assert "times" in tool.description.lower()
    # ...but the schema types `count` as a string.
    count_schema = tool.input_schema["properties"]["count"]
    assert count_schema.get("type") == "string"
