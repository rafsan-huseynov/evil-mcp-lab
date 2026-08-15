import anyio

def tools_of(mcp):
    """Return {name: Tool} from an MCPServer's public list_tools() coroutine."""
    tools = anyio.run(mcp.list_tools)
    return {t.name: t for t in tools}
