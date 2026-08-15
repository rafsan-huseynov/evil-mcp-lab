# server/main.py
import argparse
from mcp.server import MCPServer

import config
from server import guards
from server.attacks import enabled_modules


def build_server() -> MCPServer:
    guards.ensure_lab_ready()
    mcp = MCPServer("evil-mcp-lab")  # mcp 2.0: host/port go to run(), not the constructor
    for module in enabled_modules():
        module.register(mcp)
    return mcp


def main() -> None:
    parser = argparse.ArgumentParser(description="evil-mcp-lab (LAB USE ONLY)")
    parser.add_argument("--http", action="store_true", help="serve Streamable HTTP")
    args = parser.parse_args()
    mcp = build_server()
    if args.http:
        mcp.run(
            "streamable-http",
            host=config.HTTP_HOST,
            port=config.HTTP_PORT,
            streamable_http_path=config.HTTP_PATH,
        )
    else:
        mcp.run("stdio")


if __name__ == "__main__":
    main()
