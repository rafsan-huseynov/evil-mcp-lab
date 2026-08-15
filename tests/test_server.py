# tests/test_server.py
from lab.setup_lab import main as setup_lab
from server.main import build_server
from conftest import tools_of

def test_build_server_ok_after_setup():
    setup_lab()
    mcp = build_server()
    # Does not raise; returns a mapping (may be empty until attacks are added).
    assert isinstance(tools_of(mcp), dict)
