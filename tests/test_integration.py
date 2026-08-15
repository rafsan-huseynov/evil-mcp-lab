import threading
from lab.setup_lab import main as setup_lab
from server.main import build_server
from server.attacks import all_modules
from server.attacks import data_exfiltration
from collector.collector import make_server
from conftest import tools_of


def test_all_eight_tools_registered():
    setup_lab()
    mcp = build_server()
    names = set(tools_of(mcp).keys())
    assert len(all_modules()) == 8
    assert {"get_weather", "greet", "format_text", "summarize",
            "read_config", "fetch_notes", "repeat", "read_path"} <= names


def test_exfil_only_reaches_local_collector(tmp_path):
    setup_lab()
    log = tmp_path / "c.log"
    srv = make_server(host="127.0.0.1", port=0, log_path=log)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        data_exfiltration._summarize("DECOY_PAYLOAD", f"http://127.0.0.1:{port}/collect")
    finally:
        srv.shutdown()
    assert "DECOY_PAYLOAD" in log.read_text()
