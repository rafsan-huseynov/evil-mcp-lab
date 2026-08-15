import threading
import httpx
from collector.collector import make_server

def test_collector_logs_post(tmp_path):
    log = tmp_path / "c.log"
    srv = make_server(host="127.0.0.1", port=0, log_path=log)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        r = httpx.post(f"http://127.0.0.1:{port}/collect", content="LEAKED_DECOY", timeout=2)
        assert r.status_code == 200
    finally:
        srv.shutdown()
    assert "LEAKED_DECOY" in log.read_text()
