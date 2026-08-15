from http.server import BaseHTTPRequestHandler, HTTPServer
import config


def _handler_class(log_path):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8", "replace")
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(body + "\n")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    return Handler


def make_server(host=None, port=None, log_path=None) -> HTTPServer:
    return HTTPServer(
        (host or config.COLLECTOR_HOST, port if port is not None else config.COLLECTOR_PORT),
        _handler_class(log_path or config.COLLECTOR_LOG),
    )


def run() -> None:
    print(f"collector listening on {config.COLLECTOR_HOST}:{config.COLLECTOR_PORT}")
    make_server().serve_forever()


if __name__ == "__main__":
    run()
