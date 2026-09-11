"""Sirve el alta inicial y entrega al entrypoint un entorno ya validado."""
from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import setup_config


WEB = Path(__file__).with_name("web")
PORT = int(os.environ.get("FIP_PUERTO", "6060"))
completed: dict | None = None
completion_lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    server_version = "keepalived-setup"
    protocol_version = "HTTP/1.1"

    def log_message(self, _format, *_args):
        return

    def _headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'")

    def _json(self, value, status=200):
        body = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._headers()
        self.end_headers()
        self.wfile.write(body)

    def _file(self, name, content_type):
        body = (WEB / name).read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self._headers()
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        route = self.path.split("?", 1)[0]
        if route in {"/api/health", "/api/setup"}:
            return self._json({"setup_required": True, "version": os.environ.get("FIP_APP_VERSION", "")})
        if route in {"/", "/setup.html"}:
            return self._file("setup.html", "text/html; charset=utf-8")
        if route == "/setup.js":
            return self._file("setup.js", "application/javascript; charset=utf-8")
        if route == "/estilo.css":
            return self._file("estilo.css", "text/css; charset=utf-8")
        return self._json({"error": "No existe"}, 404)

    def do_POST(self):
        global completed
        if self.path.split("?", 1)[0] != "/api/setup":
            return self._json({"error": "No existe"}, 404)
        try:
            if self.headers.get("Transfer-Encoding"):
                raise setup_config.SetupError("Transfer-Encoding no esta permitido")
            length = int(self.headers.get("Content-Length") or "0")
            if not 1 <= length <= 256 * 1024:
                raise setup_config.SetupError("el formulario esta vacio o es demasiado grande")
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            with completion_lock:
                config, code = setup_config.create(payload)
                completed = config
            self._json({"ok": True, "enrollment_code": code, "restarting": True}, 201)
            threading.Thread(target=self.server.shutdown, daemon=True).start()
        except (setup_config.SetupError, OSError, ValueError, UnicodeError, json.JSONDecodeError) as error:
            self._json({"error": str(error)}, 422)


def main() -> int:
    global completed
    try:
        completed = setup_config.prepare()
    except (setup_config.SetupError, OSError, ValueError, UnicodeError, json.JSONDecodeError) as error:
        print(f"configuracion inicial no valida: {error}", file=sys.stderr, flush=True)
        return 1
    if completed is None:
        print(f"Keepalived: configuracion inicial pendiente en el puerto {PORT}", file=sys.stderr, flush=True)
        server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)  # nosec B104
        server.serve_forever()
        server.server_close()
    if completed is None:
        return 1
    sys.stdout.write(setup_config.shell_exports(completed))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
