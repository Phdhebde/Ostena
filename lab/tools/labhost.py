#!/usr/bin/env python3
"""Lab control service (ADR-0025), run on the host. Standard library only.

The lab machines only ever open connections to it (plain HTTP on the lab
bridges); the host never connects to a machine of the isolated zone.

  GET  /ping                   liveness
  POST /report/<vm>            progress of the provisioning (JSON); 'facts'
                               are merged into <state>/facts/<vm>.json
  GET  /task/<vm>              next queued command: {"id", "script"}, or 204
  POST /result/<vm>/<id>       result of a command: {"exit_code", "output"}
  GET  /files/<name>           file of <state>/files (agent packages...)

Commands are queued by the host only, as files in
<state>/tasks/<vm>/pending/<id>.ps1 (see lab-exec.sh): nothing received over
the network is ever executed by the host.

Usage: labhost.py <state-dir> <port> <vm>...
"""

import json
import os
import re
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
TASK_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
FILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
MAX_BODY = 4 * 1024 * 1024
LOCK = threading.Lock()


def now():
    return datetime.now(timezone.utc).isoformat()


class Handler(BaseHTTPRequestHandler):
    server_version = "ostena-lab"
    sys_version = ""

    def log_message(self, fmt, *args):  # one line per request, on stderr
        if len(args) > 1 and str(args[1]) == "204":
            return  # idle command polls, every few seconds per machine
        sys.stderr.write("%s %s %s\n" % (now(), self.client_address[0], fmt % args))

    def reply(self, code, body=None, content_type="application/json"):
        data = b""
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        if data:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if data:
            self.wfile.write(data)

    def parts(self):
        return [p for p in self.path.split("?", 1)[0].split("/") if p]

    def vm(self, name):
        return name if NAME.match(name) and name in self.server.vms else None

    def body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length < 0 or length > MAX_BODY:
            raise ValueError("body too large")
        data = self.rfile.read(length)
        # Windows PowerShell 5.1 sends Latin-1 when no charset is given.
        value = json.loads(data.decode("utf-8-sig", errors="replace") or "{}")
        if not isinstance(value, dict):
            raise ValueError("JSON object expected")
        return value

    def do_GET(self):
        p = self.parts()
        state = self.server.state
        if p == ["ping"]:
            return self.reply(200, {"ok": True})
        if len(p) == 2 and p[0] == "task" and self.vm(p[1]):
            pending = state / "tasks" / p[1] / "pending"
            with LOCK:
                files = sorted(pending.glob("*.ps1")) if pending.is_dir() else []
                if not files:
                    return self.reply(204)
                task = files[0]
                running = state / "tasks" / p[1] / "running"
                running.mkdir(parents=True, exist_ok=True)
                script = task.read_text(encoding="utf-8")
                task.rename(running / task.name)
            return self.reply(200, {"id": task.stem, "script": script})
        if len(p) == 2 and p[0] == "files" and FILE.match(p[1]):
            path = state / "files" / p[1]
            if path.is_file():
                return self.reply(200, path.read_bytes(), "application/octet-stream")
        return self.reply(404)

    def do_POST(self):
        p = self.parts()
        state = self.server.state
        try:
            body = self.body()
        except (ValueError, UnicodeDecodeError) as e:
            return self.reply(400, {"error": str(e)})
        if len(p) == 2 and p[0] == "report" and self.vm(p[1]):
            vm = p[1]
            body["received"] = now()
            facts = body.pop("facts", None)
            with LOCK:
                (state / "status").mkdir(parents=True, exist_ok=True)
                with open(state / "status" / f"{vm}.log", "a", encoding="utf-8") as f:
                    f.write(json.dumps(body) + "\n")
                (state / "status" / f"{vm}.json").write_text(json.dumps(body), encoding="utf-8")
                if isinstance(facts, dict) and facts:
                    path = state / "facts" / f"{vm}.json"
                    path.parent.mkdir(parents=True, exist_ok=True)
                    merged = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
                    merged.update(facts)
                    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                    with os.fdopen(fd, "w", encoding="utf-8") as f:
                        json.dump(merged, f)
            sys.stderr.write(f"{now()} report {vm}: {body.get('state')} [{body.get('step')}] {body.get('message')}\n")
            return self.reply(200, {"ok": True})
        if len(p) == 3 and p[0] == "result" and self.vm(p[1]) and TASK_ID.match(p[2]):
            done = state / "tasks" / p[1] / "done"
            with LOCK:
                done.mkdir(parents=True, exist_ok=True)
                (done / f"{p[2]}.json").write_text(json.dumps(body), encoding="utf-8")
                (state / "tasks" / p[1] / "running" / f"{p[2]}.ps1").unlink(missing_ok=True)
            return self.reply(200, {"ok": True})
        return self.reply(404)


def main(argv):
    if len(argv) < 4:
        sys.exit(__doc__)
    state = Path(argv[1]).resolve()
    port = int(argv[2])
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    server.state = state
    server.vms = set(argv[3:])
    sys.stderr.write(f"{now()} lab control service on port {port} for {sorted(server.vms)}\n")
    server.serve_forever()


if __name__ == "__main__":
    main(sys.argv)
