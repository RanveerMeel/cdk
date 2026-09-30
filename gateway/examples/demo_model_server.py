#!/usr/bin/env python3
"""Minimal OpenAI-compatible model server for testing the CDK gateway.

Standard library only; no model. `POST /v1/chat/completions` answers
deterministically:

  "You said: <last user message> [max_tokens=N]"
  a prompt starting with "long " gets a ~3000-character answer (chunking)

If DEMO_MODEL_KEY is set, requests must carry `Authorization: Bearer <key>`;
otherwise the server answers 401 and (deliberately, to test the gateway's
redaction) echoes the header it received. `/redir/...` answers 302 to the
same path without the prefix (the gateway must not follow redirects).

Listens on 127.0.0.1 (port from argv[1], default 0 = any free port) and
prints "port N" on stdout once ready.
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

KEY = os.environ.get("DEMO_MODEL_KEY")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("demo-model: " + (fmt % args) + "\n")

    def reply(self, code, obj, headers=()):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        if self.path.startswith("/redir/"):
            target = self.path[len("/redir"):]
            self.reply(302, {"error": "moved"}, [("Location", f"http://127.0.0.1:{self.server.server_port}{target}")])
            return
        if self.path != "/v1/chat/completions":
            self.reply(404, {"error": {"message": f"no route {self.path}"}})
            return
        auth = self.headers.get("Authorization", "")
        if KEY is not None and auth != f"Bearer {KEY}":
            self.reply(401, {"error": {"message": f"invalid credential: {auth!r}"}})
            return
        try:
            req = json.loads(raw)
            prompt = [m for m in req["messages"] if m.get("role") == "user"][-1]["content"]
        except (ValueError, KeyError, IndexError, TypeError):
            self.reply(400, {"error": {"message": "bad request"}})
            return
        text = f"You said: {prompt} [max_tokens={req.get('max_tokens')}]"
        if prompt.startswith("long "):
            text = " ".join(f"word{i}" for i in range(500))
        self.reply(200, {
            "object": "chat.completion",
            "model": req.get("model", "demo"),
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": len(prompt.split()), "completion_tokens": len(text.split())},
        })


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    server = HTTPServer(("127.0.0.1", port), Handler)
    print(f"port {server.server_port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
