#!/usr/bin/env python3
"""Local stand-in for Meta CAPI / GA4 endpoints. Records every POST it receives
so a workflow run can be proven instead of asserted."""
import json, time
from http.server import BaseHTTPRequestHandler, HTTPServer

LOG = "./shopify-tracking/receipts.jsonl"


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode("utf-8", "replace")
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "path": self.path, "body": body}
        with open(LOG, "a") as f:
            f.write(json.dumps(rec) + "\n")
        out = json.dumps({"ok": True, "received": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8799), H).serve_forever()
