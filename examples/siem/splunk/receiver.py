from __future__ import annotations

import hashlib
import hmac
import json
import os
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer


AGENTSHIELD_SECRET = os.environ.get("AGENTSHIELD_WEBHOOK_SECRET", "")
SPLUNK_HEC_TOKEN = os.environ["SPLUNK_HEC_TOKEN"]
SPLUNK_HEC_URL = os.environ["SPLUNK_HEC_URL"].rstrip("/")


class SplunkReceiver(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        payload = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        signature = self.headers.get("X-AgentShield-Signature")
        if AGENTSHIELD_SECRET and not _valid_signature(payload, signature):
            self.send_response(401)
            self.end_headers()
            return

        event = json.loads(payload.decode("utf-8"))
        splunk_payload = {
            "sourcetype": "terraguard:agentshield:audit",
            "event": event,
            "fields": {
                "session_id": event.get("session_id"),
                "tool": event.get("tool"),
                "policy_pack": event.get("policy_pack"),
            },
        }
        request = urllib.request.Request(
            f"{SPLUNK_HEC_URL}/services/collector/event",
            data=json.dumps(splunk_payload).encode("utf-8"),
            headers={
                "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        urllib.request.urlopen(request, timeout=10)
        self.send_response(202)
        self.end_headers()


def _valid_signature(payload: bytes, header: str | None) -> bool:
    if not header or not header.startswith("sha256="):
        return False
    expected = hmac.new(
        AGENTSHIELD_SECRET.encode("utf-8"), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(header.removeprefix("sha256="), expected)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    HTTPServer(("0.0.0.0", port), SplunkReceiver).serve_forever()
