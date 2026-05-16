from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import urllib.request
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler, HTTPServer


AGENTSHIELD_SECRET = os.environ.get("AGENTSHIELD_WEBHOOK_SECRET", "")
WORKSPACE_ID = os.environ["SENTINEL_WORKSPACE_ID"]
SHARED_KEY = os.environ["SENTINEL_SHARED_KEY"]
LOG_TYPE = os.environ.get("SENTINEL_LOG_TYPE", "AgentShieldAudit")


class SentinelReceiver(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        payload = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        signature = self.headers.get("X-AgentShield-Signature")
        if AGENTSHIELD_SECRET and not _valid_signature(payload, signature):
            self.send_response(401)
            self.end_headers()
            return

        body = json.dumps([json.loads(payload.decode("utf-8"))]).encode("utf-8")
        date = formatdate(timeval=None, localtime=False, usegmt=True)
        sentinel_signature = _sentinel_signature(
            "POST", len(body), "application/json", date, "/api/logs"
        )
        request = urllib.request.Request(
            f"https://{WORKSPACE_ID}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01",
            data=body,
            headers={
                "Authorization": f"SharedKey {WORKSPACE_ID}:{sentinel_signature}",
                "Content-Type": "application/json",
                "Log-Type": LOG_TYPE,
                "x-ms-date": date,
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


def _sentinel_signature(
    method: str, content_length: int, content_type: str, date: str, resource: str
) -> str:
    string_to_hash = f"{method}\n{content_length}\n{content_type}\nx-ms-date:{date}\n{resource}"
    decoded_key = base64.b64decode(SHARED_KEY)
    encoded_hash = hmac.new(
        decoded_key, string_to_hash.encode("utf-8"), hashlib.sha256
    ).digest()
    return base64.b64encode(encoded_hash).decode("utf-8")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    HTTPServer(("0.0.0.0", port), SentinelReceiver).serve_forever()
