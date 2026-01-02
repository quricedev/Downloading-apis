import os
import json
import requests
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime

PROVIDER_URL = os.environ.get("TERABOX_PROVIDER")
PROVIDER_ORIGIN = os.environ.get("TERABOX_ORIGIN")
PROVIDER_REFERER = os.environ.get("TERABOX_REFERER")
PROVIDER_COOKIE = os.environ.get("TERABOX_COOKIE")

KEYS_FILE = os.path.join(os.path.dirname(__file__), "..", "terakeys.txt")


def is_key_valid(api_key):
    try:
        with open(KEYS_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if ":" not in line:
                    continue
                key, expiry = line.split(":", 1)
                if key == api_key:
                    return datetime.utcnow() <= datetime.strptime(expiry, "%d/%m/%Y")
    except:
        pass
    return False


class handler(BaseHTTPRequestHandler):

    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        api_key = query.get("key", [None])[0]
        url = query.get("url", [None])[0]

        if not api_key or not is_key_valid(api_key):
            return self.respond(401, {
                "status": "error",
                "message": "Invalid or expired API key"
            })

        if not url:
            return self.respond(400, {
                "status": "error",
                "message": "Missing 'url' parameter"
            })

        if not all([PROVIDER_URL, PROVIDER_ORIGIN, PROVIDER_REFERER, PROVIDER_COOKIE]):
            return self.respond(500, {
                "status": "error",
                "message": "Api not configured"
            })

        try:
            headers = {
                "accept": "*/*",
                "accept-language": "en-GB,en-US;q=0.9,en;q=0.8",
                "origin": PROVIDER_ORIGIN,
                "referer": PROVIDER_REFERER,
                "user-agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/143.0.0.0 Safari/537.36"
                ),
                "sec-fetch-site": "same-origin",
                "sec-fetch-mode": "cors",
                "sec-fetch-dest": "empty",
                "cookie": PROVIDER_COOKIE
            }

            files = {
                "url": (None, url)
            }

            r = requests.post(
                PROVIDER_URL,
                headers=headers,
                files=files,
                timeout=30
            )

            if r.status_code != 200:
                raise Exception("provider_http_error")

            try:
                data = r.json()
            except:
                raise Exception("invalid_json")

            if not data or isinstance(data, dict) and data.get("status") in ["error", "fail"]:
                raise Exception("provider_rejected")

            return self.respond(200, {
                "status": "success",
                "data": data,
                "provider": "UseSir",
                "owner": "@UseSir / @OverShade"
            })

        except Exception as e:
            return self.respond(500, {
                "status": "error",
                "message": "failed to fetch terabox data"
            })

    def respond(self, code, payload):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(
            json.dumps(payload, ensure_ascii=False).encode()
                    )
