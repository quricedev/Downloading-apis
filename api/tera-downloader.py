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

KEYS_FILE = os.path.join(os.path.dirname(__file__), "..", "teraboxkey.txt")

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

        if not PROVIDER_URL or not PROVIDER_ORIGIN or not PROVIDER_REFERER or not PROVIDER_COOKIE:
            return self.respond(500, {
                "status": "error",
                "message": "Api not configured"
            })

        try:
            headers = {
                "accept": "*/*",
                "accept-encoding": "gzip, deflate, br, zstd",
                "accept-language": "en-GB,en-US;q=0.9,en;q=0.8",
                "origin": PROVIDER_ORIGIN,
                "referer": PROVIDER_REFERER,
                "user-agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/143.0.0.0 Safari/537.36"
                ),
                "sec-ch-ua": "\"Google Chrome\";v=\"143\", \"Chromium\";v=\"143\", \"Not A(Brand\";v=\"24\"",
                "sec-ch-ua-arch": "\"x86\"",
                "sec-ch-ua-bitness": "\"64\"",
                "sec-ch-ua-full-version": "\"143.0.7499.170\"",
                "sec-ch-ua-full-version-list": (
                    "\"Google Chrome\";v=\"143.0.7499.170\", "
                    "\"Chromium\";v=\"143.0.7499.170\", "
                    "\"Not A(Brand\";v=\"24.0.0.0\""
                ),
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-model": "\"\"",
                "sec-ch-ua-platform": "\"Windows\"",
                "sec-ch-ua-platform-version": "\"10.0.0\"",
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
                "priority": "u=1, i",
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

            r.raise_for_status()
            data = r.json()

            self.respond(200, {
                "status": "success",
                "data": data,
                "provider": "UseSir",
                "owner": "@UseSir / @OverShade"
            })

        except:
            self.respond(500, {
                "status": "error",
                "message": "failed to fetch terabox data"
            })

    def respond(self, code, payload):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload, ensure_ascii=False, indent=2).encode())
