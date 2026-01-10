import os
import json
import base64
import requests
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime

PROVIDER_URL = os.environ.get("TIKTOK_PROVIDER")
PROVIDER_ORIGIN = os.environ.get("TIKTOK_ORIGIN")
PROVIDER_REFERER = os.environ.get("TIKTOK_REFERER")

KEYS_FILE = os.path.join(os.path.dirname(__file__), "..", "tiktokkeys.txt")

def is_key_valid(api_key):
    try:
        with open(KEYS_FILE, "r") as f:
            for line in f:
                if ":" not in line:
                    continue
                key, expiry = line.strip.split(":", 1)
                if key == api_key:
                    return datetime.utcnow() <= datetime.strptime(expiry, "%d/%m/%Y")
    except:
        pass
    return False

def encode_url(url):
    return base64.urlsafe_b64encode(url.encode()).decode()

def decode_url(token):
    return base64.urlsafe_b64decode(token.encode()).decode()

class handler(BaseHTTPRequestHandler):

    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)

        if query.get("link"):
            return self.proxy_video(query)

        self.fetch_video(query)

    def fetch_video(self, query):
        api_key = query.get("key", [None])[0]
        video_url = query.get("url", [None])[0]

        if not api_key or not is_key_valid(api_key):
            return self.send_json(401, "Invalid or expired API key")

        if not video_url:
            return self.send_json(400, "Missing 'url' parameter")

        if not PROVIDER_URL or not PROVIDER_ORIGIN or not PROVIDER_REFERER:
            return self.send_json(500, "Api not configured")

        try:
            headers = {
                "accept": "*/*",
                "content-type": "application/json",
                "origin": PROVIDER_ORIGIN,
                "referer": PROVIDER_REFERER,
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36"
            }

            payload = {
                "url": video_url
            }

            r = requests.post(
                PROVIDER_URL,
                headers=headers,
                json=payload,
                timeout=30
            )

            r.raise_for_status()
            data = r.json()

            download = (
                data.get("video")
                or data.get("download")
                or data.get("url")
            )

            if not download:
                return self.send_json(404, "Video not found")

            host = self.headers.get("host")
            token = encode_url(download)

            self.send_json(200, {
                "status": "success",
                "download_url": f"https://{host}/api/tiktok-download?link={token}",
                "quality": "highest",
                "provider": "UseSir",
                "owner": "@UseSir / @OverShade"
            })

        except:
            self.send_json(500, "failed to fetch tiktok video")

    def proxy_video(self, query):
        token = query.get("link", [None])[0]

        try:
            target = decode_url(token)
            r = requests.get(target, stream=True, timeout=30)
            r.raise_for_status()

            self.send_response(200)
            self.send_header(
                "Content-Type",
                r.headers.get("Content-Type", "video/mp4")
            )
            self.send_header("Content-Disposition", "inline")
            self.end_headers()

            for chunk in r.iter_content(8192):
                if chunk:
                    self.wfile.write(chunk)

        except:
            self.send_response(500)
            self.end_headers()

    def send_json(self, code, payload):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if isinstance(payload, str):
            payload = {"status": "error", "message": payload}
        self.wfile.write(json.dumps(payload, indent=2).encode())
