import os
import json
import base64
import requests
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime

PROVIDER_URL = os.environ.get("TIKTOK_PROVIDER")

KEYS_FILE = os.path.join(os.path.dirname(__file__), "..", "tiktokkeys.txt")


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


def encode_url(url):
    return base64.urlsafe_b64encode(url.encode()).decode()


def decode_url(token):
    return base64.urlsafe_b64decode(token.encode()).decode()


def proxy(url, host, path):
    if not url:
        return None
    return f"https://{host}{path}?link={encode_url(url)}"


class handler(BaseHTTPRequestHandler):

    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)

        if query.get("link"):
            return self.proxy_media(query)

        self.fetch_video(query)

    def fetch_video(self, query):
        api_key = query.get("key", [None])[0]
        video_url = query.get("url", [None])[0]

        if not api_key or not is_key_valid(api_key):
            return self.send_json(401, "Invalid or expired API key")

        if not video_url:
            return self.send_json(400, "Missing 'url' parameter")

        if not PROVIDER_URL:
            return self.send_json(500, "Api not configured")

        try:
            headers = {
                "accept": "*/*",
                "content-type": "application/json",
                "user-agent": "Mozilla/5.0"
            }

            payload = {"url": video_url}

            r = requests.post(
                PROVIDER_URL,
                headers=headers,
                json=payload,
                timeout=30
            )

            r.raise_for_status()
            data = r.json()

            media = data.get("mediaUrl")
            if not media:
                return self.send_json(404, "Video not found")

            host = self.headers.get("host")
            path = urlparse(self.path).path

            response = {
                "status": "success",
                "id": data.get("id"),
                "username": data.get("username"),
                "caption": data.get("caption"),
                "stats": data.get("stats"),
                "video": {
                    "download_url": proxy(media, host, path),
                    "quality": "highest"
                },
                "thumbnail": proxy(data.get("thumbnail"), host, path),
                "author": {
                    "id": data.get("authorInfo", {}).get("id"),
                    "username": data.get("authorInfo", {}).get("username"),
                    "nickname": data.get("authorInfo", {}).get("nickname"),
                    "avatar": proxy(
                        data.get("authorInfo", {}).get("avatar"),
                        host,
                        path
                    )
                },
                "music": {
                    "id": data.get("musicInfo", {}).get("id"),
                    "title": data.get("musicInfo", {}).get("title"),
                    "author": data.get("musicInfo", {}).get("author"),
                    "duration": data.get("musicInfo", {}).get("duration"),
                    "cover": proxy(
                        data.get("musicInfo", {}).get("cover"),
                        host,
                        path
                    )
                },
                "provider": "UseSir",
                "owner": "@UseSir / @OverShade"
            }

            self.send_json(200, response)

        except Exception:
            self.send_json(500, "failed to fetch tiktok video")

    def proxy_media(self, query):
        try:
            target = decode_url(query.get("link")[0])
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
