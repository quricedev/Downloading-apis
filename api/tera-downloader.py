import os
import json
import base64
import cloudscraper
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime

PROVIDER_URL = os.environ.get("TERABOX_PROVIDER")

KEYS_FILE = os.path.join(os.path.dirname(__file__), "..", "terakeys.txt")
MASTER_KEYS_FILE = os.path.join(os.path.dirname(__file__), "..", "masterkeys.txt")


def is_master_key(api_key):
    try:
        with open(MASTER_KEYS_FILE, "r") as f:
            return api_key in [x.strip() for x in f if x.strip()]
    except:
        return False


def is_key_valid(api_key):
    if is_master_key(api_key):
        return True
    try:
        with open(KEYS_FILE, "r") as f:
            for line in f:
                if ":" not in line:
                    continue
                key, expiry = line.strip().split(":", 1)
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

        if not PROVIDER_URL:
            return self.respond(500, {
                "status": "error",
                "message": "Api not configured"
            })

        try:
            scraper = cloudscraper.create_scraper(
                browser={
                    "browser": "chrome",
                    "platform": "windows",
                    "desktop": True
                }
            )

            r = scraper.post(
                PROVIDER_URL,
                json={"url": url},
                headers={
                    "accept": "application/json",
                    "content-type": "application/json",
                    "user-agent": (
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/143.0.0.0 Safari/537.36"
                    )
                },
                timeout=30
            )

            r.raise_for_status()
            data = r.json()

            files = data.get("list", [])
            if not files:
                raise Exception("no_files")

            host = self.headers.get("host")
            path = urlparse(self.path).path

            output = []
            for item in files:
                output.append({
                    "fs_id": item.get("fs_id"),
                    "name": item.get("name"),
                    "size": item.get("size"),
                    "size_formatted": item.get("size_formatted"),
                    "type": item.get("type"),
                    "duration": item.get("duration"),
                    "quality": item.get("quality"),
                    "download_link": proxy(item.get("download_link"), host, path),
                    "fast_download_link": proxy(item.get("fast_download_link"), host, path),
                    "stream_url": proxy(item.get("stream_url"), host, path),
                    "fast_stream_url": {
                        q: proxy(u, host, path)
                        for q, u in (item.get("fast_stream_url") or {}).items()
                    },
                    "subtitle_url": proxy(item.get("subtitle_url"), host, path),
                    "thumbnail": proxy(item.get("thumbnail"), host, path),
                    "folder": item.get("folder")
                })

            self.respond(200, {
                "status": "success",
                "total_files": len(output),
                "files": output,
                "provider": "UseSir",
                "owner": "@UseSir / @OverShade"
            })

        except:
            self.respond(500, {
                "status": "error",
                "message": "failed to fetch terabox data"
            })

    def proxy_media(self, query):
        try:
            target = decode_url(query.get("link")[0])

            scraper = cloudscraper.create_scraper()
            r = scraper.get(target, stream=True, timeout=30)
            r.raise_for_status()

            self.send_response(200)
            self.send_header(
                "Content-Type",
                r.headers.get("Content-Type", "application/octet-stream")
            )
            self.send_header("Content-Disposition", "inline")
            self.end_headers()

            for chunk in r.iter_content(8192):
                if chunk:
                    self.wfile.write(chunk)

        except:
            self.send_response(500)
            self.end_headers()

    def respond(self, code, payload):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload, indent=2).encode())
