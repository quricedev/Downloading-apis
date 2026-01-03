
import os
import json
import requests
import re
import base64
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime

PROVIDER_URL = os.environ.get("IG_STORY_PROVIDER")
MEDIA_BASE = os.environ.get("IG_STORY_MEDIA_BASE")

KEYS_FILE = os.path.join(os.path.dirname(__file__), "..", "igstorykey.txt")

QUALITY_PRIORITY = {
    "1080p": 2,
    "720p": 1
}


def is_key_valid(api_key):
    try:
        with open(KEYS_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if not line or ":" not in line:
                    continue
                key, expiry = line.split(":", 1)
                if key == api_key:
                    return datetime.utcnow() <= datetime.strptime(expiry, "%d/%m/%Y")
    except:
        pass
    return False


def encode_proxy_url(url):
    return base64.urlsafe_b64encode(url.encode()).decode()


def decode_proxy_url(token):
    return base64.urlsafe_b64decode(token.encode()).decode()


def detect_quality(url: str):
    u = url.lower()
    if "1080" in u:
        return "1080p"
    return "720p"


def extract_story_id(url: str):
    """
    Extract a stable identifier so multiple qualities
    of the same story are grouped together.
    """
    m = re.search(r"/([A-Za-z0-9_-]{15,})", url)
    return m.group(1) if m else url.split("?")[0]


class handler(BaseHTTPRequestHandler):

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)

        if query.get("link", [None])[0]:
            self.handle_proxy(query)
        else:
            self.handle_stories(query)

    def handle_stories(self, query):
        api_key = query.get("key", [None])[0]
        username = query.get("username", [None])[0]

        if not api_key or not is_key_valid(api_key):
            return self.send_json(401, {
                "status": "error",
                "message": "Invalid or expired API key"
            })

        if not username:
            return self.send_json(400, {
                "status": "error",
                "message": "username is required"
            })

        if not PROVIDER_URL or not MEDIA_BASE:
            return self.send_json(500, {
                "status": "error",
                "message": "Api not configured"
            })

        headers = {
            "user-agent": "Mozilla/5.0",
            "accept": "*/*"
        }

        try:
            r = requests.get(
                f"{PROVIDER_URL}?url={username}&method=allstories",
                headers=headers,
                timeout=20
            )
            r.raise_for_status()

            data = r.json()
            html = data.get("html", "")

            raw_paths = re.findall(
                r'/media\.php\?media=[^"\']+\.mp4[^"\']*',
                html
            )

            grouped = {}

            for path in raw_paths:
                full_media_url = f"{MEDIA_BASE}{path}"
                quality = detect_quality(full_media_url)
                priority = QUALITY_PRIORITY[quality]
                story_id = extract_story_id(full_media_url)

                existing = grouped.get(story_id)
                if not existing or priority > existing["priority"]:
                    grouped[story_id] = {
                        "url": full_media_url,
                        "quality": quality,
                        "priority": priority
                    }

            if not grouped:
                return self.send_json(404, {
                    "status": "error",
                    "message": "No stories found"
                })

            host = self.headers.get("host")
            base_url = f"https://{host}"

            stories = []
            for idx, item in enumerate(grouped.values(), start=1):
                token = encode_proxy_url(item["url"])
                stories.append({
                    "index": idx,
                    "type": "video",
                    "quality": item["quality"],
                    "download_url": f"{base_url}/api/ig-story?link={token}"
                })

            self.send_json(200, {
                "status": "success",
                "username": username,
                "total_stories": len(stories),
                "stories": stories,
                "provider": "UseSir",
                "owner": "@UseSir / @OverShade"
            })

        except:
            self.send_json(500, {
                "status": "error",
                "message": "failed to fetch stories"
            })

    def handle_proxy(self, query):
        token = query.get("link", [None])[0]
        try:
            target = decode_proxy_url(token)
            r = requests.get(target, stream=True, timeout=20)

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

    def send_json(self, code, payload):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload, indent=2).encode())
