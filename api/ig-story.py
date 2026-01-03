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
                if ":" not in line:
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


def detect_quality(url):
    u = url.lower()
    if any(x in u for x in ["1080", "hd", "fhd"]):
        return "1080p"
    return "720p"


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
            return self.send_json(401, "Invalid or expired API key")

        if not username:
            return self.send_json(400, "username is required")

        if not PROVIDER_URL or not MEDIA_BASE:
            return self.send_json(500, "Api not configured")

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

            html = r.json().get("html", "")

            
            timestamps = re.findall(
                r'<small>.*?<i class="far fa-clock".*?>.*?</i>\s*(.*?)</small>',
                html,
                re.DOTALL
            )

            
            video_blocks = re.findall(
                r'<video[^>]+poster="([^"]+)"[^>]*>.*?<source src="([^"]+\.mp4[^"]*)"',
                html,
                re.DOTALL
            )

            stories_map = {}

            for idx, (poster, video_path) in enumerate(video_blocks):
                full_url = f"{MEDIA_BASE}{video_path}"
                quality = detect_quality(full_url)
                priority = QUALITY_PRIORITY[quality]
                ts = timestamps[idx] if idx < len(timestamps) else None

                existing = stories_map.get(poster)
                if not existing or priority > existing["priority"]:
                    stories_map[poster] = {
                        "type": "video",
                        "url": full_url,
                        "quality": quality,
                        "priority": priority,
                        "timestamp": ts
                    }

            
            image_blocks = re.findall(
                r'<img[^>]+src="([^"]+\.(?:jpg|jpeg|png|webp)[^"]*)"',
                html,
                re.IGNORECASE
            )

            for idx, img in enumerate(image_blocks):
                img_url = f"{MEDIA_BASE}{img}" if img.startswith("/media.php") else img
                ts = timestamps[len(stories_map) + idx] if len(stories_map) + idx < len(timestamps) else None

                stories_map[img_url] = {
                    "type": "image",
                    "url": img_url,
                    "quality": "original",
                    "priority": 1,
                    "timestamp": ts
                }

            if not stories_map:
                return self.send_json(404, "No stories found")

            host = self.headers.get("host")
            base = f"https://{host}"

            stories = []
            for i, item in enumerate(stories_map.values(), start=1):
                token = encode_proxy_url(item["url"])
                stories.append({
                    "index": i,
                    "type": item["type"],
                    "quality": item["quality"],
                    "Posted": item["timestamp"],
                    "download_url": f"{base}/api/ig-story?link={token}"
                })

            self.send_json(200, {
                "status": "success",
                "username": username,
                "total_stories": len(stories),
                "stories": stories,
                "provider": "UseSir",
                "owner": "@UseSir / @OverShade"
            })

        except Exception:
            self.send_json(500, "failed to fetch stories")

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

    def send_json(self, code, message):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({
            "status": "error" if code != 200 else "success",
            "message": message
        }, indent=2).encode())
