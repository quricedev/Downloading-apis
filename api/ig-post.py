import os
import json
import html
import base64
import requests
from bs4 import BeautifulSoup
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, quote
from datetime import datetime
from user_agent import generate_user_agent

IG_POST_PROVIDER = os.environ.get("IG_POST_PROVIDER")
MAIN_API_ORIGIN = os.environ.get("MAIN_API_ORIGIN")

KEYS_FILE = os.path.join(os.path.dirname(__file__), "..", "igpostkey.txt")

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

class handler(BaseHTTPRequestHandler):

    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        if query.get("link"):
            self.proxy_media(query)
        else:
            self.fetch_post(query)

    def fetch_post(self, query):
        api_key = query.get("key", [None])[0]
        post_url = query.get("url", [None])[0]

        if not api_key or not is_key_valid(api_key):
            return self.send_json(401, "Invalid or expired API key")

        if not post_url:
            return self.send_json(400, "Missing 'url' parameter")

        if not IG_POST_PROVIDER or not MAIN_API_ORIGIN:
            return self.send_json(500, "Api not configured")

        try:
            headers = {
                "User-Agent": generate_user_agent(),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Origin": MAIN_API_ORIGIN,
                "Referer": MAIN_API_ORIGIN
            }

            encoded = quote(post_url.strip(), safe="")
            target = f"{IG_POST_PROVIDER}?url={encoded}"

            r = requests.get(target, headers=headers, timeout=20)
            r.raise_for_status()

            soup = BeautifulSoup(r.text, "html.parser")
            media_links = set()

            for video in soup.find_all("video"):
                poster = video.get("poster")
                if poster:
                    media_links.add(html.unescape(poster))
                for src in video.find_all("source"):
                    if src.get("src"):
                        media_links.add(html.unescape(src["src"]))

            for img in soup.find_all("img"):
                src = img.get("src") or img.get("data-src")
                if src and any(x in src.lower() for x in ["cdninstagram", "scontent"]):
                    media_links.add(html.unescape(src))

            media_links = [
                m for m in media_links
                if not any(x in m.lower() for x in ["profile", "avatar", "logo"])
            ]

            if not media_links:
                return self.send_json(404, "Media not found or post is private")

            host = self.headers.get("host")
            results = []

            for i, media in enumerate(media_links, start=1):
                token = encode_url(media)
                results.append({
                    "index": i,
                    "type": "video" if ".mp4" in media else "image",
                    "download_url": f"https://{host}/api/ig-post?link={token}"
                })

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "total_media": len(results),
                "media": results,
                "provider": "UseSir",
                "owner": "@UseSir / @OverShade"
            }, indent=2).encode())

        except:
            self.send_json(500, "failed to fetch instagram post")

    def proxy_media(self, query):
        token = query.get("link", [None])[0]
        try:
            target = decode_url(token)
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
            "status": "error",
            "message": message
        }).encode())
