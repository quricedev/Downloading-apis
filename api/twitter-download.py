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

PROVIDER_URL = os.environ.get("TWITTER_PROVIDER")
KEYS_FILE = os.path.join(os.path.dirname(__file__), "..", "twitterapikey.txt")

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

def encode_url(url):
    return base64.urlsafe_b64encode(url.encode()).decode()

def decode_url(token):
    return base64.urlsafe_b64decode(token.encode()).decode()

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)

        if query.get("link", [None])[0]:
            self.handle_proxy(query)
        else:
            self.handle_download(query)

    def handle_download(self, query):
        api_key = query.get("key", [None])[0]
        url = query.get("url", [None])[0]

        if not api_key or not is_key_valid(api_key):
            self.send_json(401, {
                "status": "error",
                "message": "Invalid or expired API key"
            })
            return

        if not url:
            self.send_json(400, {
                "status": "error",
                "message": "Missing 'url' parameter"
            })
            return

        if not PROVIDER_URL:
            self.send_json(500, {
                "status": "error",
                "message": "Api not configured"
            })
            return

        try:
            headers = {
                "User-Agent": generate_user_agent(),
                "Accept": "*/*",
                "Accept-Language": "en-US,en;q=0.9"
            }

            encoded_url = quote(url.strip(), safe="")
            target_url = f"{PROVIDER_URL}?url={encoded_url}"

            r = requests.get(target_url, headers=headers, timeout=20)
            r.raise_for_status()

            soup = BeautifulSoup(r.text, "html.parser")

            videos = []
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if href.lower().endswith(".mp4"):
                    videos.append(html.unescape(href))

            if not videos:
                self.send_json(404, {
                    "status": "error",
                    "message": "Video not found or tweet is private"
                })
                return

            best_video = videos[-1]

            token = encode_url(best_video)

            host = self.headers.get("host")
            base_url = f"https://{host}"

            self.send_json(200, {
                "status": "success",
                "download_url": f"{base_url}/api/twitter-download?link={token}",
                "quality": "highest",
                "provider": "UseSir",
                "owner": "@UseSir / @OverShade"
            })

        except:
            self.send_json(500, {
                "status": "error",
                "message": "failed to fetch twitter video"
            })

    def handle_proxy(self, query):
        token = query.get("link", [None])[0]

        if not token:
            self.send_response(400)
            self.end_headers()
            return

        try:
            target = decode_url(token)
            r = requests.get(target, stream=True, timeout=20)

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
        self.wfile.write(json.dumps(payload, indent=2).encode())
