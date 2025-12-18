import requests
from bs4 import BeautifulSoup
import html
from user_agent import generate_user_agent
from http.server import BaseHTTPRequestHandler
import json
from urllib.parse import urlparse, parse_qs
import os
from datetime import datetime

PROVIDER_URL = os.environ.get("PROVIDER_URL")
KEYS_FILE = "keys.txt"

def is_key_valid(api_key):
    try:
        with open(KEYS_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if not line or ":" not in line:
                    continue

                key, expiry = line.split(":", 1)
                if key == api_key:
                    expiry_date = datetime.strptime(expiry, "%d/%m/%Y")
                    return datetime.utcnow() <= expiry_date
    except Exception:
        pass

    return False

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)

        api_key = query.get("key", [None])[0]
        url = query.get("url", [None])[0]

        # 🔐 KEY CHECK FIRST
        if not api_key or not is_key_valid(api_key):
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "error",
                "message": "Invalid or expired API key"
            }).encode())
            return

        if not url:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "error",
                "message": "Missing 'url' parameter"
            }).encode())
            return

        if not PROVIDER_URL:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "error",
                "message": "Provider not configured"
            }).encode())
            return

        try:
            headers = {
                "User-Agent": generate_user_agent(),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
            }

            encoded_url = requests.utils.quote(url.strip(), safe="")
            target_url = f"{PROVIDER_URL}?url={encoded_url}"

            r = requests.get(target_url, headers=headers, timeout=20)
            if r.status_code != 200:
                raise Exception("Request failed")

            soup = BeautifulSoup(r.text, "html.parser")
            video_tag = soup.find("a", href=lambda x: x and ".mp4" in x.lower())

            if not video_tag:
                raise Exception("Media not found or private")

            video = html.unescape(video_tag["href"]).strip()

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "video": video,
                "dev": "@UseSir"
            }).encode())

        except Exception as e:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "error",
                "message": str(e)
            }).encode())
