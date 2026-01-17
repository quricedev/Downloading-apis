import os
import json
import time
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from openai import OpenAI

client = OpenAI(
    api_key=os.environ.get("DEEPSEEK_API_KEY"),
    OPENAI_BASE_URL=os.environ.get("OPENAI_BASE_URL")
)

MODEL_NAME = os.environ.get("DEEPSEEK_MODEL")

BASE_DIR = os.path.dirname(__file__)
KEYS_FILE = os.path.join(BASE_DIR, "..", "WormGptkeys.txt")
MASTER_KEYS_FILE = os.path.join(BASE_DIR, "..", "masterkeys.txt")

MAX_REQUESTS = 50
WINDOW_SECONDS = 180  

IP_CACHE = {}

KEY_CACHE = set()
LIMITED_KEYS = set()
EXPIRY_MAP = {}


def load_keys():
    try:
        with open(KEYS_FILE) as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) < 2:
                    continue
                key, expiry = parts[0], parts[1]
                KEY_CACHE.add(key)
                EXPIRY_MAP[key] = expiry
                if len(parts) == 3 and parts[2] == "limit":
                    LIMITED_KEYS.add(key)
    except:
        pass

    try:
        with open(MASTER_KEYS_FILE) as f:
            for k in f:
                KEY_CACHE.add(k.strip())
    except:
        pass


load_keys()


def validate_key(api_key, ip):
    if api_key not in KEY_CACHE:
        return False, "API key is invalid or expired"

    if api_key in EXPIRY_MAP:
        if datetime.utcnow() > datetime.strptime(EXPIRY_MAP[api_key], "%d/%m/%Y"):
            return False, "API key is invalid or expired"

    if api_key in LIMITED_KEYS:
        now = int(time.time())
        IP_CACHE.setdefault(api_key, {})
        IP_CACHE[api_key].setdefault(ip, [])

        IP_CACHE[api_key][ip] = [
            t for t in IP_CACHE[api_key][ip]
            if now - t < WINDOW_SECONDS
        ]

        if len(IP_CACHE[api_key][ip]) >= MAX_REQUESTS:
            return False, "IP request limit reached"

        IP_CACHE[api_key][ip].append(now)

    return True, None


class handler(BaseHTTPRequestHandler):

    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)

        api_key = query.get("key", [None])[0]
        text = query.get("text", [None])[0]

        ip = self.headers.get("x-forwarded-for") or self.client_address[0]

        if not api_key:
            return self.error(400, "API key is required")

        valid, msg = validate_key(api_key, ip)
        if not valid:
            return self.error(401, msg)

        if not text:
            return self.error(400, "Missing 'text' parameter")

        try:
            response = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {
                        "role": "system",
                        "content": "you are funny"
                    },
                    {
                        "role": "user",
                        "content": text
                    }
                ],
                stream=False
            )

            answer = response.choices[0].message.content

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "success",
                "query": text,
                "response": answer,
                "owner": "@UseSir / @OverShade"
            }, indent=2).encode())

        except:
            self.error(500, "Failed to generate response")

    def error(self, code, message):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({
            "status": "error",
            "error": {
                "message": message
            },
            "owner": "@UseSir / @OverShade"
        }, indent=2).encode())
