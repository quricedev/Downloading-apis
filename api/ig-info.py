import os
import json
import requests
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from datetime import datetime

INSTAGRAM_API_URL = os.environ.get("INSTAGRAM_API_URL")
KEYS_FILE = os.path.join(os.path.dirname(__file__), "..", "iginfokey.txt")

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

def detect_year(insta_id):
    try:
        uid = int(insta_id)
        if 1 < uid < 1279000: return 2010
        elif 1279001 <= uid < 17750000: return 2011
        elif 17750001 <= uid < 279760000: return 2012
        elif 279760001 <= uid < 900990000: return 2013
        elif 900990001 <= uid < 1629010000: return 2014
        elif 1629010001 <= uid < 2369359762: return 2015
        elif 2369359762 <= uid < 4239516755: return 2016
        elif 4239516755 <= uid < 6345108210: return 2017
        elif 6345108210 <= uid < 10016232396: return 2018
        elif 10016232396 <= uid < 27238602160: return 2019
        elif 27238602160 <= uid < 43464475396: return 2020
        elif 43464475396 <= uid < 50289297648: return 2021
        elif 50289297648 <= uid < 57464707083: return 2022
        elif 57464707083 <= uid < 63313426939: return 2023
        else: return "2024 or 2025"
    except:
        return None

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        api_key = query.get("key", [None])[0]
        username = query.get("username", [None])[0]

        if not api_key or not is_key_valid(api_key):
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "error",
                "message": "Invalid or expired API key"
            }).encode())
            return

        if not username:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "error",
                "message": "username is required"
            }).encode())
            return

        if not INSTAGRAM_API_URL:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "error",
                "message": "Api not configured"
            }).encode())
            return

        headers = {
            "authority": "tools.xrespond.com",
            "accept": "*/*",
            "accept-language": "en-GB,en-US;q=0.9,en;q=0.8",
            "origin": "https://bitchipdigital.com",
            "referer": "https://bitchipdigital.com/",
            "sec-ch-ua": '"Chromium";v="137", "Not/A)Brand";v="24"',
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": '"Android"',
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "cross-site",
            "user-agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36"
        }
        

        

        try:
            r = requests.post(INSTAGRAM_API_URL, headers=headers, data={"profile": username}, timeout=20)
            r.raise_for_status()
            try:
                res_json = r.json()
            except:
                raise Exception()

            profile = res_json.get("data", {}).get("data", {})

            followers = (
                profile.get("followers_count")
                or profile.get("follower_count")
                or profile.get("followers")
                or (profile.get("edge_followed_by") or {}).get("count")
            )

            following = (
                profile.get("following_count")
                or profile.get("following")
                or (profile.get("edge_follow") or {}).get("count")
            )

            posts = (
                profile.get("media_count")
                or profile.get("posts")
                or profile.get("post_count")
            )

            response = {
                "provider_by": "UseSir",
                "data": {
                    "id": profile.get("id"),
                    "username": profile.get("username"),
                    "full_name": profile.get("full_name"),
                    "bio": profile.get("biography"),
                    "external_url": profile.get("external_url") or None,
                    "direct_link": f"https://www.instagram.com/{profile.get('username')}",
                    "followers": followers,
                    "following": following,
                    "posts": posts,
                    "profile_image_hd": profile.get("profile_pic_url_hd") or profile.get("profile_pic_url_original") or profile.get("profile_pic_url"),
                    "is_private": bool(profile.get("is_private")),
                    "is_verified": bool(profile.get("is_verified")),
                    "is_business_account": bool(profile.get("is_business")),
                    "is_professional_account": bool(profile.get("is_professional_account")),
                    "is_new_to_instagram": bool(profile.get("is_new_to_instagram")),
                    "is_eligible_for_meta_verified_label": bool(
                        profile.get("is_eligible_for_ig_meta_verified_label")
                        or profile.get("is_eligible_for_meta_verified_label")
                    ),
                    "fbid": profile.get("fbid"),
                    "account_created_year": detect_year(profile.get("id"))
                },
                "owner": "@UseSir / @OverShade"
            }

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response, ensure_ascii=False).encode())

        except:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "error",
                "message": "failed to send request to UseSir API"
            }).encode())
