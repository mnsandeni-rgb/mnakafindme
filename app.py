#!/usr/bin/env python3

import json
import hashlib
import sqlite3
import os
import urllib.parse
import urllib.request
import urllib.error

from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

from auth_support import (
    current_user,
    handle_auth_get,
    handle_auth_post,
    init_auth_db,
)

from chat_support import (
    handle_chat_get,
    handle_chat_post,
    init_chat_db,
)
from subscription_api import (
    init_subscription_db,
    handle_subscription_get,
    handle_subscription_post,
)
from voucher_payment_api import (
    init_voucher_payment_db,
    handle_voucher_payment_get,
    handle_voucher_payment_post,
)

from licence_db import init_licence_db

from licence_api import (
    handle_licence_get,
    handle_licence_post,
)

HOST = "0.0.0.0"
PORT = int(os.environ.get("PORT", "8000"))
API_KEY = os.environ.get("BRAVE_API_KEY", "")

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       "findme.db")


def init_likes_db():
    with sqlite3.connect(DB_PATH, timeout=10) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS product_likes (
                product_key TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (product_key, user_id),
                FOREIGN KEY (user_id) REFERENCES users(id)
                    ON DELETE CASCADE
            )
        """)
        db.execute("""
            CREATE INDEX IF NOT EXISTS product_likes_key_idx
            ON product_likes(product_key)
        """)


def like_hash(key):
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def handle_likes_post(handler, path):
    if path not in ("/api/likes/list", "/api/likes/update"):
        return False

    user = current_user(handler)
    if user is None:
        handler.send_json(401, {
            "error": "Please log in to use Likes."
        })
        return True

    try:
        length = int(handler.headers.get("Content-Length", "0"))
        if length < 1 or length > 100000:
            handler.send_json(400, {"error": "Invalid request size."})
            return True

        data = json.loads(handler.rfile.read(length).decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Expected an object")
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        handler.send_json(400, {"error": "Invalid JSON request."})
        return True

    if path == "/api/likes/list":
        keys = data.get("keys", [])
        if not isinstance(keys, list) or len(keys) > 200:
            handler.send_json(400, {"error": "Invalid product list."})
            return True

        if any(not isinstance(k, str) or not k or len(k) > 2000
               for k in keys):
            handler.send_json(400, {"error": "Invalid product key."})
            return True

        hashes = {k: like_hash(k) for k in set(keys)}
        counts = {}
        liked = {}

        with sqlite3.connect(DB_PATH, timeout=10) as db:
            for key, hashed in hashes.items():
                counts[key] = db.execute(
                    "SELECT COUNT(*) FROM product_likes "
                    "WHERE product_key = ?", (hashed,)
                ).fetchone()[0]

                liked[key] = db.execute(
                    "SELECT 1 FROM product_likes "
                    "WHERE product_key = ? AND user_id = ?",
                    (hashed, user["id"])
                ).fetchone() is not None

        handler.send_json(200, {
            "counts": counts,
            "liked": liked
        })
        return True

    key = data.get("key")
    action = data.get("action")

    if not isinstance(key, str) or not key or len(key) > 2000:
        handler.send_json(400, {"error": "Invalid product key."})
        return True

    if action not in ("like", "unlike"):
        handler.send_json(400, {"error": "Invalid Like action."})
        return True

    hashed = like_hash(key)

    with sqlite3.connect(DB_PATH, timeout=10) as db:
        if action == "like":
            db.execute(
                "INSERT OR IGNORE INTO product_likes "
                "(product_key, user_id, created_at) VALUES (?, ?, "
                "CAST(strftime('%s','now') AS INTEGER))",
                (hashed, user["id"])
            )
        else:
            db.execute(
                "DELETE FROM product_likes "
                "WHERE product_key = ? AND user_id = ?",
                (hashed, user["id"])
            )

        count = db.execute(
            "SELECT COUNT(*) FROM product_likes WHERE product_key = ?",
            (hashed,)
        ).fetchone()[0]

        liked = db.execute(
            "SELECT 1 FROM product_likes "
            "WHERE product_key = ? AND user_id = ?",
            (hashed, user["id"])
        ).fetchone() is not None

    handler.send_json(200, {"count": count, "liked": liked})
    return True


def search_links(query):
    encoded = urllib.parse.quote_plus(query + " products prices")
    return {
        "Google": "https://www.google.com/search?q=" + encoded,
        "Bing": "https://www.bing.com/search?q=" + encoded,
        "DuckDuckGo": "https://duckduckgo.com/?q=" + encoded,
    }


class FindMeHandler(SimpleHTTPRequestHandler):

    def send_json(self, status, data):
        body = json.dumps(data).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        # Block direct downloads of private source, databases and backups.
        requested = urllib.parse.unquote(parsed.path)
        parts = requested.replace("\\\\", "/").split("/")
        filename = parts[-1].lower()

        if (
            any(part.startswith(".") for part in parts if part)
            or filename.endswith((
                ".db", ".sqlite", ".sqlite3", ".bak",
                ".py", ".pyc", ".pyo"
            ))
            or ".bak." in filename
            or ".security_backup_" in filename
            or filename.startswith("findme_")
            or "backups" in [part.lower() for part in parts]
        ):
            self.send_error(404, "Not found")
            return

        if handle_subscription_get(self, parsed.path):
            return
        if handle_voucher_payment_get(self, parsed.path):
            return

        if handle_auth_get(self, parsed.path):
            return

        if handle_chat_get(self, parsed.path, parsed.query):
            return

        # Require an authenticated account for marketplace features.
        protected_pages = {
            "/photoadd.html",  # AddMe
            "/buyme.html",     # BuyMe
            "/sell.html",      # SellMe
            "/favourites.html", # Favourites
            "/chatme.html",     # ChatMe
        }

        if handle_licence_get(self, parsed.path):
            return

        if parsed.path in protected_pages and current_user(self) is None:
            body = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Login Required | MnakaFindMe</title>
<style>
body {
  margin: 0;
  min-height: 100vh;
  display: grid;
  place-items: center;
  background: #f2f5fa;
  font-family: Arial, sans-serif;
  color: #172033;
}
.card {
  width: min(420px, calc(100% - 48px));
  padding: 32px 24px;
  background: white;
  border-radius: 18px;
  box-shadow: 0 8px 30px #15274618;
  text-align: center;
  box-sizing: border-box;
}
.icon { font-size: 42px; }
a {
  display: inline-block;
  margin: 8px 4px;
  padding: 12px 18px;
  border-radius: 9px;
  text-decoration: none;
  font-weight: bold;
}
.login { background: #1769ff; color: white; }
.register { background: #e8efff; color: #174db5; }
.home { color: #44516a; }
</style>
</head>
<body>
<main class="card">
<div class="icon">🔒</div>
<h1>Login Required</h1>
<p>You need to log in or create an account to use this feature.</p>
<a class="login" href="/accounts.html">Log In</a>
<a class="register" href="/accounts.html">Create Account</a>
<p><a class="home" href="/">Return to homepage</a></p>
</main>
</body>
</html>""".encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return

        # Serve only approved public website pages.
        # Never expose the project directory through the general file server.
        allowed_pages = {
            "/",
            "/index.html",
            "/accounts.html",
            "/buyme.html",
            "/chatme.html",
            "/favourites.html",
            "/photoadd.html",
            "/scanme.html",
            "/secureme.html",
            "/sell.html",
            "/subscriptions.html",
        }

        if parsed.path != "/api/search":
            if parsed.path not in allowed_pages:
                self.send_error(404, "Not found")
                return

            page_name = "index.html" if parsed.path == "/" else parsed.path.lstrip("/")
            base_dir = os.path.dirname(os.path.abspath(__file__))
            page_path = os.path.realpath(os.path.join(base_dir, page_name))

            # Confirm the requested page is directly inside the project folder.
            if os.path.dirname(page_path) != os.path.realpath(base_dir):
                self.send_error(404, "Not found")
                return

            try:
                with open(page_path, "rb") as page_file:
                    body = page_file.read()
            except OSError:
                self.send_error(404, "Not found")
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return

        params = urllib.parse.parse_qs(parsed.query)
        query = params.get("q", [""])[0].strip()
        engine = params.get("engine", ["all"])[0].lower()

        if not query or len(query) > 200:
            return self.send_json(400, {
                "error": "Enter a search of 1–200 characters."
            })

        links = search_links(query)

        # No API key? Still provide useful external search options.
        if not API_KEY:
            return self.send_json(200, {
                "query": query,
                "mode": "quick",
                "message": (
                    "Quick search is ready. Choose a search engine "
                    "to view live internet results."
                ),
                "results": [],
                "search_links": links,
            })

        search_query = query + " product price South Africa"

        if engine in ("google", "bing", "duckduckgo"):
            return self.send_json(200, {
                "query": query,
                "mode": "quick",
                "results": [],
                "search_links": links,
            })

        url = (
            "https://api.search.brave.com/res/v1/web/search?"
            + urllib.parse.urlencode({
                "q": search_query,
                "country": "ZA",
                "search_lang": "en",
                "count": 10,
            })
        )

        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "X-Subscription-Token": API_KEY,
                "User-Agent": "findMe/1.0",
            },
        )

        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                data = json.loads(response.read().decode("utf-8"))

            results = []

            for item in data.get("web", {}).get("results", []):
                result_url = item.get("url", "")

                if not result_url.startswith(("https://", "http://")):
                    continue

                results.append({
                    "title": item.get("title", "Product result"),
                    "url": result_url,
                    "description": item.get("description", ""),
                })

            self.send_json(200, {
                "query": query,
                "mode": "integrated",
                "results": results,
                "search_links": links,
            })

        except urllib.error.HTTPError as error:
            print("Brave API HTTP error:", error.code)

            self.send_json(200, {
                "query": query,
                "mode": "quick",
                "message": (
                    "Integrated search is temporarily unavailable. "
                    "You can still search using another engine."
                ),
                "results": [],
                "search_links": links,
            })

        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            self.send_json(200, {
                "query": query,
                "mode": "quick",
                "message": "The search service could not be reached.",
                "results": [],
                "search_links": links,
            })


    def do_HEAD(self):
        # Do not allow the inherited file server to expose private files.
        self.send_error(405, "HEAD requests are not supported")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)

        if handle_subscription_post(self, parsed.path):
            return
        if handle_voucher_payment_post(self, parsed.path):
            return

        if handle_auth_post(self, parsed.path):
            return

        if handle_chat_post(self, parsed.path):
            return
        if handle_licence_post(self, parsed.path):
            return


        if handle_likes_post(self, parsed.path):
            return

        self.send_error(404, "Unknown API endpoint")


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    # Initialise the private licence database before its APIs use it.
    init_licence_db()

    init_auth_db()
    init_subscription_db()
    init_voucher_payment_db()
    init_likes_db()
    init_chat_db()

    server = ThreadingHTTPServer((HOST, PORT), FindMeHandler)

    print("=" * 42)
    print("MnakaFindMe — Product Search")
    print(f"Website: http://{HOST}:{PORT}/")
    print(f"Brave API configured: {'Yes' if API_KEY else 'No'}")
    print("Press Ctrl+C to stop.")
    print("=" * 42)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping MnakaFindMe.")
    finally:
        server.server_close()
