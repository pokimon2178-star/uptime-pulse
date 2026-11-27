import ipaddress
import json
import os
import socket
import sqlite3
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.client import HTTPConnection, HTTPSConnection, HTTPException
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, urlunsplit

PORT = int(os.environ.get("PORT", "3000"))
DB_PATH = os.environ.get("DB_PATH", "/data/pulse.db")
CHECK_INTERVAL = max(5, int(os.environ.get("CHECK_INTERVAL", "20")))
REQUEST_TIMEOUT = 5
MAX_REQUEST_BODY = 16 * 1024
MAX_TARGETS = 500

DB_LOCK = threading.Lock()
CHECK_LOCK = threading.Lock()


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def init_db():
    directory = os.path.dirname(os.path.abspath(DB_PATH))
    os.makedirs(directory, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=10000")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS targets ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "name TEXT NOT NULL,"
        "url TEXT NOT NULL UNIQUE,"
        "status TEXT DEFAULT 'PENDING',"
        "latency_ms INTEGER,"
        "http_status INTEGER,"
        "last_checked TEXT,"
        "created_at TEXT NOT NULL)"
    )
    columns = {row[1] for row in conn.execute("PRAGMA table_info(targets)")}
    if "http_status" not in columns:
        conn.execute("ALTER TABLE targets ADD COLUMN http_status INTEGER")
    conn.commit()
    return conn


DB_CONN = init_db()


def normalize_url(raw: str) -> str:
    value = raw.strip()
    if not value:
        raise ValueError("URL is required")
    if len(value) > 2048:
        raise ValueError("URL is too long (maximum 2048 characters)")
    if any(ord(char) <= 32 or ord(char) == 127 or char == "\\" for char in value):
        raise ValueError("URL contains invalid characters")
    if not value.startswith(("http://", "https://")):
        if "://" in value:
            raise ValueError("Only HTTP and HTTPS URLs are allowed")
        value = "https://" + value

    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError("Only HTTP and HTTPS URLs are allowed")
        if not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("URL must contain a hostname and must not contain credentials")
        if parsed.port not in (None, 80, 443):
            raise ValueError("Only ports 80 and 443 are allowed")
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        if "%" in host:
            raise ValueError("Scoped IP addresses are not allowed")
        netloc_host = f"[{host}]" if ":" in host else host
        if parsed.port is not None:
            netloc_host += f":{parsed.port}"
        local_host = host.rstrip(".")
        if local_host == "localhost" or local_host.endswith((".localhost", ".local")):
            raise ValueError("Local hostnames are not allowed")
        # Remove fragments; they are not sent in HTTP requests.
        return urlunsplit((parsed.scheme.lower(), netloc_host, parsed.path or "/", parsed.query, ""))
    except (UnicodeError, ValueError) as exc:
        raise ValueError(str(exc) or "Invalid URL") from exc


def resolve_public_addresses(host: str, port: int):
    try:
        answers = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise OSError("Hostname could not be resolved") from exc
    addresses = []
    for answer in answers:
        address = answer[4][0]
        ip = ipaddress.ip_address(address.split("%", 1)[0])
        if not ip.is_global:
            raise OSError("URL resolves to a non-public IP address")
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise OSError("Hostname has no usable IP address")
    return addresses


class PinnedHTTPConnection(HTTPConnection):
    def __init__(self, host, port=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, *, ip):
        super().__init__(host, port=port, timeout=timeout, source_address=source_address)
        self.pinned_ip = ip

    def connect(self):
        self.sock = socket.create_connection((self.pinned_ip, self.port), self.timeout, self.source_address)


class PinnedHTTPSConnection(HTTPSConnection):
    def __init__(self, host, port=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, *, ip):
        super().__init__(host, port=port, timeout=timeout, source_address=source_address)
        self.pinned_ip = ip

    def connect(self):
        raw_sock = socket.create_connection((self.pinned_ip, self.port), self.timeout, self.source_address)
        self.sock = self._context.wrap_socket(raw_sock, server_hostname=self.host)


def probe_url(url: str) -> tuple[str, int | None, int | None]:
    start = time.perf_counter()
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        addresses = resolve_public_addresses(host, port)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        headers = {"User-Agent": "UptimePulse/1.1", "Connection": "close"}
        last_error = None
        for address in addresses:
            conn = None
            try:
                if parsed.scheme == "https":
                    conn = PinnedHTTPSConnection(host, port=port, timeout=REQUEST_TIMEOUT, ip=address)
                else:
                    conn = PinnedHTTPConnection(host, port=port, timeout=REQUEST_TIMEOUT, ip=address)
                conn.request("GET", path, headers=headers)
                response = conn.getresponse()
                elapsed = int((time.perf_counter() - start) * 1000)
                # Any HTTP response proves connectivity; HTTP success is reported separately.
                status = "ONLINE"
                http_status = response.status
                response.close()
                return status, elapsed, http_status
            except (OSError, ssl.SSLError, TimeoutError, HTTPException) as exc:
                last_error = exc
            finally:
                if conn:
                    conn.close()
        if last_error:
            raise last_error
    except (OSError, ssl.SSLError, TimeoutError, HTTPException, ValueError, UnicodeError):
        pass
    return "OFFLINE", None, None


def check_all_targets():
    # Prevent the background poller and manual API trigger from probing the same targets concurrently.
    with CHECK_LOCK:
        with DB_LOCK:
            rows = DB_CONN.execute("SELECT id, url FROM targets").fetchall()
        if not rows:
            return
        with ThreadPoolExecutor(max_workers=min(20, len(rows))) as executor:
            results = list(executor.map(probe_url, (url for _, url in rows)))
        checked_at = now_iso()
        updates = [
            (status, latency, http_status, checked_at, target_id)
            for (target_id, _), (status, latency, http_status) in zip(rows, results)
        ]
        with DB_LOCK:
            DB_CONN.executemany(
                "UPDATE targets SET status = ?, latency_ms = ?, http_status = ?, last_checked = ? WHERE id = ?",
                updates,
            )
            DB_CONN.commit()


def background_poller():
    while True:
        try:
            check_all_targets()
        except Exception as err:
            print(f"[poller] error: {err}", flush=True)
        time.sleep(CHECK_INTERVAL)


class Handler(BaseHTTPRequestHandler):
    server_version = "UptimePulse"

    def _send_json(self, code: int, payload):
        body = b"" if code == 204 else json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        if code != 204 and self.command != "HEAD":
            self.wfile.write(body)

    def do_OPTIONS(self):
        self._send_json(204, None)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/api/health":
            self._send_json(200, {"status": "ok"})
            return
        if path == "/api/targets":
            with DB_LOCK:
                cur = DB_CONN.execute(
                    "SELECT id, name, url, status, latency_ms, http_status, last_checked, created_at "
                    "FROM targets ORDER BY id DESC"
                )
                rows = [self._row_to_dict(r) for r in cur.fetchall()]
            self._send_json(200, rows)
            return
        self._send_json(404, {"error": "Not found"})

    @staticmethod
    def _row_to_dict(row):
        return {
            "id": row[0], "name": row[1], "url": row[2], "status": row[3],
            "latency_ms": row[4], "http_status": row[5],
            "http_success": row[5] is not None and 200 <= row[5] < 300,
            "last_checked": row[6], "created_at": row[7],
        }

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("Invalid Content-Length")
        if length < 0 or length > MAX_REQUEST_BODY:
            raise OverflowError("Request body is too large")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Invalid JSON") from exc
        if not isinstance(data, dict):
            raise ValueError("JSON body must be an object")
        return data

    def do_POST(self):
        path = urlsplit(self.path).path
        if path == "/api/targets/check":
            check_all_targets()
            self._send_json(200, {"checked": True})
            return
        if path != "/api/targets":
            self._send_json(404, {"error": "Not found"})
            return

        try:
            data = self._read_json()
            raw_url = data.get("url", "")
            raw_name = data.get("name", "")
            if not isinstance(raw_url, str) or not isinstance(raw_name, str):
                raise ValueError("name and url must be strings")
            url = normalize_url(raw_url)
            name = raw_name.strip() or url
            if len(name) > 100:
                raise ValueError("Name is too long (maximum 100 characters)")
        except OverflowError as exc:
            self._send_json(413, {"error": str(exc)})
            return
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            return

        with DB_LOCK:
            count = DB_CONN.execute("SELECT COUNT(*) FROM targets").fetchone()[0]
            existing = DB_CONN.execute("SELECT id FROM targets WHERE url = ?", (url,)).fetchone()
        if existing:
            self._send_json(409, {"error": "This URL is already being monitored"})
            return
        if count >= MAX_TARGETS:
            self._send_json(409, {"error": f"Maximum of {MAX_TARGETS} targets reached"})
            return

        status, latency, http_status = probe_url(url)
        checked_at = now_iso()
        try:
            with DB_LOCK:
                if DB_CONN.execute("SELECT COUNT(*) FROM targets").fetchone()[0] >= MAX_TARGETS:
                    self._send_json(409, {"error": f"Maximum of {MAX_TARGETS} targets reached"})
                    return
                cur = DB_CONN.execute(
                    "INSERT INTO targets (name, url, status, latency_ms, http_status, last_checked, created_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (name, url, status, latency, http_status, checked_at, checked_at),
                )
                DB_CONN.commit()
                row = DB_CONN.execute(
                    "SELECT id, name, url, status, latency_ms, http_status, last_checked, created_at "
                    "FROM targets WHERE id = ?", (cur.lastrowid,)
                ).fetchone()
        except sqlite3.IntegrityError:
            self._send_json(409, {"error": "This URL is already being monitored"})
            return
        self._send_json(201, self._row_to_dict(row))

    def do_DELETE(self):
        path = urlsplit(self.path).path
        if not path.startswith("/api/targets/"):
            self._send_json(404, {"error": "Not found"})
            return
        try:
            target_id = int(path.rsplit("/", 1)[1])
            if target_id <= 0:
                raise ValueError
        except ValueError:
            self._send_json(400, {"error": "Invalid id"})
            return
        with DB_LOCK:
            cur = DB_CONN.execute("DELETE FROM targets WHERE id = ?", (target_id,))
            DB_CONN.commit()
        if cur.rowcount == 0:
            self._send_json(404, {"error": "Target not found"})
            return
        self._send_json(200, {"deleted": target_id})

    def log_message(self, format, *args):
        print(f"[backend] {self.address_string()} - {format % args}", flush=True)


if __name__ == "__main__":
    threading.Thread(target=background_poller, daemon=True, name="uptime-poller").start()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    server.daemon_threads = True
    print(f"UptimePulse backend running on 0.0.0.0:{PORT}, db={DB_PATH}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        with DB_LOCK:
            DB_CONN.close()
