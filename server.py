"""
server.py — the heart of PatchPilot.
Runs as a Windows service (or foreground process for dev/testing).

First run:  python server.py --setup    (generates certs, creates DB)
Dev run:    python server.py            (foreground, Ctrl+C to stop)
Install:    server.exe /install         (Windows service)
"""

import json
import os
import platform
import secrets
import sqlite3
import ssl
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs, urlparse

from shared import (
    APP_NAME, VERSION, DEFAULT_PORT, DASHBOARD_PORT,
    Device, Package, Job, LogEntry,
    now_iso, new_id, jwt_verify, jwt_payload,
    sign_job, cert_fingerprint, sha256_file, verify_package,
    is_allowed_executor, KNOWN_APPS, KNOWN_APPS_BY_ID,
)

# ─── Paths ────────────────────────────────────────────────────────────────────

BASE_DIR     = Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).parent
DB_PATH      = BASE_DIR / "patchpilot.db"
CERT_DIR     = BASE_DIR / "certs"
CERT_PATH    = CERT_DIR / "server.crt"
KEY_PATH     = CERT_DIR / "server.key"
PACKAGES_DIR = BASE_DIR / "packages"
CONFIG_PATH  = BASE_DIR / "server.json"

# ─── Config ───────────────────────────────────────────────────────────────────

def load_config() -> dict:
    if CONFIG_PATH.exists():
        return json.loads(CONFIG_PATH.read_text())
    cfg = {
        "jwt_secret": secrets.token_hex(32),
        "job_secret": secrets.token_hex(32),
        "api_port":   DEFAULT_PORT,
        "dash_port":  DASHBOARD_PORT,
        "version":    VERSION,
    }
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2))
    print(f"[setup] Config created at {CONFIG_PATH}")
    print(f"[setup] job_secret (copy into Agent Builder): {cfg['job_secret']}")
    return cfg

CONFIG = load_config()

# ─── Database ─────────────────────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS devices (
            id            TEXT PRIMARY KEY,
            hostname      TEXT NOT NULL,
            ip            TEXT NOT NULL,
            os_version    TEXT,
            agent_version TEXT,
            status        TEXT DEFAULT 'pending',
            last_seen     TEXT,
            group_name    TEXT DEFAULT 'default',
            jwt           TEXT
        );
        CREATE TABLE IF NOT EXISTS packages (
            id            TEXT PRIMARY KEY,
            name          TEXT NOT NULL,
            version       TEXT,
            app_id        TEXT,
            source_url    TEXT,
            sha256        TEXT NOT NULL,
            install_cmd   TEXT NOT NULL,
            uninstall_cmd TEXT,
            update_cmd    TEXT,
            created_at    TEXT
        );
        CREATE TABLE IF NOT EXISTS jobs (
            id          TEXT PRIMARY KEY,
            device_id   TEXT REFERENCES devices(id),
            package_id  TEXT REFERENCES packages(id),
            action      TEXT NOT NULL,
            status      TEXT DEFAULT 'queued',
            created_at  TEXT,
            finished_at TEXT,
            result      TEXT,
            signature   TEXT
        );
        CREATE TABLE IF NOT EXISTS logs (
            id        TEXT PRIMARY KEY,
            device_id TEXT,
            job_id    TEXT,
            message   TEXT,
            level     TEXT DEFAULT 'info',
            timestamp TEXT
        );
    """)
    db.commit()
    db.close()

# ─── DB helpers ───────────────────────────────────────────────────────────────

def db_get(query: str, params=()) -> Optional[sqlite3.Row]:
    db = get_db()
    row = db.execute(query, params).fetchone()
    db.close()
    return row

def db_all(query: str, params=()) -> list:
    db = get_db()
    rows = db.execute(query, params).fetchall()
    db.close()
    return [dict(r) for r in rows]

def db_run(query: str, params=()):
    db = get_db()
    db.execute(query, params)
    db.commit()
    db.close()

def log_event(device_id: str, job_id: str, message: str, level="info"):
    db_run(
        "INSERT INTO logs VALUES (?,?,?,?,?,?)",
        (new_id(), device_id, job_id, message, level, now_iso())
    )

# ─── TLS ──────────────────────────────────────────────────────────────────────

def generate_certs():
    CERT_DIR.mkdir(exist_ok=True)
    if CERT_PATH.exists() and KEY_PATH.exists():
        print("[setup] Certificates already exist — skipping generation.")
        return
    print("[setup] Generating self-signed TLS certificate (RSA 4096)...")
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:4096",
        "-keyout", str(KEY_PATH),
        "-out",    str(CERT_PATH),
        "-days",   "3650",
        "-nodes",
        "-subj",   "/CN=PatchPilot-Server",
    ], check=True, capture_output=True)
    fp = cert_fingerprint(str(CERT_PATH))
    print(f"[setup] Certificate fingerprint (paste into Agent Builder):\n        {fp}")

# ─── Request handler ──────────────────────────────────────────────────────────

class PatchPilotHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
        pass  # silence default access log

    # ── Auth ──────────────────────────────────────────────────────────────────

    def get_device_from_token(self) -> Optional[dict]:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return None
        token   = auth[7:]
        payload = jwt_verify(token, CONFIG["jwt_secret"])
        if not payload:
            return None
        row = db_get(
            "SELECT * FROM devices WHERE id=? AND status='approved'",
            (payload["sub"],)
        )
        return dict(row) if row else None

    # ── Response helpers ──────────────────────────────────────────────────────

    def send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        # FIX: CORS restricted to same-host dashboard instead of wildcard "*".
        # The dashboard is served from the same machine, so this is safe.
        # Wildcard would let any website on the internet make authenticated
        # requests to the API as long as the admin's browser had a valid JWT.
        origin = self.headers.get("Origin", "")
        if origin.startswith(f"http://localhost") or origin.startswith(f"http://127.0.0.1"):
            self.send_header("Access-Control-Allow-Origin", origin)
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, message, status=400):
        self.send_json({"error": message}, status)

    def read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if not length:
            return {}
        # FIX: cap body size — previously no limit meant a malicious agent
        # could send a gigabyte payload and exhaust memory.
        if length > 1_048_576:  # 1 MB
            raise ValueError("Request body too large")
        return json.loads(self.rfile.read(length))

    # ── Routing ───────────────────────────────────────────────────────────────

    def do_OPTIONS(self):
        self.send_response(204)
        origin = self.headers.get("Origin", "")
        if origin.startswith("http://localhost") or origin.startswith("http://127.0.0.1"):
            self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.end_headers()

    def do_GET(self):
        try:
            p = urlparse(self.path).path
            if p == "/health":               return self.route_health()
            if p == "/api/devices":          return self.route_devices_list()
            if p == "/api/packages":         return self.route_packages_list()
            if p == "/api/known-apps":       return self.route_known_apps()
            if p == "/api/jobs":             return self.route_jobs_list()
            if p == "/api/logs":             return self.route_logs_list()
            if p == "/api/jobs/pending":     return self.route_agent_jobs()
            if p == "/api/stats":            return self.route_stats()
            self.send_error_json("not found", 404)
        except Exception as e:
            self.send_error_json(f"internal error: {e}", 500)

    def do_POST(self):
        try:
            p = urlparse(self.path).path
            if p == "/api/enroll":           return self.route_enroll()
            if p == "/api/heartbeat":        return self.route_heartbeat()
            if p == "/api/jobs/result":      return self.route_job_result()
            if p == "/api/packages":         return self.route_package_add()
            if p == "/api/jobs":             return self.route_job_create()
            self.send_error_json("not found", 404)
        except ValueError as e:
            self.send_error_json(str(e), 413)
        except Exception as e:
            self.send_error_json(f"internal error: {e}", 500)

    def do_PATCH(self):
        try:
            p = urlparse(self.path).path
            parts = p.split("/")
            # FIX: previously split("/")[3] — IndexError if path is malformed.
            # Now we validate the structure before indexing.
            if len(parts) == 5 and parts[1] == "api" and parts[2] == "devices":
                device_id = parts[3]
                action    = parts[4]
                if action == "approve": return self.route_device_approve(device_id)
                if action == "revoke":  return self.route_device_revoke(device_id)
            self.send_error_json("not found", 404)
        except Exception as e:
            self.send_error_json(f"internal error: {e}", 500)

    def do_DELETE(self):
        try:
            p     = urlparse(self.path).path
            parts = p.split("/")
            # FIX: same IndexError guard as do_PATCH
            if len(parts) == 4 and parts[1] == "api" and parts[2] == "packages":
                return self.route_package_delete(parts[3])
            self.send_error_json("not found", 404)
        except Exception as e:
            self.send_error_json(f"internal error: {e}", 500)

    # ── Agent-facing routes ───────────────────────────────────────────────────

    def route_health(self):
        self.send_json({
            "status":      "ok",
            "version":     VERSION,
            # FIX: don't expose the cert fingerprint in the health endpoint.
            # The fingerprint is only needed by the Agent Builder — an agent
            # already has it baked in. Exposing it publicly lets anyone who
            # can reach port 8443 trivially verify the cert without connecting.
        })

    def route_enroll(self):
        data     = self.read_body()
        hostname = data.get("hostname", "unknown")[:128]  # cap length
        ip       = self.client_address[0]

        existing = db_get(
            "SELECT * FROM devices WHERE hostname=? AND ip=?", (hostname, ip)
        )
        if existing:
            db_run(
                "UPDATE devices SET last_seen=?, agent_version=? WHERE id=?",
                (now_iso(), data.get("agent_version", "")[:32], existing["id"])
            )
            status = existing["status"]
            # FIX: only return a token if the device is approved.
            # Previously, token was returned for any status where jwt was set —
            # a revoked device that still had a jwt column value would get it back.
            token = existing["jwt"] if status == "approved" else None
            self.send_json({"status": status, "token": token})
            return

        device_id = new_id()
        db_run(
            "INSERT INTO devices VALUES (?,?,?,?,?,?,?,?,?)",
            (device_id, hostname, ip,
             data.get("os_version", "")[:256],
             data.get("agent_version", "")[:32],
             "pending", now_iso(), "default", None)
        )
        log_event(device_id, "", f"New device enrolled: {hostname} ({ip})")
        self.send_json({"status": "pending", "token": None})

    def route_heartbeat(self):
        device = self.get_device_from_token()
        if not device:
            return self.send_error_json("unauthorized", 401)
        db_run("UPDATE devices SET last_seen=? WHERE id=?", (now_iso(), device["id"]))
        self.send_json({"ok": True})

    def route_agent_jobs(self):
        device = self.get_device_from_token()
        if not device:
            return self.send_error_json("unauthorized", 401)
        jobs = db_all(
            """SELECT j.*, p.name as pkg_name, p.source_url, p.sha256,
                      p.install_cmd, p.uninstall_cmd, p.update_cmd
               FROM jobs j JOIN packages p ON j.package_id = p.id
               WHERE j.device_id=? AND j.status='queued'""",
            (device["id"],)
        )
        for job in jobs:
            db_run("UPDATE jobs SET status='running' WHERE id=?", (job["id"],))
        self.send_json({"jobs": jobs})

    def route_job_result(self):
        device = self.get_device_from_token()
        if not device:
            return self.send_error_json("unauthorized", 401)
        data    = self.read_body()
        job_id  = data.get("job_id", "")
        success = bool(data.get("success", False))
        result  = str(data.get("result", ""))[:2000]
        status  = "done" if success else "failed"
        # FIX: verify the job belongs to this device before updating it.
        # Previously any approved device could update any job ID.
        db_run(
            "UPDATE jobs SET status=?, result=?, finished_at=? WHERE id=? AND device_id=?",
            (status, result, now_iso(), job_id, device["id"])
        )
        log_event(device["id"], job_id, result[:200], "info" if success else "error")
        self.send_json({"ok": True})

    # ── Dashboard-facing routes ───────────────────────────────────────────────

    def route_known_apps(self):
        """Return the catalog so the dashboard can pre-fill the add-package form."""
        safe = [
            {"id": a["id"], "name": a["name"], "publisher": a["publisher"],
             "install_cmd": a["install_cmd"], "uninstall_cmd": a["uninstall_cmd"],
             "update_cmd": a["update_cmd"]}
            for a in KNOWN_APPS
        ]
        self.send_json(safe)

    def route_devices_list(self):
        self.send_json(db_all("SELECT * FROM devices ORDER BY last_seen DESC"))

    def route_packages_list(self):
        self.send_json(db_all("SELECT * FROM packages ORDER BY name"))

    def route_jobs_list(self):
        rows = db_all("""
            SELECT j.*, d.hostname, p.name as pkg_name
            FROM jobs j
            JOIN devices d ON j.device_id = d.id
            JOIN packages p ON j.package_id = p.id
            ORDER BY j.created_at DESC LIMIT 200
        """)
        self.send_json(rows)

    def route_logs_list(self):
        qs     = parse_qs(urlparse(self.path).query)
        dev_id = qs.get("device_id", [None])[0]
        if dev_id:
            rows = db_all(
                "SELECT * FROM logs WHERE device_id=? ORDER BY timestamp DESC LIMIT 200",
                (dev_id,)
            )
        else:
            rows = db_all("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 200")
        self.send_json(rows)

    def route_stats(self):
        # FIX: "online" should mean seen in the last 90 seconds (3 poll cycles),
        # not just "approved" — an approved device that's been offline for days
        # was previously shown as online.
        from datetime import datetime, timezone, timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=90)).isoformat()
        self.send_json({
            "total_devices":   db_get("SELECT COUNT(*) as n FROM devices")["n"],
            "online_devices":  db_get(
                "SELECT COUNT(*) as n FROM devices WHERE status='approved' AND last_seen > ?",
                (cutoff,)
            )["n"],
            "pending_devices": db_get(
                "SELECT COUNT(*) as n FROM devices WHERE status='pending'"
            )["n"],
            "total_packages":  db_get("SELECT COUNT(*) as n FROM packages")["n"],
            "jobs_queued":     db_get("SELECT COUNT(*) as n FROM jobs WHERE status='queued'")["n"],
            "jobs_running":    db_get("SELECT COUNT(*) as n FROM jobs WHERE status='running'")["n"],
            "jobs_failed":     db_get("SELECT COUNT(*) as n FROM jobs WHERE status='failed'")["n"],
        })

    def route_device_approve(self, device_id: str):
        row = db_get("SELECT * FROM devices WHERE id=?", (device_id,))
        if not row:
            return self.send_error_json("device not found", 404)
        token = jwt_payload(device_id, CONFIG["jwt_secret"])
        db_run(
            "UPDATE devices SET status='approved', jwt=? WHERE id=?",
            (token, device_id)
        )
        log_event(device_id, "", f"Device approved: {row['hostname']}")
        self.send_json({"ok": True, "token": token})

    def route_device_revoke(self, device_id: str):
        # FIX: clear the jwt column on revoke — previously the token was kept
        # in the DB. A revoked device that re-enrolled while still holding its
        # old token in memory could still authenticate until the JWT expired.
        db_run(
            "UPDATE devices SET status='revoked', jwt=NULL WHERE id=?",
            (device_id,)
        )
        log_event(device_id, "", "Device revoked by admin")
        self.send_json({"ok": True})

    def route_package_add(self):
        data = self.read_body()

        # If an app_id is provided, pull defaults from the known-app catalog
        app_id = data.get("app_id", "")
        if app_id and app_id in KNOWN_APPS_BY_ID:
            catalog = KNOWN_APPS_BY_ID[app_id]
            data.setdefault("install_cmd",   catalog["install_cmd"])
            data.setdefault("uninstall_cmd", catalog["uninstall_cmd"])
            data.setdefault("update_cmd",    catalog["update_cmd"])

        required = ["name", "version", "source_url", "sha256", "install_cmd"]
        for field in required:
            if not data.get(field):
                return self.send_error_json(f"missing field: {field}")

        # FIX: validate sha256 looks like a real hash (64 hex chars).
        # Previously any non-empty string was accepted — admins could type
        # "todo" as a placeholder and agents would reject the package at
        # runtime instead of failing here at creation time.
        sha256 = data["sha256"].strip().lower()
        if len(sha256) != 64 or not all(c in "0123456789abcdef" for c in sha256):
            return self.send_error_json("sha256 must be a valid 64-character hex string")

        if not is_allowed_executor(data["install_cmd"]):
            return self.send_error_json("install_cmd uses a disallowed executor")

        pkg_id = new_id()
        db_run(
            "INSERT INTO packages VALUES (?,?,?,?,?,?,?,?,?,?)",
            (pkg_id, data["name"], data["version"],
             app_id,
             data["source_url"], sha256,
             data["install_cmd"],
             data.get("uninstall_cmd", ""),
             data.get("update_cmd", ""),
             now_iso())
        )
        self.send_json({"ok": True, "id": pkg_id})

    def route_package_delete(self, pkg_id: str):
        # FIX: block deletion if there are queued or running jobs using this
        # package — deleting it would orphan those jobs on the agent side.
        active = db_get(
            "SELECT COUNT(*) as n FROM jobs WHERE package_id=? AND status IN ('queued','running')",
            (pkg_id,)
        )
        if active and active["n"] > 0:
            return self.send_error_json(
                "Cannot delete — this package has active jobs. Wait for them to finish."
            )
        db_run("DELETE FROM packages WHERE id=?", (pkg_id,))
        self.send_json({"ok": True})

    def route_job_create(self):
        data       = self.read_body()
        device_id  = data.get("device_id")
        group      = data.get("group")
        package_id = data.get("package_id")
        action     = data.get("action", "install")

        if action not in ("install", "uninstall", "update"):
            return self.send_error_json("invalid action")

        # Validate the package exists
        if not db_get("SELECT id FROM packages WHERE id=?", (package_id,)):
            return self.send_error_json("package not found")

        if device_id:
            # Validate the device exists and is approved
            if not db_get(
                "SELECT id FROM devices WHERE id=? AND status='approved'", (device_id,)
            ):
                return self.send_error_json("device not found or not approved")
            targets = [{"id": device_id}]
        elif group:
            targets = db_all(
                "SELECT id FROM devices WHERE group_name=? AND status='approved'", (group,)
            )
        else:
            return self.send_error_json("provide device_id or group")

        if not targets:
            return self.send_error_json("no approved devices in target")

        job_ids = []
        for t in targets:
            job_id = new_id()
            sig    = sign_job(job_id, t["id"], action, CONFIG["job_secret"])
            db_run(
                "INSERT INTO jobs VALUES (?,?,?,?,?,?,?,?,?)",
                (job_id, t["id"], package_id, action, "queued", now_iso(), "", "", sig)
            )
            job_ids.append(job_id)

        self.send_json({"ok": True, "job_ids": job_ids})


# ─── Dashboard HTML ───────────────────────────────────────────────────────────
# The entire frontend in one string. The only change from the original is the
# /api/known-apps integration that pre-fills the add-package form from the catalog.

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PatchPilot</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,400;0,9..40,500;0,9..40,600;1,9..40,300&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg:#0d0f12; --bg2:#13161b; --bg3:#1a1e25;
    --border:#ffffff0f; --border2:#ffffff18;
    --text:#e8eaf0; --muted:#6b7280;
    --accent:#4f8ef7; --accent2:#3d7de4;
    --green:#34d399; --amber:#fbbf24; --red:#f87171;
    --radius:10px; --font:'DM Sans',sans-serif; --mono:'DM Mono',monospace;
  }
  html,body{height:100%;background:var(--bg);color:var(--text);font-family:var(--font);font-size:14px;line-height:1.6}
  .shell{display:flex;height:100vh;overflow:hidden}
  .sidebar{width:220px;min-width:220px;background:var(--bg2);border-right:1px solid var(--border);display:flex;flex-direction:column;padding:24px 0}
  .main{flex:1;overflow-y:auto;padding:32px 36px}
  .logo{padding:0 20px 28px;display:flex;align-items:center;gap:10px}
  .logo-mark{width:32px;height:32px;background:var(--accent);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:16px;flex-shrink:0}
  .logo-text{font-size:16px;font-weight:600;letter-spacing:-.3px}
  .logo-ver{font-size:11px;color:var(--muted);font-family:var(--mono)}
  nav a{display:flex;align-items:center;gap:10px;padding:9px 20px;color:var(--muted);text-decoration:none;font-size:13.5px;font-weight:400;border-left:2px solid transparent;transition:color .15s,background .15s}
  nav a:hover{color:var(--text);background:var(--border)}
  nav a.active{color:var(--text);border-left-color:var(--accent);background:#4f8ef710;font-weight:500}
  nav .icon{width:16px;opacity:.7}
  .sidebar-footer{margin-top:auto;padding:16px 20px;border-top:1px solid var(--border);font-size:12px;color:var(--muted)}
  #server-status{display:flex;align-items:center;gap:6px}
  .dot{width:7px;height:7px;border-radius:50%;background:var(--green);flex-shrink:0}
  .dot.offline{background:var(--red)}
  .page-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:28px}
  .page-title{font-size:22px;font-weight:600;letter-spacing:-.4px}
  .page-sub{font-size:13px;color:var(--muted);margin-top:2px}
  .stats{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:28px}
  .stat{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);padding:20px}
  .stat-val{font-size:28px;font-weight:600;letter-spacing:-1px;font-family:var(--mono);line-height:1}
  .stat-label{font-size:12px;color:var(--muted);margin-top:4px}
  .stat-val.green{color:var(--green)}.stat-val.amber{color:var(--amber)}.stat-val.red{color:var(--red)}
  .card{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden}
  .card-header{padding:16px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
  .card-title{font-size:14px;font-weight:500}
  table{width:100%;border-collapse:collapse}
  th{font-size:11px;font-weight:500;letter-spacing:.06em;text-transform:uppercase;color:var(--muted);padding:10px 20px;text-align:left;border-bottom:1px solid var(--border)}
  td{padding:13px 20px;border-bottom:1px solid var(--border);font-size:13px;vertical-align:middle}
  tr:last-child td{border-bottom:none}
  tr:hover td{background:var(--border)}
  .mono{font-family:var(--mono);font-size:12px;color:var(--muted)}
  .badge{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border-radius:20px;font-size:11px;font-weight:500}
  .badge-green{background:#34d39920;color:var(--green)}.badge-amber{background:#fbbf2420;color:var(--amber)}
  .badge-red{background:#f8717120;color:var(--red)}.badge-gray{background:var(--bg3);color:var(--muted)}.badge-blue{background:#4f8ef720;color:var(--accent)}
  .btn{display:inline-flex;align-items:center;gap:6px;padding:7px 14px;border-radius:7px;font-size:13px;font-weight:500;font-family:var(--font);cursor:pointer;transition:all .15s;border:none;text-decoration:none}
  .btn-primary{background:var(--accent);color:#fff}.btn-primary:hover{background:var(--accent2)}
  .btn-ghost{background:transparent;color:var(--muted);border:1px solid var(--border2)}.btn-ghost:hover{color:var(--text);background:var(--border)}
  .btn-danger{background:transparent;color:var(--red);border:1px solid #f8717130}.btn-danger:hover{background:#f8717115}
  .btn-success{background:transparent;color:var(--green);border:1px solid #34d39930}.btn-success:hover{background:#34d39915}
  .btn-sm{padding:4px 10px;font-size:12px}
  .form-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
  .form-field{display:flex;flex-direction:column;gap:6px}
  .form-field.full{grid-column:1/-1}
  label{font-size:12px;font-weight:500;color:var(--muted)}
  input,select,textarea{background:var(--bg3);border:1px solid var(--border2);border-radius:7px;color:var(--text);font-family:var(--font);font-size:13px;padding:8px 12px;outline:none;transition:border-color .15s;width:100%}
  input:focus,select:focus,textarea:focus{border-color:var(--accent)}
  textarea{resize:vertical;min-height:72px;font-family:var(--mono);font-size:12px}
  .modal-backdrop{display:none;position:fixed;inset:0;background:#000a;z-index:100;align-items:center;justify-content:center}
  .modal-backdrop.open{display:flex}
  .modal{background:var(--bg2);border:1px solid var(--border2);border-radius:14px;padding:28px;width:520px;max-width:95vw}
  .modal-title{font-size:17px;font-weight:600;margin-bottom:20px}
  .modal-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:24px}
  .empty{text-align:center;padding:60px 20px;color:var(--muted)}
  .empty-icon{font-size:32px;margin-bottom:12px}
  .empty-text{font-size:13px}
  .flex{display:flex;gap:6px}
  .text-muted{color:var(--muted)}.text-sm{font-size:12px}
  .log-line{padding:7px 20px;border-bottom:1px solid var(--border);font-family:var(--mono);font-size:12px;display:flex;gap:16px}
  .log-line:last-child{border-bottom:none}
  .log-time{color:var(--muted);flex-shrink:0}
  .log-msg{flex:1}
  .log-info{color:var(--text)}.log-warn{color:var(--amber)}.log-error{color:var(--red)}
  ::-webkit-scrollbar{width:6px}
  ::-webkit-scrollbar-track{background:transparent}
  ::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}
  @keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
  .page.active{animation:fadeIn .18s ease}
  .toast{position:fixed;bottom:24px;right:24px;background:var(--bg3);border:1px solid var(--border2);border-radius:8px;padding:12px 18px;font-size:13px;z-index:200;animation:fadeIn .2s ease}
  .toast.success{border-color:#34d39940;color:var(--green)}.toast.error{border-color:#f8717140;color:var(--red)}
</style>
</head>
<body>
<div class="shell">
  <aside class="sidebar">
    <div class="logo">
      <div class="logo-mark">⚡</div>
      <div><div class="logo-text">PatchPilot</div><div class="logo-ver">v1.0.0</div></div>
    </div>
    <nav>
      <a href="#" class="active" data-page="overview">
        <svg class="icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="1" y="1" width="6" height="6" rx="1"/><rect x="9" y="1" width="6" height="6" rx="1"/><rect x="1" y="9" width="6" height="6" rx="1"/><rect x="9" y="9" width="6" height="6" rx="1"/></svg>
        Overview
      </a>
      <a href="#" data-page="devices">
        <svg class="icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="1" y="3" width="14" height="10" rx="1.5"/><path d="M5 13v2M11 13v2M3 15h10"/></svg>
        Devices
      </a>
      <a href="#" data-page="packages">
        <svg class="icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M8 1l7 4v6l-7 4-7-4V5l7-4z"/><path d="M8 9V15M1 5l7 4 7-4"/></svg>
        Packages
      </a>
      <a href="#" data-page="jobs">
        <svg class="icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M2 4h12M2 8h8M2 12h5"/></svg>
        Jobs
      </a>
      <a href="#" data-page="logs">
        <svg class="icon" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M13 2H3a1 1 0 00-1 1v10a1 1 0 001 1h10a1 1 0 001-1V3a1 1 0 00-1-1z"/><path d="M5 6h6M5 9h6M5 12h3"/></svg>
        Logs
      </a>
    </nav>
    <div class="sidebar-footer">
      <div id="server-status"><div class="dot" id="status-dot"></div><span id="status-text">Connecting…</span></div>
    </div>
  </aside>

  <main class="main">
    <div class="page active" id="page-overview">
      <div class="page-header">
        <div><div class="page-title">Overview</div><div class="page-sub">Your fleet at a glance</div></div>
        <button class="btn btn-ghost" onclick="refresh()">↻ Refresh</button>
      </div>
      <div class="stats">
        <div class="stat"><div class="stat-val" id="s-total">—</div><div class="stat-label">Total devices</div></div>
        <div class="stat"><div class="stat-val green" id="s-online">—</div><div class="stat-label">Online now</div></div>
        <div class="stat"><div class="stat-val amber" id="s-pending">—</div><div class="stat-label">Pending approval</div></div>
        <div class="stat"><div class="stat-val red" id="s-failed">—</div><div class="stat-label">Failed jobs</div></div>
      </div>
      <div class="card">
        <div class="card-header"><div class="card-title">Recent activity</div></div>
        <div id="overview-logs"></div>
      </div>
    </div>

    <div class="page" id="page-devices">
      <div class="page-header">
        <div><div class="page-title">Devices</div><div class="page-sub">Manage your endpoints</div></div>
        <button class="btn btn-ghost" onclick="loadDevices()">↻ Refresh</button>
      </div>
      <div class="card">
        <table>
          <thead><tr><th>Hostname</th><th>IP</th><th>OS</th><th>Last seen</th><th>Status</th><th>Actions</th></tr></thead>
          <tbody id="devices-tbody"></tbody>
        </table>
      </div>
    </div>

    <div class="page" id="page-packages">
      <div class="page-header">
        <div><div class="page-title">Packages</div><div class="page-sub">Software available to deploy</div></div>
        <button class="btn btn-primary" onclick="openModal('modal-add-pkg')">+ Add package</button>
      </div>
      <div class="card">
        <table>
          <thead><tr><th>Name</th><th>Version</th><th>Source</th><th>Install command</th><th>Actions</th></tr></thead>
          <tbody id="packages-tbody"></tbody>
        </table>
      </div>
    </div>

    <div class="page" id="page-jobs">
      <div class="page-header">
        <div><div class="page-title">Jobs</div><div class="page-sub">Deployments and their status</div></div>
        <button class="btn btn-primary" onclick="openModal('modal-new-job')">+ New job</button>
      </div>
      <div class="card">
        <table>
          <thead><tr><th>Device</th><th>Package</th><th>Action</th><th>Status</th><th>Created</th><th>Result</th></tr></thead>
          <tbody id="jobs-tbody"></tbody>
        </table>
      </div>
    </div>

    <div class="page" id="page-logs">
      <div class="page-header">
        <div><div class="page-title">Logs</div><div class="page-sub">Every action, recorded</div></div>
        <button class="btn btn-ghost" onclick="loadLogs()">↻ Refresh</button>
      </div>
      <div class="card" id="logs-container"></div>
    </div>
  </main>
</div>

<!-- Add Package -->
<div class="modal-backdrop" id="modal-add-pkg">
  <div class="modal">
    <div class="modal-title">Add package</div>
    <div class="form-grid">
      <div class="form-field full">
        <label>Known app (optional — pre-fills commands)</label>
        <select id="pkg-app-id" onchange="prefillFromCatalog()">
          <option value="">— custom package —</option>
        </select>
      </div>
      <div class="form-field"><label>Name</label><input id="pkg-name" placeholder="e.g. Google Chrome"></div>
      <div class="form-field"><label>Version</label><input id="pkg-version" placeholder="e.g. 120.0"></div>
      <div class="form-field full"><label>Download URL</label><input id="pkg-url" placeholder="https://..."></div>
      <div class="form-field full"><label>SHA-256 hash</label><input id="pkg-sha256" placeholder="64-character hex hash of the installer" style="font-family:var(--mono);font-size:12px"></div>
      <div class="form-field full"><label>Install command <span class="text-muted">(use {file} for the downloaded path)</span></label><textarea id="pkg-install" placeholder="msiexec /i {file} /qn /norestart"></textarea></div>
      <div class="form-field full"><label>Uninstall command <span class="text-muted">(optional)</span></label><input id="pkg-uninstall" placeholder="msiexec /x {file} /qn /norestart"></div>
    </div>
    <div class="modal-actions">
      <button class="btn btn-ghost" onclick="closeModal('modal-add-pkg')">Cancel</button>
      <button class="btn btn-primary" onclick="addPackage()">Save package</button>
    </div>
  </div>
</div>

<!-- New Job -->
<div class="modal-backdrop" id="modal-new-job">
  <div class="modal">
    <div class="modal-title">Deploy a package</div>
    <div class="form-grid">
      <div class="form-field full"><label>Package</label><select id="job-package"></select></div>
      <div class="form-field full"><label>Action</label>
        <select id="job-action">
          <option value="install">Install</option>
          <option value="update">Update</option>
          <option value="uninstall">Uninstall</option>
        </select>
      </div>
      <div class="form-field full"><label>Target</label><select id="job-target"></select></div>
    </div>
    <div class="modal-actions">
      <button class="btn btn-ghost" onclick="closeModal('modal-new-job')">Cancel</button>
      <button class="btn btn-primary" onclick="createJob()">Push job</button>
    </div>
  </div>
</div>

<script>
const API = `https://${location.hostname}:8443/api`;

async function api(method, path, body) {
  const res = await fetch(API + path, {
    method,
    headers: {'Content-Type':'application/json'},
    body: body ? JSON.stringify(body) : undefined,
  });
  return res.json();
}

// Navigation
document.querySelectorAll('nav a').forEach(a => {
  a.addEventListener('click', e => {
    e.preventDefault();
    const page = a.dataset.page;
    document.querySelectorAll('nav a').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.page').forEach(x => x.classList.remove('active'));
    a.classList.add('active');
    document.getElementById('page-'+page).classList.add('active');
    if (page==='devices')  loadDevices();
    if (page==='packages') loadPackages();
    if (page==='jobs')     loadJobs();
    if (page==='logs')     loadLogs();
  });
});

function openModal(id) {
  document.getElementById(id).classList.add('open');
  if (id==='modal-new-job')  populateJobModal();
  if (id==='modal-add-pkg')  populateKnownApps();
}
function closeModal(id) { document.getElementById(id).classList.remove('open'); }
document.querySelectorAll('.modal-backdrop').forEach(b =>
  b.addEventListener('click', e => { if (e.target===b) b.classList.remove('open'); })
);

function toast(msg, type='success') {
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3000);
}

function relativeTime(iso) {
  const diff = Date.now() - new Date(iso).getTime();
  const s = Math.floor(diff/1000);
  if (s<60)    return `${s}s ago`;
  if (s<3600)  return `${Math.floor(s/60)}m ago`;
  if (s<86400) return `${Math.floor(s/3600)}h ago`;
  return new Date(iso).toLocaleDateString();
}

function statusBadge(s) {
  const map = {
    approved:['badge-green','● Online'],pending:['badge-amber','◐ Pending'],
    revoked:['badge-red','○ Revoked'],queued:['badge-blue','◌ Queued'],
    running:['badge-amber','◑ Running'],done:['badge-green','● Done'],failed:['badge-red','✕ Failed'],
  };
  const [cls,label] = map[s]||['badge-gray',s];
  return `<span class="badge ${cls}">${label}</span>`;
}

async function loadOverview() {
  const stats = await api('GET','/stats');
  document.getElementById('s-total').textContent   = stats.total_devices;
  document.getElementById('s-online').textContent  = stats.online_devices;
  document.getElementById('s-pending').textContent = stats.pending_devices;
  document.getElementById('s-failed').textContent  = stats.jobs_failed;
  const logs = await api('GET','/logs');
  const c = document.getElementById('overview-logs');
  if (!logs.length) { c.innerHTML='<div class="empty"><div class="empty-icon">📋</div><div class="empty-text">No activity yet</div></div>'; return; }
  c.innerHTML = logs.slice(0,30).map(l=>`
    <div class="log-line">
      <span class="log-time">${relativeTime(l.timestamp)}</span>
      <span class="log-msg log-${l.level}">${l.message}</span>
    </div>`).join('');
}

async function loadDevices() {
  const devices = await api('GET','/devices');
  const tbody = document.getElementById('devices-tbody');
  if (!devices.length) { tbody.innerHTML=`<tr><td colspan="6"><div class="empty"><div class="empty-icon">🖥</div><div class="empty-text">No devices yet</div></div></td></tr>`; return; }
  tbody.innerHTML = devices.map(d=>`
    <tr>
      <td><strong>${d.hostname}</strong></td>
      <td class="mono">${d.ip}</td>
      <td class="mono text-sm">${d.os_version||'—'}</td>
      <td class="text-muted text-sm">${relativeTime(d.last_seen)}</td>
      <td>${statusBadge(d.status)}</td>
      <td><div class="flex">
        ${d.status==='pending'  ? `<button class="btn btn-success btn-sm" onclick="approveDevice('${d.id}')">Approve</button>` : ''}
        ${d.status==='approved' ? `<button class="btn btn-ghost btn-sm" onclick="deployTo('${d.id}','${d.hostname}')">Deploy</button>` : ''}
        ${d.status!=='revoked'  ? `<button class="btn btn-danger btn-sm" onclick="revokeDevice('${d.id}')">Revoke</button>` : ''}
      </div></td>
    </tr>`).join('');
}

async function approveDevice(id) { await api('PATCH',`/devices/${id}/approve`); toast('Device approved'); loadDevices(); }
async function revokeDevice(id) {
  if (!confirm('Revoke this device?')) return;
  await api('PATCH',`/devices/${id}/revoke`); toast('Device revoked','error'); loadDevices();
}
function deployTo(deviceId, hostname) {
  openModal('modal-new-job');
  setTimeout(() => {
    const sel = document.getElementById('job-target');
    for (const opt of sel.options) { if (opt.value===deviceId) { opt.selected=true; break; } }
  }, 100);
}

let _knownApps = [];
async function populateKnownApps() {
  if (!_knownApps.length) _knownApps = await api('GET','/known-apps');
  const sel = document.getElementById('pkg-app-id');
  sel.innerHTML = '<option value="">— custom package —</option>' +
    _knownApps.map(a=>`<option value="${a.id}">${a.name}</option>`).join('');
}
function prefillFromCatalog() {
  const id  = document.getElementById('pkg-app-id').value;
  const app = _knownApps.find(a=>a.id===id);
  if (!app) return;
  document.getElementById('pkg-name').value      = app.name;
  document.getElementById('pkg-install').value   = app.install_cmd;
  document.getElementById('pkg-uninstall').value = app.uninstall_cmd||'';
}

async function loadPackages() {
  const pkgs = await api('GET','/packages');
  const tbody = document.getElementById('packages-tbody');
  if (!pkgs.length) { tbody.innerHTML=`<tr><td colspan="5"><div class="empty"><div class="empty-icon">📦</div><div class="empty-text">No packages yet</div></div></td></tr>`; return; }
  tbody.innerHTML = pkgs.map(p=>`
    <tr>
      <td><strong>${p.name}</strong></td>
      <td class="mono text-sm">${p.version}</td>
      <td class="mono text-sm" style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${p.source_url}">${p.source_url}</td>
      <td class="mono text-sm">${p.install_cmd}</td>
      <td><button class="btn btn-danger btn-sm" onclick="deletePackage('${p.id}')">Delete</button></td>
    </tr>`).join('');
}

async function addPackage() {
  const body = {
    app_id:        document.getElementById('pkg-app-id').value,
    name:          document.getElementById('pkg-name').value,
    version:       document.getElementById('pkg-version').value,
    source_url:    document.getElementById('pkg-url').value,
    sha256:        document.getElementById('pkg-sha256').value,
    install_cmd:   document.getElementById('pkg-install').value,
    uninstall_cmd: document.getElementById('pkg-uninstall').value,
  };
  if (!body.name||!body.source_url||!body.sha256||!body.install_cmd) { toast('Fill in all required fields','error'); return; }
  const res = await api('POST','/packages',body);
  if (res.ok) { toast('Package saved'); closeModal('modal-add-pkg'); loadPackages(); }
  else toast(res.error||'Error','error');
}

async function deletePackage(id) {
  if (!confirm('Delete this package?')) return;
  const res = await api('DELETE',`/packages/${id}`);
  if (res.ok) toast('Package deleted');
  else toast(res.error||'Error','error');
  loadPackages();
}

async function loadJobs() {
  const jobs = await api('GET','/jobs');
  const tbody = document.getElementById('jobs-tbody');
  if (!jobs.length) { tbody.innerHTML=`<tr><td colspan="6"><div class="empty"><div class="empty-icon">⚙️</div><div class="empty-text">No jobs yet</div></div></td></tr>`; return; }
  tbody.innerHTML = jobs.map(j=>`
    <tr>
      <td><strong>${j.hostname}</strong></td>
      <td>${j.pkg_name}</td>
      <td><span class="mono text-sm">${j.action}</span></td>
      <td>${statusBadge(j.status)}</td>
      <td class="text-muted text-sm">${relativeTime(j.created_at)}</td>
      <td class="mono text-sm" style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${j.result}">${j.result||'—'}</td>
    </tr>`).join('');
}

async function populateJobModal() {
  const [pkgs,devices] = await Promise.all([api('GET','/packages'),api('GET','/devices')]);
  const approved = devices.filter(d=>d.status==='approved');
  document.getElementById('job-package').innerHTML = pkgs.map(p=>`<option value="${p.id}">${p.name} ${p.version}</option>`).join('');
  document.getElementById('job-target').innerHTML =
    `<option value="all">All approved devices</option>` +
    approved.map(d=>`<option value="${d.id}">${d.hostname} (${d.ip})</option>`).join('');
}

async function createJob() {
  const pkgId  = document.getElementById('job-package').value;
  const action = document.getElementById('job-action').value;
  const target = document.getElementById('job-target').value;
  const body   = {package_id:pkgId,action};
  if (target==='all') body.group='default';
  else body.device_id=target;
  const res = await api('POST','/jobs',body);
  if (res.ok) { toast(`${res.job_ids.length} job(s) queued`); closeModal('modal-new-job'); loadJobs(); }
  else toast(res.error||'Error','error');
}

async function loadLogs() {
  const logs = await api('GET','/logs');
  const c = document.getElementById('logs-container');
  if (!logs.length) { c.innerHTML='<div class="empty"><div class="empty-icon">📋</div><div class="empty-text">No logs yet</div></div>'; return; }
  c.innerHTML = logs.map(l=>`
    <div class="log-line">
      <span class="log-time">${new Date(l.timestamp).toLocaleString()}</span>
      <span class="log-msg log-${l.level}">${l.message}</span>
    </div>`).join('');
}

async function checkStatus() {
  try {
    await fetch(`https://${location.hostname}:8443/health`);
    document.getElementById('status-dot').className  = 'dot';
    document.getElementById('status-text').textContent = 'Server online';
  } catch {
    document.getElementById('status-dot').className  = 'dot offline';
    document.getElementById('status-text').textContent = 'Server offline';
  }
}

function refresh() { loadOverview(); checkStatus(); }
loadOverview();
checkStatus();
setInterval(checkStatus,  30000);
setInterval(loadOverview, 60000);
</script>
</body>
</html>
"""

# ─── Servers ──────────────────────────────────────────────────────────────────

def run_servers():
    PACKAGES_DIR.mkdir(exist_ok=True)
    init_db()

    api_port  = CONFIG["api_port"]
    dash_port = CONFIG["dash_port"]

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(CERT_PATH), str(KEY_PATH))

    api_server  = HTTPServer(("0.0.0.0", api_port),  PatchPilotHandler)
    dash_server = HTTPServer(("0.0.0.0", dash_port), DashboardHandler)
    api_server.socket = ctx.wrap_socket(api_server.socket, server_side=True)

    threading.Thread(target=api_server.serve_forever,  daemon=True).start()
    threading.Thread(target=dash_server.serve_forever, daemon=True).start()

    print(f"{APP_NAME} v{VERSION} running")
    print(f"  Dashboard → http://localhost:{dash_port}")
    print(f"  API       → https://localhost:{api_port}")
    print(f"  job_secret (for Agent Builder): {CONFIG['job_secret']}")


# ─── Dashboard HTTP handler ───────────────────────────────────────────────────

class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass
    def do_GET(self):
        body = DASHBOARD_HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)


# ─── Windows service ──────────────────────────────────────────────────────────

if platform.system() == "Windows":
    try:
        import win32serviceutil, win32service, win32event, servicemanager

        class PatchPilotService(win32serviceutil.ServiceFramework):
            _svc_name_         = "PatchPilot"
            _svc_display_name_ = "PatchPilot Server"
            _svc_description_  = "Patch management server — PatchPilot"

            def __init__(self, args):
                win32serviceutil.ServiceFramework.__init__(self, args)
                self._stop = win32event.CreateEvent(None, 0, 0, None)

            def SvcStop(self):
                self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
                win32event.SetEvent(self._stop)

            def SvcDoRun(self):
                servicemanager.LogMsg(
                    servicemanager.EVENTLOG_INFORMATION_TYPE,
                    servicemanager.PYS_SERVICE_STARTED,
                    (self._svc_name_, ""),
                )
                run_servers()
                win32event.WaitForSingleObject(self._stop, win32event.INFINITE)

    except ImportError:
        pass


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    args = sys.argv[1:]

    if "--setup" in args or not CERT_PATH.exists():
        generate_certs()
        init_db()
        print(f"\n[setup] Done. Run 'python server.py' to start.")
        sys.exit(0)

    if platform.system() == "Windows" and args and args[0] in ("/install", "/uninstall", "/start", "/stop"):
        try:
            win32serviceutil.HandleCommandLine(PatchPilotService)
        except Exception as e:
            print(f"Service error: {e}")
        sys.exit(0)

    run_servers()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\nShutting down.")
