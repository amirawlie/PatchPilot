"""
shared.py — the foundation everything else builds on.
Crypto, data models, and constants used by server, agent, and builder.
"""

import hashlib
import hmac
import json
import os
import shlex
import ssl
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

# ─── Constants ────────────────────────────────────────────────────────────────

APP_NAME       = "PatchPilot"
VERSION        = "1.0.0"
AGENT_VERSION  = VERSION
DEFAULT_PORT   = 8443
DASHBOARD_PORT = 8080
POLL_INTERVAL  = 30        # seconds between agent heartbeats
JWT_LIFETIME   = 28800     # 8 hours

# ── Executor whitelist ─────────────────────────────────────────────────────────
# cmd and powershell removed — they are unrestricted shells, not safe executors.
# If you need PowerShell for a specific task, use a signed .ps1 path instead.
ALLOWED_EXECUTORS = [
    "msiexec",
    "winget",
    "choco",
]

# ── Known-app catalog ──────────────────────────────────────────────────────────
# Each entry is the canonical definition for one app PatchPilot knows about.
# To add a new app in a future release, append one block here and ship it.
# Nothing else needs to change — the server, agent, and builder all read this.
#
# Fields:
#   id           — stable slug, never changes between versions
#   name         — display name shown in the dashboard
#   publisher    — used for logging / audit trail
#   install_cmd  — {file} is replaced with the downloaded installer path
#   uninstall_cmd— {version} may be substituted from the package record
#   update_cmd   — if empty, falls back to install_cmd (re-run installer)
#   executor     — must be in ALLOWED_EXECUTORS; checked before download
#   version_key  — registry path used by the server to auto-detect version
#                  (optional, not used by the agent)

KNOWN_APPS: list[dict] = [
    # ── Browsers ──────────────────────────────────────────────────────────────
    {
        "id":            "chrome",
        "name":          "Google Chrome",
        "publisher":     "Google LLC",
        "executor":      "msiexec",
        "install_cmd":   'msiexec /i {file} /qn /norestart',
        "uninstall_cmd": 'msiexec /x {file} /qn /norestart',
        "update_cmd":    "",          # re-run installer — Chrome handles delta
        "version_key":   r"HKLM\SOFTWARE\Google\Chrome\BLBeacon",
    },
    {
        "id":            "firefox",
        "name":          "Mozilla Firefox",
        "publisher":     "Mozilla Corporation",
        "executor":      "msiexec",
        "install_cmd":   'msiexec /i {file} /qn /norestart',
        "uninstall_cmd": 'msiexec /x {file} /qn /norestart',
        "update_cmd":    "",
        "version_key":   r"HKLM\SOFTWARE\Mozilla\Mozilla Firefox",
    },

    # ── Compression ───────────────────────────────────────────────────────────
    {
        "id":            "winrar",
        "name":          "WinRAR",
        "publisher":     "RARLAB",
        "executor":      "winget",
        "install_cmd":   'winget install --id RARLab.WinRAR --silent --accept-package-agreements --accept-source-agreements',
        "uninstall_cmd": 'winget uninstall --id RARLab.WinRAR --silent',
        "update_cmd":    'winget upgrade --id RARLab.WinRAR --silent --accept-package-agreements --accept-source-agreements',
        "version_key":   "",
    },
    {
        "id":            "7zip",
        "name":          "7-Zip",
        "publisher":     "Igor Pavlov",
        "executor":      "msiexec",
        "install_cmd":   'msiexec /i {file} /qn /norestart',
        "uninstall_cmd": 'msiexec /x {file} /qn /norestart',
        "update_cmd":    "",
        "version_key":   r"HKLM\SOFTWARE\7-Zip",
    },

    # ── Media ─────────────────────────────────────────────────────────────────
    {
        "id":            "vlc",
        "name":          "VLC Media Player",
        "publisher":     "VideoLAN",
        "executor":      "msiexec",
        "install_cmd":   'msiexec /i {file} /qn /norestart',
        "uninstall_cmd": 'msiexec /x {file} /qn /norestart',
        "update_cmd":    "",
        "version_key":   r"HKLM\SOFTWARE\VideoLAN\VLC",
    },

    # ── Text editors ──────────────────────────────────────────────────────────
    {
        "id":            "notepadpp",
        "name":          "Notepad++",
        "publisher":     "Notepad++ Team",
        "executor":      "msiexec",
        "install_cmd":   'msiexec /i {file} /qn /norestart',
        "uninstall_cmd": 'msiexec /x {file} /qn /norestart',
        "update_cmd":    "",
        "version_key":   r"HKLM\SOFTWARE\Notepad++",
    },

    # ── Adobe ─────────────────────────────────────────────────────────────────
    # Adobe products use the Adobe Update Server Setup Tool (AUSST) or the
    # standard MSI/EXE from the Adobe Admin Console bulk download.
    # install_cmd assumes the MSI variant from Admin Console packaging.
    {
        "id":            "adobe_reader",
        "name":          "Adobe Acrobat Reader",
        "publisher":     "Adobe Inc.",
        "executor":      "msiexec",
        "install_cmd":   'msiexec /i {file} /qn /norestart TRANSFORMS=AcroRead.mst',
        "uninstall_cmd": 'msiexec /x {file} /qn /norestart',
        "update_cmd":    "",
        "version_key":   r"HKLM\SOFTWARE\Adobe\Acrobat Reader",
    },
    {
        "id":            "adobe_acrobat",
        "name":          "Adobe Acrobat (Pro/Standard)",
        "publisher":     "Adobe Inc.",
        "executor":      "msiexec",
        "install_cmd":   'msiexec /i {file} /qn /norestart',
        "uninstall_cmd": 'msiexec /x {file} /qn /norestart',
        "update_cmd":    "",
        "version_key":   r"HKLM\SOFTWARE\Adobe\Adobe Acrobat",
    },
]

# Quick lookup by id — used by server and builder
KNOWN_APPS_BY_ID: dict[str, dict] = {a["id"]: a for a in KNOWN_APPS}


# ─── Data models ──────────────────────────────────────────────────────────────

@dataclass
class Device:
    id:            str
    hostname:      str
    ip:            str
    os_version:    str
    agent_version: str
    status:        str    # "pending", "approved", "revoked"
    last_seen:     str
    group:         str           = "default"
    jwt:           Optional[str] = None

@dataclass
class Package:
    id:            str
    name:          str
    version:       str
    app_id:        str    # must match a KNOWN_APPS entry id
    source_url:    str
    sha256:        str    # verified before execution — never skipped
    install_cmd:   str
    uninstall_cmd: str  = ""
    update_cmd:    str  = ""
    created_at:    str  = ""

@dataclass
class Job:
    id:          str
    device_id:   str
    package_id:  str
    action:      str    # "install", "uninstall", "update"
    status:      str    # "queued", "running", "done", "failed"
    created_at:  str = ""
    finished_at: str = ""
    result:      str = ""
    signature:   str = ""   # HMAC — verified by agent before execution

@dataclass
class LogEntry:
    id:        str
    device_id: str
    job_id:    str
    message:   str
    level:     str    # "info", "warn", "error"
    timestamp: str


# ─── Time / ID helpers ────────────────────────────────────────────────────────

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def new_id() -> str:
    return str(uuid.uuid4())


# ─── JWT ──────────────────────────────────────────────────────────────────────

def _b64(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _unb64(s: str) -> bytes:
    import base64
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def jwt_sign(payload: dict, secret: str) -> str:
    header  = _b64(b'{"alg":"HS256","typ":"JWT"}')
    body    = _b64(json.dumps(payload).encode())
    message = f"{header}.{body}".encode()
    sig     = _b64(hmac.new(secret.encode(), message, hashlib.sha256).digest())
    return f"{header}.{body}.{sig}"

def jwt_verify(token: str, secret: str) -> Optional[dict]:
    try:
        header, body, sig = token.split(".")
        message  = f"{header}.{body}".encode()
        expected = _b64(hmac.new(secret.encode(), message, hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(_unb64(body))
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception:
        return None

def jwt_payload(device_id: str, secret: str) -> str:
    return jwt_sign({
        "sub": device_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_LIFETIME,
    }, secret)


# ─── Job signing ──────────────────────────────────────────────────────────────

def sign_job(job_id: str, device_id: str, action: str, secret: str) -> str:
    """
    Server signs each job with a secret the agent never has.
    The agent verifies the signature before executing anything.
    This means even a fully compromised server DB cannot forge new jobs
    without also having the job_secret from the server config file.
    """
    message = f"{job_id}:{device_id}:{action}".encode()
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()

def verify_job_signature(job: Job, secret: str) -> bool:
    """
    Full HMAC verification. Both the agent and server call this.
    The secret is passed in by the caller — agent gets it from its
    baked-in config; server gets it from the server config file.
    """
    expected = sign_job(job.id, job.device_id, job.action, secret)
    return hmac.compare_digest(job.signature, expected)


# ─── Package integrity ────────────────────────────────────────────────────────

def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def verify_package(path: str, expected_hash: str) -> bool:
    if not expected_hash:
        return False   # reject if server forgot to set a hash
    return hmac.compare_digest(sha256_file(path), expected_hash)


# ─── TLS cert fingerprint ─────────────────────────────────────────────────────

def cert_fingerprint(cert_path: str) -> str:
    with open(cert_path, "rb") as f:
        data = f.read()
    return hashlib.sha256(data).hexdigest()

def fetch_server_fingerprint(host: str, port: int) -> Optional[str]:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(
            __import__("socket").create_connection((host, port), timeout=5),
            server_hostname=host
        ) as s:
            der = s.getpeercert(binary_form=True)
        return hashlib.sha256(der).hexdigest()
    except Exception:
        return None

def verify_server_cert(host: str, port: int, expected_fingerprint: str) -> bool:
    actual = fetch_server_fingerprint(host, port)
    if not actual:
        return False
    return hmac.compare_digest(actual, expected_fingerprint)


# ─── Executor whitelist ───────────────────────────────────────────────────────

def is_allowed_executor(cmd: str) -> bool:
    """
    Parse the command properly (handles quoted paths) and check the
    executable basename against the whitelist.
    Previously used a naive split()[0] which could be fooled by
    a quoted path like '"C:\\Windows\\system32\\cmd.exe" /c ...'.
    """
    try:
        tokens = shlex.split(cmd, posix=False)
    except ValueError:
        return False
    if not tokens:
        return False
    exe = tokens[0].strip('"').strip("'")
    # Take just the filename, strip .exe, lower-case
    basename = os.path.basename(exe).lower().replace(".exe", "")
    return basename in ALLOWED_EXECUTORS


# ─── Command injection guard ──────────────────────────────────────────────────

# Characters that could break out of a quoted argument and inject shell commands.
# We check the {file} substitution value (the temp path) against this set.
_SHELL_METACHARACTERS = set('&|;<>(){}$`"\'\\\n\r')

def safe_file_path(path: str) -> bool:
    """
    Return True only if the path is safe to embed in a shell command.
    A legitimate Windows temp path will never contain these characters.
    """
    return not any(c in _SHELL_METACHARACTERS for c in path)
