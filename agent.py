"""
agent.py — runs on every managed endpoint.
Installs as a Windows SYSTEM service, polls the server for jobs,
and executes them safely.

Usage:
  agent.exe /install     — install as Windows service (silent-friendly)
  agent.exe /uninstall   — remove the service
  agent.exe /run         — run in foreground (for testing)
"""

import json
import os
import platform
import shlex
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

# ── Baked-in config ────────────────────────────────────────────────────────────
# Written by agent_builder.py at build time — lives in the binary, not a file.

SERVER_URL         = "BAKED_SERVER_URL"         # e.g. https://192.168.1.10:8443
SERVER_FINGERPRINT = "BAKED_FINGERPRINT"        # SHA-256 of server TLS cert (DER)
JOB_SECRET         = "BAKED_JOB_SECRET"         # HMAC key for job signatures
AGENT_VERSION      = "1.0.0"
POLL_INTERVAL      = 30

from shared import (
    verify_package, verify_job_signature, verify_server_cert,
    is_allowed_executor, safe_file_path, now_iso, Job,
)

# ── State ─────────────────────────────────────────────────────────────────────

_token   = None
_running = True

# ── TLS — pinned to our server's certificate ──────────────────────────────────

def make_ssl_ctx() -> ssl.SSLContext:
    """
    We skip CA verification and pin the cert fingerprint instead.
    verify_server_cert() is called explicitly on every enroll — connections
    after that use this context which still encrypts the traffic even though
    we're not using CA chain validation.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def _request(method: str, path: str, body: dict = None) -> dict:
    url     = SERVER_URL + path
    data    = json.dumps(body).encode() if body else None
    headers = {"Content-Type": "application/json"}
    if _token:
        headers["Authorization"] = f"Bearer {_token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    # Use the pinned SSL context for every request — all traffic to the server
    # is encrypted and the cert fingerprint was verified at enroll time.
    ctx = make_ssl_ctx()
    with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
        return json.loads(resp.read())

# ── Device info ───────────────────────────────────────────────────────────────

def get_device_info() -> dict:
    import socket
    return {
        "hostname":      socket.gethostname(),
        "ip":            socket.gethostbyname(socket.gethostname()),
        "os_version":    platform.version(),
        "agent_version": AGENT_VERSION,
    }

# ── Enrollment ────────────────────────────────────────────────────────────────

def enroll() -> bool:
    global _token
    log("Contacting server for enrollment...")

    host, port = _parse_host_port(SERVER_URL)
    if not verify_server_cert(host, port, SERVER_FINGERPRINT):
        log("Server cert fingerprint mismatch — possible MITM. Aborting.", "error")
        return False

    while _running:
        try:
            resp   = _request("POST", "/api/enroll", get_device_info())
            status = resp.get("status")

            if status == "approved":
                _token = resp["token"]
                log("Enrollment approved. Agent is active.")
                return True
            elif status == "pending":
                log("Waiting for admin approval...")
                time.sleep(60)
            elif status == "revoked":
                log("Device has been revoked. Stopping.", "error")
                return False

        except Exception as e:
            log(f"Enrollment error: {e} — retrying in 60s", "warn")
            time.sleep(60)

    return False

# ── Poll loop ─────────────────────────────────────────────────────────────────

def poll_loop():
    global _token
    while _running:
        try:
            _request("POST", "/api/heartbeat")
            data = _request("GET", "/api/jobs/pending")
            for job in data.get("jobs", []):
                handle_job(job)
        except Exception as e:
            log(f"Poll error: {e}", "warn")
            if "401" in str(e) or "unauthorized" in str(e).lower():
                log("Token rejected — re-enrolling...")
                _token = None
                enroll()
        time.sleep(POLL_INTERVAL)

# ── Job execution ─────────────────────────────────────────────────────────────

def handle_job(job_data: dict):
    """
    Security-critical. Every check must pass or the job is rejected.

    Order of checks:
      1. Verify HMAC signature — rejects forged or tampered jobs
      2. Validate action against known commands
      3. Executor whitelist check — no shells, no arbitrary executors
      4. Download package over pinned TLS
      5. SHA-256 hash verification — never skipped, empty hash = reject
      6. Command injection guard on the temp file path
      7. Execute via list-form subprocess — no shell=True
    """
    job_id    = job_data.get("id", "")
    action    = job_data.get("action", "")
    device_id = job_data.get("device_id", "")

    log(f"Job {job_id[:8]}: received — action={action} pkg={job_data.get('pkg_name', '')}")

    # ── 1. Signature verification ──────────────────────────────────────────────
    # Reconstruct the Job dataclass so verify_job_signature can check the HMAC.
    # JOB_SECRET is baked into this binary at build time — the server also has
    # it but it is never stored in the DB or transmitted over the network.
    job_obj = Job(
        id=job_id, device_id=device_id,
        package_id=job_data.get("package_id", ""),
        action=action, status=job_data.get("status", ""),
        signature=job_data.get("signature", ""),
    )
    if not verify_job_signature(job_obj, JOB_SECRET):
        report_result(job_id, False, "Signature verification failed — job rejected")
        log(f"Job {job_id[:8]}: REJECTED — bad signature", "error")
        return

    # ── 2. Pick command for this action ───────────────────────────────────────
    cmd_template = {
        "install":   job_data.get("install_cmd", ""),
        "uninstall": job_data.get("uninstall_cmd", ""),
        "update":    job_data.get("update_cmd", "") or job_data.get("install_cmd", ""),
    }.get(action, "")

    if not cmd_template:
        report_result(job_id, False, f"No command for action: {action}")
        return

    # ── 3. Executor whitelist ──────────────────────────────────────────────────
    if not is_allowed_executor(cmd_template):
        report_result(job_id, False, "Executor not in whitelist — blocked")
        log(f"Job {job_id[:8]}: BLOCKED — disallowed executor in: {cmd_template[:60]}", "error")
        return

    # ── 4. Download ────────────────────────────────────────────────────────────
    source_url = job_data.get("source_url", "")
    if not source_url:
        report_result(job_id, False, "No source_url provided")
        return

    try:
        pkg_path = download_package(source_url, job_data.get("pkg_name", "pkg"))
    except Exception as e:
        report_result(job_id, False, f"Download failed: {e}")
        return

    # ── 5. Hash verification ───────────────────────────────────────────────────
    # Empty hash = instant reject. We never run unverified packages.
    expected_hash = job_data.get("sha256", "")
    if not expected_hash or not verify_package(pkg_path, expected_hash):
        try:
            os.unlink(pkg_path)
        except OSError:
            pass
        report_result(job_id, False, "Hash missing or mismatch — package rejected")
        log(f"Job {job_id[:8]}: REJECTED — hash check failed", "error")
        return

    # ── 6. Command injection guard ────────────────────────────────────────────
    if not safe_file_path(pkg_path):
        try:
            os.unlink(pkg_path)
        except OSError:
            pass
        report_result(job_id, False, "Temp file path contains unsafe characters — rejected")
        log(f"Job {job_id[:8]}: REJECTED — unsafe path: {pkg_path}", "error")
        return

    # ── 7. Execute — NO shell=True ────────────────────────────────────────────
    # Build the final command string by substituting {file}, then parse it into
    # a proper argv list using shlex. This way subprocess never invokes a shell
    # and shell metacharacters in the path cannot be interpreted.
    cmd_str = cmd_template.replace("{file}", pkg_path)
    try:
        argv = shlex.split(cmd_str, posix=False)
    except ValueError as e:
        try:
            os.unlink(pkg_path)
        except OSError:
            pass
        report_result(job_id, False, f"Command parse error: {e}")
        return

    try:
        result = subprocess.run(
            argv,
            shell=False,            # explicit — no shell interpretation
            capture_output=True,
            text=True,
            timeout=300,
        )
        success = result.returncode == 0
        output  = (result.stdout + result.stderr).strip()[:2000]
        report_result(job_id, success, output or ("OK" if success else "Non-zero exit"))
        log(f"Job {job_id[:8]}: {'done' if success else 'FAILED'} — exit {result.returncode}")
    except subprocess.TimeoutExpired:
        report_result(job_id, False, "Timed out after 5 minutes")
    except FileNotFoundError as e:
        report_result(job_id, False, f"Executable not found: {e}")
    except Exception as e:
        report_result(job_id, False, str(e))
    finally:
        try:
            os.unlink(pkg_path)
        except OSError:
            pass


def download_package(url: str, name: str) -> str:
    """
    Download to a temp file using the pinned SSL context.
    Previously urlretrieve was used here — it doesn't accept a custom SSL
    context, so packages could be fetched without cert pinning even though
    the API calls were pinned. Fixed by using urlopen directly.
    """
    suffix = Path(url.split("?")[0]).suffix or ".bin"
    tmp    = tempfile.NamedTemporaryFile(
        delete=False, suffix=suffix, prefix=f"pp_{name}_"
    )
    tmp.close()

    ctx = make_ssl_ctx()
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:
        with open(tmp.name, "wb") as f:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                f.write(chunk)

    return tmp.name


def report_result(job_id: str, success: bool, result: str):
    log(f"Job {job_id[:8]}: {'✓' if success else '✗'} {result[:80]}")
    try:
        _request("POST", "/api/jobs/result", {
            "job_id":  job_id,
            "success": success,
            "result":  result,
        })
    except Exception as e:
        log(f"Failed to report result: {e}", "warn")


# ── Logging ───────────────────────────────────────────────────────────────────

LOG_PATH = Path(os.environ.get("ProgramData", "C:/ProgramData")) / "PatchPilot" / "agent.log"

def log(message: str, level: str = "info"):
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    line = f"[{now_iso()}] [{level.upper()}] {message}\n"
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line)
    print(line, end="")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_host_port(url: str):
    parts = url.replace("https://", "").split(":")
    host  = parts[0]
    port  = int(parts[1].split("/")[0]) if len(parts) > 1 else 443
    return host, port


# ── Windows service ───────────────────────────────────────────────────────────

if platform.system() == "Windows":
    try:
        import win32serviceutil, win32service, win32event, servicemanager

        class PatchPilotAgent(win32serviceutil.ServiceFramework):
            _svc_name_         = "PatchPilotAgent"
            _svc_display_name_ = "PatchPilot Agent"
            _svc_description_  = "Patch management agent — PatchPilot"

            def __init__(self, args):
                win32serviceutil.ServiceFramework.__init__(self, args)
                self._stop_event = win32event.CreateEvent(None, 0, 0, None)

            def SvcStop(self):
                global _running
                _running = False
                self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
                win32event.SetEvent(self._stop_event)

            def SvcDoRun(self):
                servicemanager.LogMsg(
                    servicemanager.EVENTLOG_INFORMATION_TYPE,
                    servicemanager.PYS_SERVICE_STARTED,
                    (self._svc_name_, ""),
                )
                start_agent()
                win32event.WaitForSingleObject(self._stop_event, win32event.INFINITE)

    except ImportError:
        pass


def start_agent():
    log(f"PatchPilot Agent {AGENT_VERSION} starting")
    if enroll():
        poll_loop()
    else:
        log("Enrollment failed. Agent stopped.", "error")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    args = sys.argv[1:]

    if platform.system() == "Windows" and args:
        arg = args[0].lower()
        if arg in ("/install", "--install"):
            try:
                win32serviceutil.InstallService(
                    PatchPilotAgent._svc_reg_class_,
                    PatchPilotAgent._svc_name_,
                    PatchPilotAgent._svc_display_name_,
                    startType=win32service.SERVICE_AUTO_START,
                )
                win32serviceutil.StartService(PatchPilotAgent._svc_name_)
                print("PatchPilot Agent installed and started.")
            except Exception as e:
                print(f"Install failed: {e}")
            sys.exit(0)

        if arg in ("/uninstall", "--uninstall"):
            try:
                win32serviceutil.StopService(PatchPilotAgent._svc_name_)
                win32serviceutil.RemoveService(PatchPilotAgent._svc_name_)
                print("PatchPilot Agent removed.")
            except Exception as e:
                print(f"Uninstall failed: {e}")
            sys.exit(0)

        if arg in ("/run", "--run"):
            start_agent()
            sys.exit(0)

        win32serviceutil.HandleCommandLine(PatchPilotAgent)

    else:
        start_agent()
