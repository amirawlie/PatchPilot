# ⚡ PatchPilot

**Self-hosted patch management for Windows fleets — no cloud, no subscriptions, no nonsense.**

PatchPilot lets you deploy software packages to any number of Windows machines from a single dashboard. Agents run as SYSTEM services, poll for jobs, verify every package before executing, and report back. The server and dashboard run on a machine you control.

---

## Features

- **Zero-trust agent design** — agents pin the server's TLS certificate fingerprint at build time; MITM attacks are rejected before a single byte of job data is processed
- **Package integrity** — every package is SHA-256 verified before execution; mismatches are rejected and logged
- **Executor whitelist** — only `msiexec`, `winget`, `choco`, `powershell`, and `cmd` are allowed; arbitrary shell commands are blocked
- **Device approval flow** — new agents register as `pending`; an admin must approve them in the dashboard before any jobs are dispatched
- **Signed jobs** — the server HMAC-signs each job; agents perform structural verification before running anything
- **Self-signed TLS** — the server generates its own cert on first run; the fingerprint is baked into each agent binary by the Agent Builder
- **No external dependencies** — server, agent, and builder are pure Python + stdlib; the only extras are `pywin32` (Windows service) and `pyinstaller` (build)

---

## Architecture

```
┌─────────────────────┐        HTTPS :8443          ┌──────────────────────┐
│   Admin Dashboard   │ ◄────────────────────────►  │    PatchPilot Server │
│   (browser, :8080)  │                             │  server.py + SQLite  │
└─────────────────────┘                             └──────────┬───────────┘
                                                               │
                                              HTTPS :8443 (TLS-pinned)
                                                               │
                                              ┌────────────────┼────────────────┐
                                              ▼                ▼                ▼
                                        ┌──────────┐    ┌──────────┐    ┌──────────┐
                                        │ Agent    │    │ Agent    │    │ Agent    │
                                        │ (Win SVC)│    │(Win SVC) │    │ (Win SVC)│
                                        └──────────┘    └──────────┘    └──────────┘
```

| Component | File | Role |
|---|---|---|
| **Server** | `server.py` | HTTPS API + embedded web dashboard, SQLite database |
| **Agent** | `agent.py` | Windows SYSTEM service — polls for jobs, executes packages |
| **Agent Builder** | `agent_builder.py` | GUI tool that bakes server URL + cert fingerprint into `agent.exe` |
| **Shared** | `shared.py` | Crypto, data models, and constants used by all three |

---

## Getting Started

### 1. Set up the server

Requires Python 3.10+ and `openssl` on PATH.

```bash
pip install pywin32          # Windows only, for service support
python server.py --setup     # generates TLS cert + SQLite DB, prints fingerprint
python server.py             # start API (:8443) and dashboard (:8080)
```

The dashboard is at `http://localhost:8080`. The first run also prints the server's cert fingerprint — keep it handy for the next step.

To install as a Windows service (run as SYSTEM, auto-start):

```cmd
python server.py /install
```

### 2. Build an agent

Run `agent_builder.py` on the server machine (or any machine that can reach the server):

```bash
python agent_builder.py
```

1. Enter the server IP and port (default `8443`)
2. Click **Test connection** — the builder fetches and pins the cert fingerprint
3. Click **Build agent.exe** — PyInstaller produces a standalone binary in `dist/`

```bash
pip install pyinstaller      # required for the build step
```

### 3. Deploy the agent

Copy `PatchPilot-Agent.exe` to the target machine and install it as a service:

```cmd
PatchPilot-Agent.exe /install
```

The agent registers itself with the server as `pending`. Approve it in the dashboard under **Devices**.

### 4. Push a package

1. Go to **Packages** in the dashboard → **Add package**
2. Fill in the name, download URL, SHA-256 hash, and install command (e.g. `msiexec /i {file} /qn`)
3. Go to **Jobs** → **New job**, pick a package, an action, and a target device or group
4. The agent picks up the job on its next poll (default every 30 seconds), verifies the package, and reports back

---

## Security model

| Threat | Mitigation |
|---|---|
| MITM on agent→server traffic | TLS cert fingerprint pinned at build time |
| Tampered package on download | SHA-256 verified before execution; mismatch = rejection |
| Forged job from rogue server | Job signed by server with HMAC-SHA256; agent checks signature |
| Arbitrary command execution | Executor whitelist enforced in `shared.py`; first word of command must be in `ALLOWED_EXECUTORS` |
| Unapproved device running jobs | Devices start as `pending`; no JWT issued until admin approves |
| JWT replay after revocation | Device status checked on every authenticated request |

> **Note:** The self-signed TLS cert is generated locally and never leaves your network. The cert fingerprint is the trust anchor — guard it like a key.

---

## Configuration

The server writes `server.json` on first run:

```json
{
  "jwt_secret":  "<random 32-byte hex>",
  "job_secret":  "<random 32-byte hex>",
  "api_port":    8443,
  "dash_port":   8080,
  "version":     "1.0.0"
}
```

Secrets are generated once with `secrets.token_hex(32)` and never regenerated unless you delete the file.

Agent config is baked into the binary at build time (no config files on endpoints):

| Value | Source |
|---|---|
| `SERVER_URL` | Entered in Agent Builder |
| `SERVER_FINGERPRINT` | Fetched from live server by Agent Builder |
| `POLL_INTERVAL` | Hardcoded to 30 s (edit `agent.py` before building) |

---

## File layout

```
patchpilot/
├── server.py           # Server + dashboard
├── agent.py            # Endpoint agent
├── agent_builder.py    # GUI builder
├── shared.py           # Shared crypto + models
├── certs/              # Auto-generated TLS cert (created on --setup)
│   ├── server.crt
│   └── server.key
├── packages/           # Uploaded package storage
├── patchpilot.db       # SQLite database
├── server.json         # Server config + secrets
└── dist/               # agent_builder output directory
    └── PatchPilot-Agent.exe
```

---

## Requirements

**Server & Builder**
- Python 3.10+
- `pywin32` (Windows service support)
- `pyinstaller` (agent build only)
- `openssl` on PATH (cert generation)

**Agent** (after building)
- Windows 10 / Server 2016 or later
- No Python required — fully standalone `.exe`

---

## Roadmap

- [ ] Group-based targeting (currently all devices share the `default` group)
- [ ] Package upload (currently URL-only)
- [ ] Scheduled jobs
- [ ] Multi-admin support with role-based access
- [ ] Agent auto-update
- [ ] Linux agent

---

## License

MIT — do whatever you want, just don't hold me liable.
