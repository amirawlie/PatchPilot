"""
agent_builder.py — the tool admins use to create agent.exe files.
Fill in the server address and job secret, test the connection, click Build.
The resulting agent.exe has everything baked in.
"""

import hashlib
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from shared import fetch_server_fingerprint, AGENT_VERSION

# ─── Paths ────────────────────────────────────────────────────────────────────

BASE_DIR   = Path(__file__).parent
AGENT_SRC  = BASE_DIR / "agent.py"
SHARED_SRC = BASE_DIR / "shared.py"
DIST_DIR   = BASE_DIR / "dist"

# ─── Colors ───────────────────────────────────────────────────────────────────

COLORS = {
    "bg":     "#0d0f12",
    "bg2":    "#13161b",
    "bg3":    "#1a1e25",
    "border": "#ffffff12",
    "text":   "#e8eaf0",
    "muted":  "#6b7280",
    "accent": "#4f8ef7",
    "green":  "#34d399",
    "amber":  "#fbbf24",
    "red":    "#f87171",
}

# ─── Main window ──────────────────────────────────────────────────────────────

class AgentBuilder(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PatchPilot — Agent Builder")
        self.resizable(False, False)
        self.configure(bg=COLORS["bg"])

        self.update_idletasks()
        w, h = 520, 620
        x = (self.winfo_screenwidth()  - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

        self._fingerprint  = None
        self._build_thread = None
        self._build_ui()

    # ─── UI ───────────────────────────────────────────────────────────────────

    def _build_ui(self):
        header = tk.Frame(self, bg=COLORS["bg2"], pady=20)
        header.pack(fill="x")
        tk.Label(header, text="⚡  PatchPilot", bg=COLORS["bg2"],
                 fg=COLORS["text"], font=("DM Sans", 18, "bold")).pack()
        tk.Label(header, text="Agent Builder", bg=COLORS["bg2"],
                 fg=COLORS["muted"], font=("DM Sans", 11)).pack()

        body = tk.Frame(self, bg=COLORS["bg"], padx=36, pady=28)
        body.pack(fill="both", expand=True)

        # Server address
        self._section(body, "Server address")
        addr_row = tk.Frame(body, bg=COLORS["bg"])
        addr_row.pack(fill="x", pady=(6, 0))
        self.ip_var   = tk.StringVar(value="192.168.1.10")
        self.port_var = tk.StringVar(value="8443")
        self._entry(addr_row, self.ip_var, width=26).pack(side="left")
        tk.Label(addr_row, text=":", bg=COLORS["bg"], fg=COLORS["muted"],
                 font=("DM Sans", 14)).pack(side="left", padx=6)
        self._entry(addr_row, self.port_var, width=7).pack(side="left")

        # Test connection
        test_row = tk.Frame(body, bg=COLORS["bg"])
        test_row.pack(fill="x", pady=(10, 0))
        self._btn(test_row, "Test connection", self._test_connection,
                  style="ghost").pack(side="left")
        self.conn_status = tk.Label(test_row, text="", bg=COLORS["bg"],
                                    fg=COLORS["muted"], font=("DM Sans", 12))
        self.conn_status.pack(side="left", padx=12)

        # Fingerprint display
        self._section(body, "Server certificate fingerprint")
        self.fp_var = tk.StringVar(value="— run 'Test connection' first —")
        tk.Label(body, textvariable=self.fp_var, bg=COLORS["bg3"],
                 fg=COLORS["muted"], font=("DM Mono", 10), wraplength=440,
                 justify="left", padx=12, pady=10).pack(fill="x", pady=(6, 0))
        tk.Label(body,
                 text="Baked into the agent so it can detect MITM attacks.",
                 bg=COLORS["bg"], fg=COLORS["muted"], font=("DM Sans", 11),
                 wraplength=440, justify="left").pack(anchor="w", pady=(4, 0))

        # Job signing secret
        self._section(body, "Job signing secret")
        self.secret_var = tk.StringVar()
        secret_entry = self._entry(body, self.secret_var, width=44)
        secret_entry.config(show="•")
        secret_entry.pack(fill="x", pady=(6, 0))
        tk.Label(body,
                 text="Must match the job_secret in your server config. "
                      "The agent uses this to verify job signatures.",
                 bg=COLORS["bg"], fg=COLORS["muted"], font=("DM Sans", 11),
                 wraplength=440, justify="left").pack(anchor="w", pady=(4, 0))

        # Output folder
        self._section(body, "Output folder")
        out_row = tk.Frame(body, bg=COLORS["bg"])
        out_row.pack(fill="x", pady=(6, 0))
        self.out_var = tk.StringVar(value=str(DIST_DIR))
        self._entry(out_row, self.out_var, width=34).pack(side="left")
        self._btn(out_row, "Browse", self._browse_output,
                  style="ghost").pack(side="left", padx=(8, 0))

        # Progress
        self.progress_var = tk.StringVar(value="")
        self.progress_label = tk.Label(body, textvariable=self.progress_var,
                                       bg=COLORS["bg"], fg=COLORS["muted"],
                                       font=("DM Mono", 11), wraplength=448,
                                       justify="left")
        self.progress_label.pack(anchor="w", pady=(20, 0))

        # Build button
        self.build_btn = self._btn(body, "Build  agent.exe", self._start_build,
                                   style="primary", height=44)
        self.build_btn.pack(fill="x", pady=(16, 0))

        footer = tk.Frame(self, bg=COLORS["bg2"], pady=10)
        footer.pack(fill="x", side="bottom")
        tk.Label(footer, text=f"Agent Builder  ·  v{AGENT_VERSION}",
                 bg=COLORS["bg2"], fg=COLORS["muted"],
                 font=("DM Sans", 10)).pack()

    # ─── Helpers ──────────────────────────────────────────────────────────────

    def _section(self, parent, text):
        frame = tk.Frame(parent, bg=COLORS["bg"])
        frame.pack(fill="x", pady=(18, 0))
        tk.Label(frame, text=text.upper(), bg=COLORS["bg"],
                 fg=COLORS["muted"], font=("DM Sans", 10, "bold")).pack(side="left")
        tk.Frame(frame, bg=COLORS["border"], height=1).pack(
            side="left", fill="x", expand=True, padx=(10, 0))

    def _entry(self, parent, var, width=30):
        return tk.Entry(
            parent, textvariable=var, width=width,
            bg=COLORS["bg3"], fg=COLORS["text"],
            insertbackground=COLORS["text"],
            relief="flat", font=("DM Sans", 13),
            highlightthickness=1,
            highlightbackground=COLORS["border"],
            highlightcolor=COLORS["accent"],
        )

    def _btn(self, parent, text, command, style="ghost", height=34):
        colors = {
            "primary": (COLORS["accent"], COLORS["text"],  COLORS["accent"]),
            "ghost":   (COLORS["bg3"],    COLORS["text"],  COLORS["border"]),
        }
        bg, fg, hl = colors.get(style, colors["ghost"])
        return tk.Button(
            parent, text=text, command=command,
            bg=bg, fg=fg,
            activebackground=COLORS["bg2"], activeforeground=fg,
            relief="flat",
            font=("DM Sans", 13, "bold" if style == "primary" else "normal"),
            cursor="hand2", pady=0, height=1,
            highlightthickness=1, highlightbackground=hl,
        )

    def _set_status(self, msg, color=None):
        self.conn_status.config(text=msg, fg=color or COLORS["muted"])
        self.update_idletasks()

    def _set_progress(self, msg, color=None):
        self.progress_var.set(msg)
        self.progress_label.config(fg=color or COLORS["muted"])
        self.update_idletasks()

    # ─── Actions ──────────────────────────────────────────────────────────────

    def _test_connection(self):
        host = self.ip_var.get().strip()
        try:
            port = int(self.port_var.get().strip())
        except ValueError:
            self._set_status("Invalid port", COLORS["red"])
            return

        self._set_status("Connecting…")
        self.fp_var.set("…")

        def run():
            fp = fetch_server_fingerprint(host, port)
            if fp:
                self._fingerprint = fp
                self.fp_var.set(fp)
                self._set_status("✓ Reachable · fingerprint pinned", COLORS["green"])
            else:
                self._fingerprint = None
                self.fp_var.set("— connection failed —")
                self._set_status("✗ Could not reach server", COLORS["red"])

        threading.Thread(target=run, daemon=True).start()

    def _browse_output(self):
        folder = filedialog.askdirectory(title="Choose output folder")
        if folder:
            self.out_var.set(folder)

    def _start_build(self):
        if not self._fingerprint:
            messagebox.showerror("Missing fingerprint",
                                 "Test the connection first so the fingerprint can be pinned.")
            return

        secret = self.secret_var.get().strip()
        if not secret:
            messagebox.showerror("Missing secret",
                                 "Enter the job signing secret from your server config.")
            return
        if len(secret) < 32:
            if not messagebox.askyesno("Weak secret",
                                       "The job secret is shorter than 32 characters. "
                                       "A short secret weakens job signature security.\n\n"
                                       "Continue anyway?"):
                return

        host = self.ip_var.get().strip()
        port = self.port_var.get().strip()
        if not host or not port:
            messagebox.showerror("Missing fields", "Server address and port are required.")
            return

        server_url = f"https://{host}:{port}"
        out_dir    = Path(self.out_var.get().strip())
        out_dir.mkdir(parents=True, exist_ok=True)

        self.build_btn.config(state="disabled", text="Building…")
        self._set_progress("Preparing build…", COLORS["muted"])

        def run():
            try:
                self._build(server_url, self._fingerprint, secret, out_dir)
            finally:
                self.build_btn.config(state="normal", text="Build  agent.exe")

        self._build_thread = threading.Thread(target=run, daemon=True)
        self._build_thread.start()

    # ─── Build ────────────────────────────────────────────────────────────────

    def _build(self, server_url: str, fingerprint: str, job_secret: str, out_dir: Path):
        self._set_progress("Patching agent source…", COLORS["amber"])

        source = AGENT_SRC.read_text(encoding="utf-8")
        source = source.replace('"BAKED_SERVER_URL"',    f'"{server_url}"')
        source = source.replace('"BAKED_FINGERPRINT"',   f'"{fingerprint}"')
        # The job secret is baked in — it is never read from a file at runtime.
        # This means even if an endpoint is compromised and the agent binary is
        # extracted, the secret cannot be used to forge new jobs without also
        # knowing the server's job_secret (which is never exposed to agents).
        source = source.replace('"BAKED_JOB_SECRET"',    f'"{job_secret}"')

        tmp_dir = Path(tempfile.mkdtemp(prefix="patchpilot_build_"))
        try:
            patched_agent  = tmp_dir / "agent.py"
            patched_shared = tmp_dir / "shared.py"
            patched_agent.write_text(source, encoding="utf-8")
            shutil.copy(SHARED_SRC, patched_shared)

            self._set_progress("Running PyInstaller…", COLORS["amber"])

            result = subprocess.run([
                sys.executable, "-m", "PyInstaller",
                "--onefile",
                "--noconsole",
                "--name", "PatchPilot-Agent",
                "--distpath", str(out_dir),
                "--workpath", str(tmp_dir / "build"),
                "--specpath", str(tmp_dir),
                str(patched_agent),
            ], capture_output=True, text=True, cwd=str(tmp_dir))

            if result.returncode != 0:
                self._set_progress(
                    f"Build failed:\n{result.stderr[-600:]}", COLORS["red"])
                return

            final_path = out_dir / "PatchPilot-Agent.exe"
            if final_path.exists():
                self._set_progress(
                    f"✓ Done!  →  {final_path}\n\n"
                    f"Deploy with:  PatchPilot-Agent.exe /install",
                    COLORS["green"],
                )
            else:
                self._set_progress(
                    "Build completed but output file not found.", COLORS["amber"])

        except FileNotFoundError:
            self._set_progress(
                "PyInstaller not found. Install it:\n  pip install pyinstaller",
                COLORS["red"])
        except Exception as e:
            self._set_progress(f"Unexpected error: {e}", COLORS["red"])
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = AgentBuilder()
    app.mainloop()
