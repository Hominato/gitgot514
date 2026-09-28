#!/usr/bin/env python3
"""Tiny shared .env store — atomic read/write of KEY=VALUE lines.
Used by app.py and lure_server.py so dashboard changes persist to .env."""

import os, re, tempfile, threading

_lock = threading.Lock()

def env_path():
    return os.environ.get("GPENV_FILE",
                          os.path.join(os.path.dirname(
                              os.path.abspath(__file__)), ".env"))

def read_env():
    """Parse .env into a dict (comments/blank lines ignored)."""
    path = env_path()
    out = {}
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip().strip('"').strip("'")
    return out

def write_env(updates: dict):
    """Merge KEY=VALUE updates into .env atomically. None deletes a key."""
    path = env_path()
    with _lock:
        current = read_env()
        current.update(updates)
        current = {k: v for k, v in current.items() if v is not None}
        lines = ["# gPhish env — updated automatically by the dashboard, "
                 f"do not hand-edit blindly",
                 f"# last write: {__import__('datetime').datetime.now()}"
                 .replace("datetime.", ""), ""]
        for k, v in current.items():
            if re.search(r"[\s\"']", v):
                v = '"' + v.replace('"', '\\"') + '"'
            lines.append(f"{k}={v}")
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".",
                                   prefix=".env.tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        os.replace(tmp, path)
        os.chmod(path, 0o600)

def apply_to_process(keys):
    """Re-read .env values into os.environ for the running process."""
    env = read_env()
    for k in keys:
        if k in env:
            os.environ[k] = env[k]
