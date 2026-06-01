"""SentinelOne SDL client (uses `requests` for reliable I/O)."""
from __future__ import annotations

import json
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
CFG = json.loads((ROOT / "config.json").read_text())

import os, uuid

BASE = CFG["base_url"].rstrip("/")
WRITE_KEY = CFG["log_write_key"]
READ_KEY = CFG["log_read_key"]
# Make the session unique per *process* so SDL never dedupes re-runs of the
# same payload (SDL hashes session+ts on the server side and silently drops
# events whose (session, ts) tuple was already accepted -> bytesCharged=0).
SESSION = os.environ.get("KQL_PROOF_SESSION") or f"kql-proof-{uuid.uuid4()}"
VERIFY = CFG.get("verify_tls", True)
TIMEOUT = CFG.get("timeout_seconds", 120)
print(f"[sdl_client] session = {SESSION}")


def _post(path: str, body: dict, token: str, timeout: int | None = None) -> dict:
    url = f"{BASE}{path}"
    r = requests.post(
        url,
        json=body,
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {token}"},
        timeout=timeout or TIMEOUT,
        verify=VERIFY,
    )
    try:
        return r.json()
    except ValueError:
        return {"status": "error", "http_status": r.status_code, "raw": r.text[:500]}


# --- addEvents -------------------------------------------------------------
def add_events(events: list[dict], session_info: dict | None = None) -> dict:
    payload = {
        "session": SESSION,
        "sessionInfo": session_info or {
            "serverHost": "kql-proof",
            "logfile": "kql-proof.jsonl",
            "parser": "json",
        },
        "events": events,
        "threads": [{"id": "T1", "name": "kql-proof"}],
    }
    return _post("/api/addEvents", payload, WRITE_KEY)


def _clean_attrs(rec: dict) -> dict:
    """SDL silently rejects events that contain `null` attribute values
    (the call returns status=success but bytesCharged=0 and the event is
    not queryable). Strip them, and coerce everything else to JSON-safe
    primitives that SDL's parser indexes correctly."""
    out: dict = {}
    for k, v in rec.items():
        if v is None:
            continue
        if isinstance(v, bool):
            out[k] = str(v).lower()       # SDL stores bools as strings reliably
        elif isinstance(v, (int, float, str)):
            out[k] = v
        else:
            # dict/list -> JSON string
            out[k] = json.dumps(v, default=str)
    return out


def upload_logs(body: str, server_host: str = "kql-proof",
                logfile: str = "kql-proof.jsonl",
                parser: str = "json") -> dict:
    """POST /api/uploadLogs. Body is raw text; SDL applies the named parser."""
    url = f"{BASE}/api/uploadLogs"
    headers = {
        "Authorization": f"Bearer {WRITE_KEY}",
        "Content-Type": "text/plain",
        "parser": parser,
        "server-host": server_host,
        "logfile": logfile,
    }
    r = requests.post(url, data=body.encode(), headers=headers,
                      timeout=TIMEOUT, verify=VERIFY)
    try:
        return r.json()
    except ValueError:
        return {"status": "error", "http_status": r.status_code, "raw": r.text[:500]}


def ingest_jsonl(jsonl_path: Path, run_id: str | None = None,
                 batch_lines: int = 2000) -> tuple[int, str]:
    """Ingest the entire JSONL via uploadLogs. Stamps every event with the
    given `run_id` (or a fresh uuid) so subsequent PowerQueries can scope to
    a single run. Returns (events_sent, run_id)."""
    run_id = run_id or f"run-{uuid.uuid4().hex[:10]}"
    sent = 0
    buf: list[str] = []

    def flush():
        nonlocal sent
        if not buf:
            return
        r = upload_logs("\n".join(buf))
        if r.get("status") != "success":
            raise RuntimeError(f"uploadLogs rejected batch: {r}")
        sent += len(buf); buf.clear()

    for line in jsonl_path.read_text().splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        rec["proof_run_id"] = run_id
        buf.append(json.dumps(rec, default=str))
        if len(buf) >= batch_lines:
            flush()
    flush()
    return sent, run_id


# --- powerQuery ------------------------------------------------------------
def power_query(query: str,
                start_time: str | int = "7d",
                end_time: str | int | None = None) -> dict:
    body: dict = {"query": query, "startTime": str(start_time)}
    if end_time is not None:
        body["endTime"] = str(end_time)
    return _post("/api/powerQuery", body, READ_KEY)
