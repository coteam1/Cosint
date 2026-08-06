"""Tiny SQLite job store. No ORM - one table, JSON payloads."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from typing import Any

from .config import DB_PATH

_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id          TEXT PRIMARY KEY,
    target      TEXT NOT NULL,
    target_type TEXT NOT NULL,
    status      TEXT NOT NULL,
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL,
    payload     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at DESC);
"""


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init() -> None:
    with _lock, _connect() as conn:
        conn.executescript(SCHEMA)


def create_job(target: str, target_type: str, options: dict[str, Any]) -> str:
    job_id = uuid.uuid4().hex[:12]
    now = time.time()
    payload = {
        "options": options,
        "modules": [],
        "entities": [],
        "edges": [],
        "findings": [],
        "graph": {"nodes": [], "edges": []},
        "log": [],
    }
    with _lock, _connect() as conn:
        conn.execute(
            "INSERT INTO jobs (id, target, target_type, status, created_at, updated_at, payload)"
            " VALUES (?,?,?,?,?,?,?)",
            (job_id, target, target_type, "queued", now, now, json.dumps(payload)),
        )
    return job_id


def update_job(job_id: str, *, status: str | None = None, payload: dict | None = None) -> None:
    with _lock, _connect() as conn:
        row = conn.execute("SELECT status, payload FROM jobs WHERE id=?", (job_id,)).fetchone()
        if row is None:
            return
        new_status = status or row["status"]
        new_payload = json.dumps(payload) if payload is not None else row["payload"]
        conn.execute(
            "UPDATE jobs SET status=?, payload=?, updated_at=? WHERE id=?",
            (new_status, new_payload, time.time(), job_id),
        )


def get_job(job_id: str) -> dict[str, Any] | None:
    with _lock, _connect() as conn:
        row = conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    if row is None:
        return None
    job = dict(row)
    job["payload"] = json.loads(job["payload"])
    return job


def list_jobs(limit: int = 25) -> list[dict[str, Any]]:
    with _lock, _connect() as conn:
        rows = conn.execute(
            "SELECT id, target, target_type, status, created_at, updated_at"
            " FROM jobs ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def delete_job(job_id: str) -> bool:
    with _lock, _connect() as conn:
        cur = conn.execute("DELETE FROM jobs WHERE id=?", (job_id,))
    return cur.rowcount > 0
