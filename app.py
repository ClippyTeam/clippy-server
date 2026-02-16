# app.py
import base64
import hashlib
import os
import sqlite3
import time
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

APP_NAME = "clippy"
DB_PATH = os.getenv("CLIPPY_DB", "/data/clippy.db")
AUTH_TOKEN = os.getenv("CLIPPY_TOKEN", "")
RETENTION = int(os.getenv("CLIPPY_RETENTION", "200"))  # keep last N clips
MAX_BYTES = int(os.getenv("CLIPPY_MAX_BYTES", str(64 * 1024)))  # 64KB default
DEFAULT_TTL = int(os.getenv("CLIPPY_DEFAULT_TTL", "86400"))  # 24h

app = FastAPI(title=f"{APP_NAME} server", version="0.1.0")


def now_ms() -> int:
    return int(time.time() * 1000)


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS clips (
          id TEXT PRIMARY KEY,
          device_id TEXT NOT NULL,
          device_name TEXT,
          content_type TEXT NOT NULL,
          content_b64 TEXT NOT NULL,
          content_sha256 TEXT NOT NULL,
          client_ts_ms INTEGER,
          client_seq INTEGER,
          server_ts_ms INTEGER NOT NULL,
          expires_ts_ms INTEGER NOT NULL
        );
        """
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_clips_server_ts ON clips(server_ts_ms DESC);"
    )
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_clips_device_ts ON clips(device_id, server_ts_ms DESC);"
    )
    conn.commit()
    conn.close()


def auth_or_401(req: Request) -> None:
    if not AUTH_TOKEN:
        # allow running without auth token for local dev
        return
    h = req.headers.get("authorization", "")
    if not h.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    token = h.split(" ", 1)[1].strip()
    if token != AUTH_TOKEN:
        raise HTTPException(status_code=403, detail="Invalid token")


def purge_expired_and_overflow(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    # Purge expired
    cur.execute("DELETE FROM clips WHERE expires_ts_ms <= ?", (now_ms(),))
    # Purge overflow beyond retention (keep newest RETENTION)
    cur.execute(
        """
        DELETE FROM clips
        WHERE id IN (
          SELECT id FROM clips
          ORDER BY server_ts_ms DESC
          LIMIT -1 OFFSET ?
        )
        """,
        (RETENTION,),
    )
    conn.commit()


class ClipIn(BaseModel):
    device_id: str = Field(..., min_length=1, max_length=64)
    device_name: Optional[str] = Field(None, max_length=128)
    content_type: str = Field("text/plain", max_length=64)
    content_text: Optional[str] = None
    content_b64: Optional[str] = None  # for binary or if client prefers base64 always
    client_ts_ms: Optional[int] = None
    client_seq: Optional[int] = None
    ttl_seconds: Optional[int] = Field(None, ge=5, le=30 * 24 * 3600)  # 5s .. 30d


class ClipOut(BaseModel):
    clip_id: str
    server_ts_ms: int
    expires_ts_ms: int
    device_id: str
    device_name: Optional[str]
    content_type: str
    content_sha256: str
    content_text: Optional[str] = None
    content_b64: Optional[str] = None


@app.on_event("startup")
def _startup() -> None:
    init_db()


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"ok": True, "name": APP_NAME, "ts_ms": now_ms()}


@app.post("/v1/clip")
def post_clip(payload: ClipIn, req: Request) -> Dict[str, Any]:
    auth_or_401(req)

    if payload.content_text is None and payload.content_b64 is None:
        raise HTTPException(
            status_code=400, detail="Provide content_text or content_b64"
        )

    if payload.content_text is not None and payload.content_b64 is not None:
        raise HTTPException(
            status_code=400, detail="Provide only one of content_text or content_b64"
        )

    if payload.content_text is not None:
        raw = payload.content_text.encode("utf-8")
        b64 = base64.b64encode(raw).decode("ascii")
    else:
        try:
            raw = base64.b64decode(payload.content_b64.encode("ascii"), validate=True)
        except Exception:
            raise HTTPException(
                status_code=400, detail="Invalid content_b64 (must be base64)"
            )
        b64 = payload.content_b64

    if len(raw) > MAX_BYTES:
        raise HTTPException(
            status_code=413, detail=f"Clip too large ({len(raw)} bytes > {MAX_BYTES})"
        )

    server_ts = now_ms()
    ttl = payload.ttl_seconds if payload.ttl_seconds is not None else DEFAULT_TTL
    expires_ts = server_ts + int(ttl * 1000)

    content_hash = sha256_hex(raw)
    # Unique clip id: hash + time to avoid collisions on repeated same content
    clip_id = f"{content_hash[:16]}_{server_ts}"

    conn = get_db()
    try:
        purge_expired_and_overflow(conn)
        conn.execute(
            """
            INSERT INTO clips (
              id, device_id, device_name, content_type, content_b64, content_sha256,
              client_ts_ms, client_seq, server_ts_ms, expires_ts_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                clip_id,
                payload.device_id,
                payload.device_name,
                payload.content_type,
                b64,
                content_hash,
                payload.client_ts_ms,
                payload.client_seq,
                server_ts,
                expires_ts,
            ),
        )
        conn.commit()
        purge_expired_and_overflow(conn)
    finally:
        conn.close()

    return {
        "clip_id": clip_id,
        "server_ts_ms": server_ts,
        "expires_ts_ms": expires_ts,
        "content_sha256": content_hash,
    }


def row_to_clipout(row: sqlite3.Row, include_content: bool) -> Dict[str, Any]:
    out = {
        "clip_id": row["id"],
        "server_ts_ms": row["server_ts_ms"],
        "expires_ts_ms": row["expires_ts_ms"],
        "device_id": row["device_id"],
        "device_name": row["device_name"],
        "content_type": row["content_type"],
        "content_sha256": row["content_sha256"],
    }
    if include_content:
        # For now always return base64; client can decode to text if content_type is text/*
        out["content_b64"] = row["content_b64"]
    return out


@app.get("/v1/clips")
def list_clips(
    req: Request,
    limit: int = 50,
    include_content: int = 0,
) -> Dict[str, Any]:
    auth_or_401(req)

    limit = max(1, min(limit, 500))
    conn = get_db()
    try:
        purge_expired_and_overflow(conn)
        cur = conn.execute(
            """
            SELECT * FROM clips
            ORDER BY server_ts_ms DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cur.fetchall()
    finally:
        conn.close()

    return {
        "items": [row_to_clipout(r, bool(include_content)) for r in rows],
        "limit": limit,
        "ts_ms": now_ms(),
    }


@app.get("/v1/latest")
def latest(req: Request, include_content: int = 1) -> Dict[str, Any]:
    auth_or_401(req)
    conn = get_db()
    try:
        purge_expired_and_overflow(conn)
        cur = conn.execute(
            """
            SELECT * FROM clips
            ORDER BY server_ts_ms DESC
            LIMIT 1
            """
        )
        row = cur.fetchone()
    finally:
        conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="No clips")
    return row_to_clipout(row, bool(include_content))


@app.get("/v1/latest_per_device")
def latest_per_device(req: Request, include_content: int = 0) -> Dict[str, Any]:
    auth_or_401(req)
    conn = get_db()
    try:
        purge_expired_and_overflow(conn)
        # SQLite trick: join with max(ts) per device
        cur = conn.execute(
            """
            SELECT c.*
            FROM clips c
            JOIN (
              SELECT device_id, MAX(server_ts_ms) AS mx
              FROM clips
              GROUP BY device_id
            ) m
            ON c.device_id = m.device_id AND c.server_ts_ms = m.mx
            ORDER BY c.server_ts_ms DESC
            """
        )
        rows = cur.fetchall()
    finally:
        conn.close()

    return {
        "items": [row_to_clipout(r, bool(include_content)) for r in rows],
        "ts_ms": now_ms(),
    }
