"""
models.py
~~~~~~~~~
SecureScan — PostgreSQL persistence layer (psycopg2, no ORM).

Reads the database connection string from the DATABASE_URL environment
variable.  For local development you can set it to a local Postgres URL or
keep a .env file and load it with python-dotenv.

Schema
------
  scans(id, url, status, created_at)
  findings(id, scan_id FK→scans.id, check_name, severity, description, recommendation)

All public functions open and close their own connection so it is safe
to call them from any thread without sharing a connection object.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Generator

import psycopg2
import psycopg2.extras  # RealDictCursor


# ---------------------------------------------------------------------------
# Connection string
# ---------------------------------------------------------------------------

def _get_dsn() -> str:
    """
    Return the PostgreSQL DSN from the DATABASE_URL environment variable.

    Raises
    ------
    RuntimeError
        If DATABASE_URL is not set.
    """
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        raise RuntimeError(
            "DATABASE_URL environment variable is not set. "
            "Set it to your Neon (or any PostgreSQL) connection string, e.g.:\n"
            "  postgresql://user:pass@host/dbname?sslmode=require"
        )
    return dsn


# ---------------------------------------------------------------------------
# Low-level connection helper
# ---------------------------------------------------------------------------

@contextmanager
def _get_conn() -> Generator[psycopg2.extensions.connection, None, None]:
    """
    Yield a psycopg2 connection with RealDictCursor as the default cursor
    factory so rows behave like dicts (column-name access).

    Each call opens a fresh connection — safe to use from any thread.
    """
    conn = psycopg2.connect(_get_dsn(), cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Schema initialisation
# ---------------------------------------------------------------------------

def init_db() -> None:
    """
    Create the ``scans`` and ``findings`` tables if they do not already
    exist.  Safe to call on every application start-up.
    """
    # psycopg2 only allows one statement per execute() call.
    # Split into two separate calls.
    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id         SERIAL      PRIMARY KEY,
                    url        TEXT        NOT NULL,
                    status     TEXT        NOT NULL DEFAULT 'pending',
                    created_at TIMESTAMPTZ NOT NULL
                );
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    id             SERIAL  PRIMARY KEY,
                    scan_id        INTEGER NOT NULL
                                       REFERENCES scans(id) ON DELETE CASCADE,
                    check_name     TEXT    NOT NULL,
                    severity       TEXT    NOT NULL,
                    description    TEXT    NOT NULL,
                    recommendation TEXT    NOT NULL
                );
                """
            )


# ---------------------------------------------------------------------------
# Scan CRUD
# ---------------------------------------------------------------------------

def insert_scan(url: str) -> int:
    """
    Insert a new scan row with ``status='pending'`` and the current UTC
    timestamp.

    Returns
    -------
    int
        The newly created scan ID.
    """
    created_at = datetime.now(timezone.utc)
    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scans (url, status, created_at)
                VALUES (%s, %s, %s)
                RETURNING id
                """,
                (url, "pending", created_at),
            )
            row = cur.fetchone()
            return row["id"]


def get_scan(scan_id: int) -> dict[str, Any] | None:
    """
    Fetch a single scan row by primary key.

    Returns
    -------
    dict | None
        Dict with keys (id, url, status, created_at), or None if not found.
    """
    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, url, status, created_at FROM scans WHERE id = %s",
                (scan_id,),
            )
            row = cur.fetchone()
            # RealDictCursor returns a RealDictRow; convert to plain dict for
            # easy JSON serialisation in app.py.
            return dict(row) if row is not None else None


def update_scan_status(scan_id: int, status: str) -> None:
    """Update the ``status`` column of scan *scan_id*."""
    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE scans SET status = %s WHERE id = %s",
                (status, scan_id),
            )


# ---------------------------------------------------------------------------
# Findings CRUD
# ---------------------------------------------------------------------------

def insert_findings(scan_id: int, findings: list[dict[str, Any]]) -> None:
    """
    Bulk-insert a list of Finding dicts for *scan_id*.

    Each dict must contain: check_name, severity, description, recommendation.
    """
    rows = [
        (
            scan_id,
            f["check_name"],
            f["severity"],
            f["description"],
            f["recommendation"],
        )
        for f in findings
    ]
    if not rows:
        return
    with _get_conn() as conn:
        with conn.cursor() as cur:
            psycopg2.extras.execute_batch(
                cur,
                """
                INSERT INTO findings
                    (scan_id, check_name, severity, description, recommendation)
                VALUES (%s, %s, %s, %s, %s)
                """,
                rows,
            )


def get_findings(scan_id: int) -> list[dict[str, Any]]:
    """
    Return all findings for *scan_id* as a list of plain dicts, ordered
    by severity (critical → high → medium → info).
    """
    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, scan_id, check_name, severity, description, recommendation
                FROM findings
                WHERE scan_id = %s
                ORDER BY
                    CASE severity
                        WHEN 'critical' THEN 0
                        WHEN 'high'     THEN 1
                        WHEN 'medium'   THEN 2
                        WHEN 'info'     THEN 3
                        ELSE 4
                    END,
                    id
                """,
                (scan_id,),
            )
            return [dict(row) for row in cur.fetchall()]
