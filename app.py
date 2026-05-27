"""
app.py
~~~~~~
SecureScan — Flask REST API.

Endpoints
---------
POST /scan
    Body : {"url": "https://..."}
    Returns: {"scan_id": <int>}
    Validates the URL (must be HTTP/HTTPS, non-private), inserts a scan
    row with status="pending", and fires the scanner in a background thread.

GET /results/<scan_id>
    Returns the scan status and, once complete, all findings as JSON.
    {"status": "pending"}                          — still running
    {"status": "done",    "findings": [...]}       — completed
    {"status": "error",   "error": "<message>"}    — scanner raised

Usage
-----
    python app.py
    # API listens on http://0.0.0.0:5000
"""

from __future__ import annotations

import ipaddress
import logging
import os
import threading
from urllib.parse import urlparse

from dotenv import load_dotenv
load_dotenv()  # Load .env for local development (no-op in production)

from flask import Flask, jsonify, request
from flask_cors import CORS

import models
from scanner import engine

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
CORS(app)  # Allow all origins — tighten in production with origins=[...]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Private-IP / SSRF guard
# ---------------------------------------------------------------------------

# RFC-1918 + loopback + link-local networks that must never be scanned.
_BLOCKED_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network("127.0.0.0/8"),       # loopback
    ipaddress.ip_network("10.0.0.0/8"),        # RFC-1918 class A
    ipaddress.ip_network("172.16.0.0/12"),     # RFC-1918 class B (172.16–172.31)
    ipaddress.ip_network("192.168.0.0/16"),    # RFC-1918 class C
    ipaddress.ip_network("169.254.0.0/16"),    # link-local (APIPA)
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 unique-local
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
]

_BLOCKED_HOSTNAMES: frozenset[str] = frozenset(
    {"localhost", "ip6-localhost", "ip6-loopback"}
)


def _validate_url(url: str) -> str | None:
    """
    Validate *url* for use as a scan target.

    Returns
    -------
    str | None
        An error message string if the URL is invalid, or None if it is
        acceptable.
    """
    if not url or not isinstance(url, str):
        return "url is required and must be a string."

    url = url.strip()

    parsed = urlparse(url)

    # Must be an absolute HTTP(S) URL.
    if parsed.scheme not in ("http", "https"):
        return (
            f"URL scheme '{parsed.scheme}' is not allowed. "
            "Only http and https are accepted."
        )

    hostname = parsed.hostname
    if not hostname:
        return "URL must contain a valid hostname."

    # Reject known loopback hostnames by name.
    if hostname.lower() in _BLOCKED_HOSTNAMES:
        return f"Scanning '{hostname}' is not permitted."

    # If the hostname is a bare IP address, reject private/loopback ranges.
    try:
        addr = ipaddress.ip_address(hostname)
        for network in _BLOCKED_NETWORKS:
            if addr in network:
                return (
                    f"Scanning private/reserved IP address '{hostname}' "
                    "is not permitted."
                )
    except ValueError:
        # Not an IP address — hostname will be resolved at scan time.
        # We cannot reliably block DNS rebinding here without an actual
        # lookup; the network-layer check is the primary guard.
        pass

    return None  # URL is acceptable


# ---------------------------------------------------------------------------
# Background scan worker
# ---------------------------------------------------------------------------

def _run_scan(scan_id: int, url: str) -> None:
    """
    Target function for the background scan thread.

    Runs the scanner engine against *url*, then writes results to the DB.
    Updates scan status to "done" on success or "error" on failure.
    """
    log.info("Scan %d started  url=%s", scan_id, url)
    try:
        findings = engine.scan(url)
        models.insert_findings(scan_id, findings)
        models.update_scan_status(scan_id, "done")
        log.info(
            "Scan %d completed — %d finding(s)", scan_id, len(findings)
        )
    except Exception as exc:  # noqa: BLE001
        log.exception("Scan %d failed: %s", scan_id, exc)
        # Store a compact error message so the GET endpoint can surface it.
        error_msg = f"{type(exc).__name__}: {exc}"
        # Re-use the findings table for the error record — insert a
        # single synthetic finding instead of adding another DB column.
        models.insert_findings(
            scan_id,
            [
                {
                    "check_name": "Scanner Error",
                    "severity": "info",
                    "description": (
                        f"The scanner encountered an unexpected error: {error_msg}"
                    ),
                    "recommendation": (
                        "Check that the target URL is reachable and that the "
                        "scanner dependencies are installed correctly."
                    ),
                }
            ],
        )
        models.update_scan_status(scan_id, "error")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.post("/scan")
def start_scan():
    """
    POST /scan
    ----------
    Request body (JSON):
        {"url": "https://example.com"}

    Response (201):
        {"scan_id": 42}

    Errors (400):
        {"error": "<reason>"}
    """
    body = request.get_json(silent=True)
    if not body:
        return jsonify({"error": "Request body must be JSON."}), 400

    url: str = body.get("url", "")
    validation_error = _validate_url(url)
    if validation_error:
        return jsonify({"error": validation_error}), 400

    # Normalise — strip trailing whitespace; keep as supplied otherwise.
    url = url.strip()

    scan_id = models.insert_scan(url)

    thread = threading.Thread(
        target=_run_scan,
        args=(scan_id, url),
        daemon=True,          # Don't block process exit.
        name=f"scan-{scan_id}",
    )
    thread.start()

    log.info("Scan %d enqueued  url=%s", scan_id, url)
    return jsonify({"scan_id": scan_id}), 201


@app.get("/results/<int:scan_id>")
def get_results(scan_id: int):
    """
    GET /results/<scan_id>
    ----------------------
    Response when pending (200):
        {"status": "pending", "scan_id": 42, "url": "..."}

    Response when done (200):
        {
          "status": "done",
          "scan_id": 42,
          "url": "...",
          "created_at": "...",
          "findings": [
            {
              "id": 1,
              "check_name": "...",
              "severity": "high",
              "description": "...",
              "recommendation": "..."
            },
            ...
          ]
        }

    Response when errored (200):
        {"status": "error", "scan_id": 42, "url": "...", "findings": [...]}

    404 if scan_id not found.
    """
    scan = models.get_scan(scan_id)
    if scan is None:
        return jsonify({"error": f"Scan {scan_id} not found."}), 404

    scan_dict = dict(scan)
    status = scan_dict["status"]

    if status == "pending":
        return jsonify(
            {
                "status": "pending",
                "scan_id": scan_dict["id"],
                "url": scan_dict["url"],
            }
        )

    # "done" or "error" — return full detail.
    findings = models.get_findings(scan_id)
    return jsonify(
        {
            "status": status,
            "scan_id": scan_dict["id"],
            "url": scan_dict["url"],
            "created_at": scan_dict["created_at"],
            "findings": findings,
        }
    )


# ---------------------------------------------------------------------------
# Health check (optional convenience endpoint)
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    """GET /health — returns 200 {"status": "ok"} for uptime monitors."""
    return jsonify({"status": "ok"})


# ---------------------------------------------------------------------------
# Entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Initialise the database schema before accepting requests.
    models.init_db()
    log.info("Database initialised (PostgreSQL / Neon)")

    # Read PORT from the environment so Render (and similar platforms) can
    # inject the correct port.  Falls back to 5000 for local development.
    port = int(os.environ.get("PORT", 5000))

    # debug=False is intentional — the reloader spawns a child process that
    # conflicts with daemon threads on Windows.
    app.run(host="0.0.0.0", port=port, debug=False)
