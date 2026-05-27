"""
scanner/headers.py
~~~~~~~~~~~~~~~~~~
Checks for the presence of important HTTP security response headers.
Operates on an already-fetched requests.Response object so the engine
never makes more than one network request per scan.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import requests

# ---------------------------------------------------------------------------
# Type alias
# ---------------------------------------------------------------------------

Finding = dict  # keys: check_name, severity, description, recommendation


# ---------------------------------------------------------------------------
# Header catalogue
# Each entry: (header_name, severity, description, recommendation)
# ---------------------------------------------------------------------------

_REQUIRED_HEADERS: list[tuple[str, str, str, str]] = [
    (
        "Content-Security-Policy",
        "high",
        "Content-Security-Policy (CSP) header is missing. Without it the browser "
        "applies no restrictions on inline scripts or external resource origins, "
        "leaving the page vulnerable to Cross-Site Scripting (XSS).",
        "Add a Content-Security-Policy header with a strict policy, e.g. "
        "\"default-src 'self'\" and tighten per-directive as needed.",
    ),
    (
        "Strict-Transport-Security",
        "high",
        "Strict-Transport-Security (HSTS) header is missing. Without it, browsers "
        "may connect over plain HTTP even after a first HTTPS visit, enabling "
        "downgrade and man-in-the-middle attacks.",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' "
        "and consider adding the 'preload' directive.",
    ),
    (
        "X-Frame-Options",
        "medium",
        "X-Frame-Options header is missing. The page can be embedded in an iframe "
        "on a third-party origin, which enables clickjacking attacks.",
        "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN', or use the "
        "frame-ancestors CSP directive instead.",
    ),
    (
        "X-Content-Type-Options",
        "medium",
        "X-Content-Type-Options header is missing. Browsers may MIME-sniff "
        "responses away from the declared content-type, potentially executing "
        "malicious content as a different resource type.",
        "Add 'X-Content-Type-Options: nosniff' to all responses.",
    ),
    (
        "Referrer-Policy",
        "info",
        "Referrer-Policy header is missing. By default browsers may send the full "
        "URL in the Referer header to third-party sites, leaking potentially "
        "sensitive path or query-string information.",
        "Add 'Referrer-Policy: strict-origin-when-cross-origin' or a stricter "
        "policy such as 'no-referrer'.",
    ),
]


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def check(response: "requests.Response") -> list[Finding]:
    """
    Inspect *response* for missing HTTP security headers.

    Parameters
    ----------
    response:
        A fully-fetched ``requests.Response`` object.

    Returns
    -------
    list[Finding]
        One Finding per missing header; empty list when all are present.
    """
    findings: list[Finding] = []

    # requests normalises header names to title-case, so a case-insensitive
    # lookup via response.headers is already handled by the CaseInsensitiveDict.
    for header_name, severity, description, recommendation in _REQUIRED_HEADERS:
        if header_name not in response.headers:
            findings.append(
                {
                    "check_name": f"Missing Header: {header_name}",
                    "severity": severity,
                    "description": description,
                    "recommendation": recommendation,
                }
            )

    return findings
