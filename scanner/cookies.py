"""
scanner/cookies.py
~~~~~~~~~~~~~~~~~~
Inspects Set-Cookie response headers for missing security attributes.

Operates on an already-fetched requests.Response object.  The raw
Set-Cookie headers are read from response.raw.headers (which preserves
multiple Set-Cookie lines) rather than response.headers, because the
latter merges duplicate keys into a single comma-joined string, which
would break cookie parsing.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import requests

# ---------------------------------------------------------------------------
# Type alias
# ---------------------------------------------------------------------------

Finding = dict  # keys: check_name, severity, description, recommendation


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_cookie_name(set_cookie_value: str) -> str:
    """Return the cookie name from a raw Set-Cookie header value."""
    # The first token before '=' is the cookie name.
    first_pair = set_cookie_value.split(";")[0].strip()
    name, _, _ = first_pair.partition("=")
    return name.strip() or "<unnamed>"


def _has_flag(set_cookie_value: str, flag: str) -> bool:
    """
    Return True if *flag* appears as a standalone attribute in the
    Set-Cookie directive (case-insensitive).
    """
    # Split on ';', strip each token, compare case-insensitively.
    parts = [p.strip().lower() for p in set_cookie_value.split(";")]
    return flag.lower() in parts


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def check(response: "requests.Response") -> list[Finding]:
    """
    Inspect Set-Cookie headers in *response* for missing security flags.

    Checks performed per cookie
    ---------------------------
    * **HttpOnly** – prevents JavaScript from accessing the cookie, mitigating
      XSS-based session-theft.
    * **Secure** – instructs the browser to transmit the cookie only over
      HTTPS, preventing exposure over plain HTTP connections.

    Parameters
    ----------
    response:
        A fully-fetched ``requests.Response`` object.

    Returns
    -------
    list[Finding]
        One Finding per (cookie, missing-flag) combination.
    """
    findings: list[Finding] = []

    # urllib3 stores raw headers in response.raw.headers as a
    # HTTPHeaderDict that yields all values for repeated keys.
    # We iterate the raw list so that each Set-Cookie line is treated
    # independently.
    raw_headers: list[tuple[bytes | str, bytes | str]] = (
        response.raw.headers.items()
        if hasattr(response.raw, "headers")
        else []
    )

    set_cookie_values: list[str] = []
    for key, value in raw_headers:
        # Decode bytes keys/values if necessary.
        k = key.decode("latin-1") if isinstance(key, bytes) else key
        v = value.decode("latin-1") if isinstance(value, bytes) else value
        if k.lower() == "set-cookie":
            set_cookie_values.append(v)

    for raw_value in set_cookie_values:
        cookie_name = _parse_cookie_name(raw_value)

        if not _has_flag(raw_value, "httponly"):
            findings.append(
                {
                    "check_name": f"Cookie Missing HttpOnly: {cookie_name}",
                    "severity": "high",
                    "description": (
                        f"The cookie '{cookie_name}' is set without the HttpOnly "
                        "attribute. Client-side scripts can read this cookie, making "
                        "it trivially stealable via an XSS vulnerability."
                    ),
                    "recommendation": (
                        f"Set the HttpOnly attribute on '{cookie_name}': "
                        "Set-Cookie: {name}=<value>; HttpOnly; ..."
                    ),
                }
            )

        if not _has_flag(raw_value, "secure"):
            findings.append(
                {
                    "check_name": f"Cookie Missing Secure Flag: {cookie_name}",
                    "severity": "high",
                    "description": (
                        f"The cookie '{cookie_name}' is set without the Secure "
                        "attribute. It may be transmitted over unencrypted HTTP "
                        "connections, exposing it to interception."
                    ),
                    "recommendation": (
                        f"Set the Secure attribute on '{cookie_name}': "
                        "Set-Cookie: {name}=<value>; Secure; ..."
                    ),
                }
            )

    return findings
