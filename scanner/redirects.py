"""
scanner/redirects.py
~~~~~~~~~~~~~~~~~~~~
SecureScan — open redirect probe.

Phase 1 (discovery)
    Parse the already-fetched response with BeautifulSoup to collect all
    <a href> and <form action> URLs that contain redirect-like query
    parameters (redirect, next, url, return, goto, destination).

Phase 2 (probe)
    For each candidate that is in-scope (same registered domain as the
    scan origin), replace the redirect-parameter value with a canary URL
    and make a single GET request with follow_redirects=False.  If the
    server's Location header points to the canary host we flag an open
    redirect finding with severity "high".

Only the *first hop* is checked — no redirect chains are followed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from scanner.scope import is_in_scope

if TYPE_CHECKING:
    import requests as _requests

# ---------------------------------------------------------------------------
# Type alias
# ---------------------------------------------------------------------------

Finding = dict  # keys: check_name, severity, description, recommendation


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Query-parameter names that are commonly exploited for open redirects.
_REDIRECT_PARAMS: frozenset[str] = frozenset(
    {
        "redirect",
        "next",
        "url",
        "return",
        "returnurl",
        "return_url",
        "goto",
        "destination",
        "dest",
        "forward",
        "continue",
        "target",
        "redir",
        "redirect_uri",
        "redirect_url",
    }
)

# Canary domain injected as the redirect target.
# Chosen to be obviously non-existent in production and unique enough that
# a false-positive match is extremely unlikely.
_CANARY_URL = "https://evil-securescan-test.com"
_CANARY_HOST = "evil-securescan-test.com"

_UA = "SecureScan/1.0 (+https://github.com/securescan)"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _inject_canary(url: str, param_name: str) -> str:
    """
    Return a copy of *url* with *param_name* set to the canary URL.

    All other query parameters are preserved.
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param_name] = [_CANARY_URL]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def _has_redirect_param(url: str) -> list[str]:
    """
    Return the list of redirect-like parameter names present in *url*'s
    query string.  Empty list when none are found.
    """
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    return [k for k in qs if k.lower() in _REDIRECT_PARAMS]


def _collect_candidates(html: str, base_url: str) -> list[tuple[str, str]]:
    """
    Parse *html* and return (absolute_url, matching_param_name) tuples
    for every <a href> and <form action> that carries a redirect-like
    query parameter.
    """
    soup = BeautifulSoup(html, "lxml")
    candidates: list[tuple[str, str]] = []

    raw_urls: list[str] = []

    for tag in soup.find_all("a", href=True):
        raw_urls.append(tag["href"])

    for form in soup.find_all("form"):
        action = (form.get("action") or "").strip()
        if action:
            raw_urls.append(action)

    for raw in raw_urls:
        absolute = urljoin(base_url, raw)
        for param in _has_redirect_param(absolute):
            candidates.append((absolute, param))

    return candidates


def _location_points_to_canary(location: str) -> bool:
    """Return True if *location* redirects to the canary host."""
    if not location:
        return False
    parsed = urlparse(location)
    host = parsed.netloc.lower().split(":")[0]  # strip optional port
    return host == _CANARY_HOST


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def check(
    url: str,
    response: "_requests.Response",
    timeout: int = 10,
) -> list[Finding]:
    """
    Probe for open redirect vulnerabilities on same-domain URLs found in
    *response*.

    Parameters
    ----------
    url:
        The original scan target URL (used as the base for relative URLs
        and for scope enforcement).
    response:
        The Phase 1 ``requests.Response`` object.
    timeout:
        Per-request timeout (seconds) for probe GET requests.

    Returns
    -------
    list[Finding]
        Zero or more open redirect findings.
    """
    import requests as _req  # local import — avoids circular dependency

    candidates = _collect_candidates(response.text, url)
    if not candidates:
        return []

    findings: list[Finding] = []
    # Track probed (base_url, param) pairs to avoid duplicate requests.
    probed: set[tuple[str, str]] = set()

    session = _req.Session()
    session.headers.update({"User-Agent": _UA})

    for candidate_url, param_name in candidates:
        # --- Scope guard ---------------------------------------------------
        if not is_in_scope(candidate_url, url):
            continue  # skip external links

        dedup_key = (_strip_query(candidate_url), param_name)
        if dedup_key in probed:
            continue
        probed.add(dedup_key)

        probe_url = _inject_canary(candidate_url, param_name)

        try:
            probe_resp = session.get(
                probe_url,
                allow_redirects=False,   # NEVER follow — first hop only
                timeout=timeout,
            )
        except Exception:
            # Network error on a single probe — skip silently.
            continue

        location = probe_resp.headers.get("Location", "")
        if _location_points_to_canary(location):
            findings.append(
                {
                    "check_name": (
                        f"Open Redirect: param='{param_name}' "
                        f"endpoint='{_strip_query(candidate_url)}'"
                    ),
                    "severity": "high",
                    "description": (
                        f"The endpoint '{_strip_query(candidate_url)}' reflected "
                        f"the value of the '{param_name}' query parameter directly "
                        f"into the Location header (HTTP {probe_resp.status_code}), "
                        f"redirecting the browser to an arbitrary external domain. "
                        f"An attacker can craft a link on the trusted domain that "
                        f"silently forwards victims to a phishing or malware site."
                    ),
                    "recommendation": (
                        "Validate redirect targets against an allowlist of permitted "
                        "URLs or paths. Reject any redirect target that is not on the "
                        "expected origin. Prefer relative paths over absolute URLs for "
                        "post-action redirects."
                    ),
                }
            )

    return findings


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _strip_query(url: str) -> str:
    """Return *url* without its query string (for display / dedup keys)."""
    p = urlparse(url)
    return urlunparse(p._replace(query="", fragment=""))
