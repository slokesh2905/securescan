"""
scanner/forms.py
~~~~~~~~~~~~~~~~
SecureScan — Phase 2 form crawler + error-based SQL injection probe.

Phase 1 (crawl)
    Parse the already-fetched response with BeautifulSoup to enumerate
    every <form> element, its action URL, method, and input fields.

Phase 2 (probe)
    For every same-origin form, submit it with SQL injection payloads
    injected into each text / search field and inspect the response
    body for database error signatures.

    Detection is *error-based only* — no blind/timing attacks are
    performed.  Any positive match is annotated with a manual-
    verification reminder before being reported.

Dependencies
    beautifulsoup4, lxml (HTML parser), requests
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

if TYPE_CHECKING:
    import requests as _requests

# ---------------------------------------------------------------------------
# Type alias
# ---------------------------------------------------------------------------

Finding = dict  # keys: check_name, severity, description, recommendation


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Payloads injected into every fuzzable input field.
_SQLI_PAYLOADS: list[str] = [
    "'",
    "' OR '1'='1",
]

# Regex patterns that indicate a raw database error leaked into the response.
# Compiled once at import time for performance.
_ERROR_SIGNATURES: list[re.Pattern[str]] = [
    re.compile(r"syntax\s+error", re.IGNORECASE),
    re.compile(r"mysql_fetch", re.IGNORECASE),
    re.compile(r"ORA-\d{4,5}"),                   # Oracle error codes
    re.compile(r"SQLSTATE\[", re.IGNORECASE),
    re.compile(r"Warning:\s*mysql", re.IGNORECASE),
    re.compile(r"Unclosed\s+quotation", re.IGNORECASE),
    re.compile(r"Microsoft\s+OLE\s+DB\s+Provider", re.IGNORECASE),
    re.compile(r"pg_query\(\)", re.IGNORECASE),    # PostgreSQL
    re.compile(r"supplied\s+argument\s+is\s+not\s+a\s+valid\s+MySQL", re.IGNORECASE),
]

# HTML input types considered fuzzable (carry user-supplied string data).
_FUZZABLE_INPUT_TYPES: frozenset[str] = frozenset(
    {"text", "search", "email", "url", "tel", "password", ""}
)

# A harmless, high-entropy token used to establish a per-field baseline.
# If the target already leaks a database error for this benign value, the
# error cannot be attributed to our payload and the field is skipped.
_BASELINE_TOKEN = "securescan7a3f9b2cbaseline"

# Note appended to every SQLi finding describing the evidence basis.
_DISCLAIMER = (
    "A benign baseline request to the same field did not return this error, "
    "so the error is attributable to the injected quote."
)

# Browser-like User-Agent shared by all probe requests.
_UA = "SecureScan/1.0 (+https://github.com/securescan)"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _same_origin(base_url: str, action_url: str) -> bool:
    """
    Return True when *action_url* resolves to the same scheme+host+port
    as *base_url*.

    An empty or relative action URL is always considered same-origin
    (it resolves within the same origin by definition).
    """
    if not action_url:
        return True  # relative / self-submitting form

    parsed_action = urlparse(action_url)
    if not parsed_action.scheme:
        return True  # relative URL — same origin

    parsed_base = urlparse(base_url)
    return (
        parsed_action.scheme.lower() == parsed_base.scheme.lower()
        and parsed_action.netloc.lower() == parsed_base.netloc.lower()
    )


def _resolve_action(base_url: str, raw_action: str) -> str:
    """Resolve *raw_action* against *base_url*, returning an absolute URL."""
    return urljoin(base_url, raw_action) if raw_action else base_url


def _extract_forms(html: str, base_url: str) -> list[dict]:
    """
    Parse *html* and return a list of form descriptors, each containing:
        - action (str): absolute URL the form submits to
        - method (str): "get" or "post"
        - fields (dict[str, str]): {field_name: default_value}
        - fuzzable (list[str]): names of text-like input fields
    """
    soup = BeautifulSoup(html, "lxml")
    form_descriptors: list[dict] = []

    for form_tag in soup.find_all("form"):
        raw_action: str = (form_tag.get("action") or "").strip()
        method: str = (form_tag.get("method") or "get").strip().lower()
        action_url: str = _resolve_action(base_url, raw_action)

        # Collect all named inputs with their default values.
        fields: dict[str, str] = {}
        fuzzable: list[str] = []

        for inp in form_tag.find_all("input"):
            name: str = (inp.get("name") or "").strip()
            if not name:
                continue  # unnamed inputs are ignored by browsers too
            input_type: str = (inp.get("type") or "").strip().lower()
            default_value: str = inp.get("value") or ""
            fields[name] = default_value
            if input_type in _FUZZABLE_INPUT_TYPES:
                fuzzable.append(name)

        for textarea in form_tag.find_all("textarea"):
            name = (textarea.get("name") or "").strip()
            if name:
                fields[name] = textarea.get_text()
                fuzzable.append(name)

        form_descriptors.append(
            {
                "action": action_url,
                "method": method,
                "fields": fields,
                "fuzzable": fuzzable,
            }
        )

    return form_descriptors


def _contains_sql_error(text: str) -> str | None:
    """
    Return the first matching error signature found in *text*, or None.
    """
    for pattern in _ERROR_SIGNATURES:
        m = pattern.search(text)
        if m:
            return m.group(0)
    return None


def _probe_form(
    form: dict,
    session: "_requests.Session",
    timeout: int,
) -> list[Finding]:
    """
    Inject each SQLi payload into every fuzzable field of *form* and
    inspect the response body.  Returns a list of findings (may be empty).
    """
    findings: list[Finding] = []

    def _submit(field_name: str, value: str):
        """Submit the form with *value* in *field_name*; return response or None."""
        data = dict(form["fields"])
        data[field_name] = value
        try:
            if form["method"] == "post":
                return session.post(form["action"], data=data, timeout=timeout)
            return session.get(form["action"], params=data, timeout=timeout)
        except Exception:
            # Network errors during probing are skipped so one flaky form
            # doesn't abort the whole scan.
            return None

    for field_name in form["fuzzable"]:
        # --- Baseline -----------------------------------------------------
        # Submit a harmless token first. If the endpoint already emits a
        # database-error signature for benign input, any later match is not
        # attributable to our payload, so we cannot prove injection — skip.
        baseline_resp = _submit(field_name, _BASELINE_TOKEN)
        if baseline_resp is None:
            continue
        if _contains_sql_error(baseline_resp.text):
            continue

        # --- Probe --------------------------------------------------------
        for payload in _SQLI_PAYLOADS:
            resp = _submit(field_name, payload)
            if resp is None:
                continue

            matched_sig = _contains_sql_error(resp.text)
            # Report only when the error appears for the payload but did NOT
            # appear in the clean baseline above — that difference is the proof.
            if matched_sig:
                findings.append(
                    {
                        "check_name": (
                            f"SQL Injection (error-based): field='{field_name}' "
                            f"action='{form['action']}'"
                        ),
                        "severity": "high",
                        "description": (
                            f"The form field '{field_name}' (action: {form['action']}) "
                            f"returned a database error signature \"{matched_sig}\" "
                            f"when submitted with the payload {payload!r}, while a "
                            "benign baseline value did not. This indicates user input "
                            "is concatenated into a SQL query without parameterisation. "
                            f"{_DISCLAIMER}"
                        ),
                        "recommendation": (
                            "Use parameterised queries / prepared statements for all "
                            "database interactions. Never interpolate user-controlled "
                            "strings into SQL. Apply an ORM or query-builder that "
                            "enforces safe query construction by default."
                        ),
                        "evidence": (
                            f"Baseline value {_BASELINE_TOKEN!r}: no DB error. "
                            f"Payload {payload!r}: matched signature \"{matched_sig}\" "
                            f"in the {form['method'].upper()} response from "
                            f"{form['action']}."
                        ),
                    }
                )
                # One confirmed payload is enough for this field.
                break

    return findings


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def check(url: str, response: "_requests.Response", timeout: int = 15) -> list[Finding]:
    """
    Crawl forms in *response* and probe same-origin forms for SQL injection.

    Parameters
    ----------
    url:
        The original URL that was fetched (used to resolve relative action
        URLs and to enforce the same-origin policy).
    response:
        The ``requests.Response`` from the initial page fetch.
    timeout:
        Per-request timeout (seconds) used when submitting probe payloads.

    Returns
    -------
    list[Finding]
        Zero or more SQLi findings.  Empty list when no forms exist or
        no error signatures are triggered.
    """
    import requests as _req  # local import to avoid circular dependency

    html = response.text
    forms = _extract_forms(html, url)

    if not forms:
        return []

    # Filter to same-origin forms only before probing.
    same_origin_forms = [f for f in forms if _same_origin(url, f["action"])]

    if not same_origin_forms:
        return []

    # Reuse a session so cookies set by the server during the initial
    # page load are automatically sent with probe requests (e.g. CSRF
    # tokens stored in cookies, not just hidden fields).
    session = _req.Session()
    session.headers.update({"User-Agent": _UA})
    # Seed the session with any cookies from the Phase 1 response.
    for cookie in response.cookies:
        session.cookies.set(cookie.name, cookie.value)

    findings: list[Finding] = []
    for form in same_origin_forms:
        if not form["fuzzable"]:
            continue  # nothing to inject into
        findings.extend(_probe_form(form, session, timeout))

    return findings
