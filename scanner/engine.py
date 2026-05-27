"""
scanner/engine.py
~~~~~~~~~~~~~~~~~
SecureScan — scan engine.

Phase 1 — passive checks (single HTTP request)
    Runs headers.check() and cookies.check() against the initial response.

Phase 2 — active probing (additional requests)
    forms.check()     — crawls <form> elements and submits SQLi payloads to
                        same-origin endpoints (error-based detection only).
    redirects.check() — discovers redirect-param URLs, probes with a canary
                        domain, flags open redirects on first-hop Location.

Scope enforcement
    is_in_scope(url, origin_url) validates that a discovered URL shares the
    same registered domain as the scan origin (via tldextract).  Subdomains
    are permitted; cross-domain URLs are always rejected.

Usage (module entry-point)
--------------------------
    python -m scanner.engine https://example.com
"""

from __future__ import annotations

import sys
import textwrap
from typing import TypedDict

import requests

from scanner import cookies, forms, headers, redirects
from scanner.scope import is_in_scope as is_in_scope  # re-exported public API
from scanner.scope import registered_domain as registered_domain  # re-exported


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------

class Finding(TypedDict):
    check_name: str
    severity: str          # "critical" | "high" | "medium" | "info"
    description: str
    recommendation: str


# ---------------------------------------------------------------------------
# Severity ordering for display
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "info": 3,
}

_SEVERITY_LABELS: dict[str, str] = {
    "critical": "CRITICAL",
    "high":     "HIGH    ",
    "medium":   "MEDIUM  ",
    "info":     "INFO    ",
}

# ANSI colour codes (degraded gracefully if the terminal doesn't support them)
_SEVERITY_COLORS: dict[str, str] = {
    "critical": "\033[91m",   # bright red
    "high":     "\033[31m",   # red
    "medium":   "\033[93m",   # bright yellow
    "info":     "\033[36m",   # cyan
}
_RESET = "\033[0m"


# ---------------------------------------------------------------------------
# Core scan function
# ---------------------------------------------------------------------------

def scan(url: str, timeout: int = 15) -> list[Finding]:
    """
    Fetch *url* and run all registered check modules.

    Parameters
    ----------
    url:
        The target URL (must include scheme, e.g. ``https://example.com``).
    timeout:
        Connection + read timeout in seconds passed to ``requests.get``.
        Also forwarded to Phase 2 probe requests.

    Returns
    -------
    list[Finding]
        Aggregated findings from every check module, sorted by severity.

    Raises
    ------
    requests.RequestException
        Propagates any network-level error to the caller.
    """
    response = requests.get(
        url,
        timeout=timeout,
        allow_redirects=True,
        headers={"User-Agent": "SecureScan/1.0 (+https://github.com/securescan)"},
    )

    all_findings: list[Finding] = []

    # ------------------------------------------------------------------
    # Phase 1 — passive checks (operate on the single initial response)
    # Each module must expose: check(response) -> list[Finding]
    # ------------------------------------------------------------------
    passive_modules = [
        headers,
        cookies,
    ]
    for module in passive_modules:
        all_findings.extend(module.check(response))

    # ------------------------------------------------------------------
    # Phase 2 — active probing
    # Both modules share the signature: check(url, response, timeout)
    # They use is_in_scope() from scanner.scope for domain enforcement.
    # ------------------------------------------------------------------
    all_findings.extend(forms.check(url, response, timeout=timeout))
    all_findings.extend(redirects.check(url, response, timeout=timeout))

    # Sort by severity so critical issues surface first.
    all_findings.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 99))

    return all_findings


# ---------------------------------------------------------------------------
# Pretty-print helper
# ---------------------------------------------------------------------------

def _severity_badge(severity: str, use_color: bool = True) -> str:
    label = _SEVERITY_LABELS.get(severity, severity.upper().ljust(8))
    if use_color and sys.stdout.isatty():
        color = _SEVERITY_COLORS.get(severity, "")
        return f"{color}[{label}]{_RESET}"
    return f"[{label}]"


def print_findings(findings: list[Finding], url: str) -> None:
    """Render *findings* as formatted text to stdout."""
    use_color = sys.stdout.isatty()
    width = 78

    print()
    print("=" * width)
    print(f"  SecureScan — {url}")
    print("=" * width)

    if not findings:
        print("\n  ✅  No issues found — all checks passed.\n")
        print("=" * width)
        return

    print(f"\n  {len(findings)} finding(s) detected\n")

    for idx, finding in enumerate(findings, start=1):
        badge = _severity_badge(finding["severity"], use_color)
        print(f"  {idx:>2}. {badge}  {finding['check_name']}")
        print()

        desc_lines = textwrap.wrap(finding["description"], width=72)
        for line in desc_lines:
            print(f"        {line}")
        print()

        rec_lines = textwrap.wrap(
            f"=> {finding['recommendation']}", width=72
        )
        for line in rec_lines:
            print(f"        {line}")

        print()
        print("  " + "-" * (width - 2))
        print()

    # Summary counts
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    print("  Summary:")
    for sev in ("critical", "high", "medium", "info"):
        n = counts.get(sev, 0)
        if n:
            badge = _severity_badge(sev, use_color)
            print(f"    {badge}  {n}")
    print()
    print("=" * width)
    print()


# ---------------------------------------------------------------------------
# __main__ entry-point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m scanner.engine <url>", file=sys.stderr)
        sys.exit(1)

    target_url = sys.argv[1]

    try:
        results = scan(target_url)
    except requests.exceptions.MissingSchema:
        print(
            f"Error: invalid URL '{target_url}'. "
            "Did you forget 'https://'?",
            file=sys.stderr,
        )
        sys.exit(1)
    except requests.exceptions.ConnectionError as exc:
        print(f"Error: could not connect to '{target_url}': {exc}", file=sys.stderr)
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(f"Error: request to '{target_url}' timed out.", file=sys.stderr)
        sys.exit(1)
    except requests.exceptions.RequestException as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    print_findings(results, target_url)
    # Exit with non-zero code if any high/critical findings exist.
    has_critical = any(f["severity"] in ("critical", "high") for f in results)
    sys.exit(1 if has_critical else 0)
