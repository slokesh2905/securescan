"""
scanner/scope.py
~~~~~~~~~~~~~~~~
SecureScan — domain-scope utilities.

Extracted into their own module so that both engine.py and any probe
module (e.g. redirects.py) can import scope helpers without creating
circular import cycles.

Requires: tldextract
"""

from __future__ import annotations

from urllib.parse import urlparse

import tldextract


def registered_domain(url: str) -> str:
    """
    Return the *registered domain* of *url* (domain + public suffix),
    lowercased.

    Uses ``tldextract`` so that compound suffixes like ``co.uk``,
    ``com.au``, ``pvt.k12.ma.us`` are handled correctly — a simple
    ``split('.')[-2:]`` approach would fail for these.

    Examples
    --------
    >>> registered_domain("https://sub.example.com/path")
    'example.com'
    >>> registered_domain("https://sub.example.co.uk/path")
    'example.co.uk'
    >>> registered_domain("http://192.168.1.1/")
    ''          # bare IPs have no registered domain
    """
    extracted = tldextract.extract(url)
    # domain + suffix; empty when the host is a bare IP or localhost.
    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}".lower()
    return ""


def is_in_scope(url: str, origin_url: str) -> bool:
    """
    Return True when *url* shares the same *registered domain* as
    *origin_url*.

    Subdomains are permitted — ``sub.example.com`` is considered in-scope
    for ``example.com``.  Completely different registered domains are
    always out-of-scope.

    Parameters
    ----------
    url:
        The candidate URL to evaluate.
    origin_url:
        The original scan target URL (the "origin" of the scan).

    Returns
    -------
    bool

    Examples
    --------
    >>> is_in_scope("https://api.example.com/v1", "https://www.example.com")
    True
    >>> is_in_scope("https://evil.com/steal", "https://example.com")
    False
    >>> is_in_scope("", "https://example.com")
    False
    """
    if not url:
        return False

    # Relative URLs (no scheme) are always on the same origin.
    parsed = urlparse(url)
    if not parsed.scheme:
        return True

    origin_rd = registered_domain(origin_url)
    target_rd = registered_domain(url)

    if not origin_rd or not target_rd:
        # If either is a bare IP or unparseable, fall back to strict
        # netloc equality to avoid accidentally widening scope.
        origin_netloc = urlparse(origin_url).netloc.lower()
        target_netloc = parsed.netloc.lower()
        return origin_netloc == target_netloc

    return origin_rd == target_rd
