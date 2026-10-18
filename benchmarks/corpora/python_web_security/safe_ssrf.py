from __future__ import annotations

import urllib.request


def validate_url(url: str) -> str:
    """Validate destination against authorized API prefix."""
    if not url.startswith("https://api.example.com/"):
        raise ValueError("Invalid destination")
    return url


def fetch_external_resource(url_target: str):
    safe_target = validate_url(url_target)
    return urllib.request.urlopen(safe_target).read()


def main():
    return fetch_external_resource(input())
