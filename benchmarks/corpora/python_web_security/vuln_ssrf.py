from __future__ import annotations

import urllib.request


def fetch_external_resource(url_target: str):
    return urllib.request.urlopen(url_target).read()


def main():
    return fetch_external_resource(input())
