from __future__ import annotations

import yaml


def parse_configuration(payload: str):
    return yaml.safe_load(payload)


def main():
    return parse_configuration(input())
