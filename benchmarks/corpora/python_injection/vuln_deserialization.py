from __future__ import annotations

import yaml


def parse_configuration(payload: str):
    return yaml.load(payload, Loader=yaml.Loader)


def main():
    return parse_configuration(input())
