from __future__ import annotations

import ast


def calculate_expression(expr: str):
    return ast.literal_eval(expr)


def main():
    return calculate_expression(input())
