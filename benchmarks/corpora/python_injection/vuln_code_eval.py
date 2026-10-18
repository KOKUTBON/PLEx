from __future__ import annotations


def calculate_expression(expr: str):
    return eval(expr)


def main():
    return calculate_expression(input())
