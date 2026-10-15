import re


def render(items):
    text = ""
    for item in items:
        text += str(item)
        re.compile("prefix.*").match(str(item))
    return text


def pairs(values):
    result = []
    for left in values:
        for right in values:
            result.append((left, right))
    return result


def count(values):
    return len(values)
