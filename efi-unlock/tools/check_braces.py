#!/usr/bin/env python3
"""Crude brace/paren balance check for the EFI source (strings+comments aware)."""
import sys

src = open(sys.argv[1], encoding="utf-8").read()
depth = paren = 0
state = 0  # 0=code 1=// 2=block comment 3=string
line = 1
errs = []
i = 0
n = len(src)
while i < n:
    c = src[i]
    if c == "\n":
        line += 1
        if state == 1:
            state = 0
    if state == 0:
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            state = 1
        elif c == "/" and i + 1 < n and src[i + 1] == "*":
            state = 2
            i += 1
        elif c == '"':
            state = 3
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth < 0:
                errs.append(f"extra }} at line {line}")
                depth = 0
        elif c == "(":
            paren += 1
        elif c == ")":
            paren -= 1
            if paren < 0:
                errs.append(f"extra ) at line {line}")
                paren = 0
    elif state == 2:
        if c == "*" and i + 1 < n and src[i + 1] == "/":
            state = 0
            i += 1
    elif state == 3:
        if c == "\\":
            i += 1
        elif c == '"':
            state = 0
    i += 1
print(f"final brace depth: {depth}, paren depth: {paren}, state at EOF: {state}")
for e in errs[:10]:
    print(e)
sys.exit(1 if (depth or paren or errs or state) else 0)
