#!/usr/bin/env python3
"""Wrap direct UEFI protocol calls with uefi_call_wrapper.

The 40HX upstream source calls protocol methods directly (legal on their
MSYS2/mingw toolchain where everything is ms_abi). On a Linux gnu-efi build
without GNU_EFI_USE_MS_ABI those calls must go through uefi_call_wrapper.

Usage: python3 wrap_protocol_calls.py FILE [--apply]
Without --apply it lists every match for review.
"""
import re
import sys

# Known UEFI protocol method names used in this code base.
METHODS = (
    "OutputString|InputString|Write|Read|Open|Close|Delete|Flush|GetInfo|"
    "SetInfo|SetPosition|GetPosition|OpenVolume|HandleProtocol|"
    "LocateHandleBuffer|LocateHandle|LocateProtocol|AllocatePool|FreePool|"
    "AllocatePages|FreePages|CopyMem|SetMem|Stall|LoadImage|StartImage|Exit|"
    "CheckEvent|WaitForEvent|CreateEvent|CloseEvent|SetWatchdogTimer|"
    "ConnectController|DisconnectController|InstallProtocolInterface|"
    "ReinstallProtocolInterface|UninstallProtocolInterface|"
    "HandleProtocol|RegisterProtocolNotify|GetMemoryMap|ExitBootServices|"
    "GetNextMonotonicCount|CalculateCrc1|GetTime|SetTime"
)
# object expressions that can appear before ->Method(
OBJ = r"(?:[A-Za-z_][A-Za-z0-9_]*(?:->\w+)*)"
PAT = re.compile(r"\b(" + OBJ + r")->(" + METHODS + r")\s*\(")


def find_close(s, i):
    """s[i] == '(' ; return index just past the matching ')'."""
    depth = 0
    while i < len(s):
        c = s[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        elif c == '"':  # skip string literal
            i += 1
            while i < len(s) and s[i] != '"':
                if s[i] == "\\":
                    i += 1
                i += 1
        i += 1
    return -1


def count_args(args):
    args = args.strip()
    if not args:
        return 0
    depth = 0
    n = 1
    i = 0
    while i < len(args):
        c = args[i]
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif c == "," and depth == 0:
            n += 1
        elif c == '"':
            i += 1
            while i < len(args) and args[i] != '"':
                if args[i] == "\\":
                    i += 1
                i += 1
        i += 1
    return n


def main():
    path = sys.argv[1]
    apply = "--apply" in sys.argv
    src = open(path, encoding="utf-8").read()
    out = []
    pos = 0
    n = 0
    while True:
        m = PAT.search(src, pos)
        if not m:
            out.append(src[pos:])
            break
        start = m.start()
        # skip if the call is already the function of a wrapper:
        # look back for 'uefi_call_wrapper(' before this call on the same stmt
        line_start = src.rfind("\n", 0, start) + 1
        prefix = src[line_start:start]
        if "uefi_call_wrapper" in prefix:
            out.append(src[pos:m.end()])
            pos = m.end()
            continue
        open_idx = m.end() - 1
        close = find_close(src, open_idx)
        if close < 0:
            out.append(src[pos:m.end()])
            pos = m.end()
            continue
        args = src[open_idx + 1 : close - 1]
        nargs = count_args(args)
        n += 1
        print(f"{src.count(chr(10), 0, start)+1}: {m.group(1)}->{m.group(2)} ({nargs} args)")
        if apply:
            out.append(src[pos:start])
            out.append(f"uefi_call_wrapper({m.group(1)}->{m.group(2)}, {nargs}, {args})")
        else:
            out.append(src[pos:close])
        pos = close
    print(f"total: {n} call sites")
    if apply:
        open(path, "w", encoding="utf-8", newline="\n").write("".join(out))
        print("APPLIED")


if __name__ == "__main__":
    main()
