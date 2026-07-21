#!/usr/bin/env python3
"""
Solve script for the crackme "code_linux".

Pipeline applied by the binary to the user input:
    input  --Base64 encode-->  --Caesar cipher (shift = len+1)-->  --XOR 4-->  compared to TARGET

To recover the input we invert each step in reverse order:
    TARGET  --XOR 4-->  --Caesar decrypt-->  --Base64 decode-->  input

Note: Base64 is an ENCODING (no key), Caesar and XOR are (weak) ENCRYPTIONS (with a key).
"""
import base64

# --- Constants extracted from the binary (static + dynamic analysis) ---
XOR_KEY = 4
TARGET  = "KcT6LV@JCU1lV6bJV4PcTU0f~e99"   # hard-coded value the input is compared against


def undo_xor(data: str) -> bytes:
    """Reverse the final XOR. XOR is its own inverse: re-XOR with the same key."""
    return bytes(ord(ch) ^ XOR_KEY for ch in data)


def original_input_length(b64: bytes) -> int:
    """
    Recover the length of the original input from the Base64 string.
    Base64 encodes 3 bytes into 4 chars; each '=' is 1 byte of padding.
        bytes = (len / 4) * 3 - number_of_'='
    We need this length because the Caesar shift is (length + 1).
    """
    pad = b64.count(ord('='))
    return (len(b64) // 4) * 3 - pad


def caesar_decrypt(byte: int, shift: int) -> int:
    """Reverse a Caesar shift on ASCII letters; leave everything else untouched."""
    if 0x61 <= byte <= 0x7a:            # lowercase a-z
        return (byte - 0x61 - shift) % 26 + 0x61
    if 0x41 <= byte <= 0x5a:            # uppercase A-Z
        return (byte - 0x41 - shift) % 26 + 0x41
    return byte                         # digits, symbols, '=' : unchanged


def main() -> None:
    # 1) undo the XOR
    after_xor = undo_xor(TARGET)
    print("[*] after XOR 4   :", after_xor.decode())

    # 2) derive the Caesar shift from the original input length
    shift = original_input_length(after_xor) + 1
    print("[*] input length  :", shift - 1, "-> Caesar shift:", shift)

    # 3) undo the Caesar cipher -> we get the Base64 string back
    b64_string = bytes(caesar_decrypt(b, shift) for b in after_xor)
    print("[*] after Caesar  :", b64_string.decode())

    # 4) undo the Base64 encoding -> the original input
    code = base64.b64decode(b64_string)
    print("[+] CODE          :", code.decode())


if __name__ == '__main__':
    main()
