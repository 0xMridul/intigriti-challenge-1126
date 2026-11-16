#!/usr/bin/env python3
"""Verify the HELP-sample RSA signature offline.

The server checks RSA-2048 PKCS#1 v1.5 over a *raw* 32-byte SHA-256 digest
(no ASN.1 DigestInfo). This script decrypts the sample signature with the
public modulus embedded in the binary and checks the padding and digest.

Run from this directory:  python3 verify_signature.py
"""
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
modulus_hex = (ROOT / "artifacts/modulus.hex").read_text().strip()
n = int(modulus_hex, 16)
e = 65537

sig = (ROOT / "artifacts/help_sig.bin").read_bytes()
code = (ROOT / "artifacts/help_code.bin").read_bytes()
data = (ROOT / "artifacts/help_data.bin").read_bytes()

assert len(sig) == 256, f"expected 256-byte signature, got {len(sig)}"
assert n.bit_length() == 2048, f"expected 2048-bit modulus, got {n.bit_length()}"

# RSA "decrypt" with the public exponent, then parse the PKCS#1 v1.5 block.
em = pow(int.from_bytes(sig, "big"), e, n).to_bytes(256, "big")
digest = hashlib.sha256(code + data).digest()

# Layout: 00 01 FF .. FF 00 <32-byte digest>
padding_ok = em[:2] == b"\x00\x01" and b"\x00" in em[2:-32]
if padding_ok:
    ff_len = em[2:-32].index(b"\x00")
    padding_ok = ff_len >= 8 and set(em[2:2 + ff_len]) == {0xFF}
valid = padding_ok and em[-32:] == digest

print(f"signature            : {len(sig)} bytes")
print(f"modulus              : {n.bit_length()} bits, e={e}")
print(f"PKCS#1 prefix        : {em[:2].hex()}")
print(f"digest in signature  : {em[-32:].hex()}")
print(f"sha256(CODE||DATA)   : {digest.hex()}")
print(f"SIGNATURE VALID      : {valid}")

raise SystemExit(0 if valid else 1)
