

import os, hashlib
from ecdsa import SECP256k1, ellipticcurve

curve = SECP256k1
G = curve.generator
order = curve.order

def sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()

def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, "big")

def hash_to_int(*parts: bytes) -> int:
    return int_from_bytes(sha256(*parts)) % order

# deterministically derive a second generator H (simple approach)
def _derive_H() -> ellipticcurve.Point:
    seed = sha256(b"pedersen-H-v1")
    k = int_from_bytes(seed) % order
    return k * G
H = _derive_H()

def pedersen_commit(value: int, blinding: int = None):
    if blinding is None:
        blinding = int_from_bytes(os.urandom(32)) % order
    v = value % order
    C_point = v * H + blinding * G
    return C_point, v, blinding

def point_to_bytes(P: ellipticcurve.Point) -> bytes:
    x = int(P.x()).to_bytes(32, "big")
    y = int(P.y()).to_bytes(32, "big")
    return b"\x04" + x + y

def bytes_to_point(b: bytes) -> ellipticcurve.Point:
    assert b[0] == 4
    x = int.from_bytes(b[1:33], "big")
    y = int.from_bytes(b[33:65], "big")
    return ellipticcurve.Point(curve.curve, x, y, order)

# Schnorr-style NIZK proof of knowledge of opening (v, r) for C = v*H + r*G
def prove_pedersen_opening(C_point, value: int, blinding: int):
    k1 = int_from_bytes(os.urandom(32)) % order
    k2 = int_from_bytes(os.urandom(32)) % order
    t_point = k1 * H + k2 * G
    c = hash_to_int(point_to_bytes(C_point), point_to_bytes(t_point))
    s1 = (k1 + c * (value % order)) % order
    s2 = (k2 + c * (blinding % order)) % order
    return {
        "t": point_to_bytes(t_point).hex(),
        "s1": str(s1),
        "s2": str(s2)
    }

def verify_pedersen_opening(C_bytes_hex, proof):
    C_bytes = bytes.fromhex(C_bytes_hex)
    C_point = bytes_to_point(C_bytes)
    t_bytes = bytes.fromhex(proof["t"])
    t_point = bytes_to_point(t_bytes)
    c = hash_to_int(point_to_bytes(C_point), point_to_bytes(t_point))
    s1 = int(proof["s1"]) % order
    s2 = int(proof["s2"]) % order
    lhs = s1 * H + s2 * G
    rhs = t_point + c * C_point
    return lhs == rhs
