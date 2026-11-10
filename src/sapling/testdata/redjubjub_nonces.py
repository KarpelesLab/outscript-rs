#!/usr/bin/env python3
"""Regenerates redjubjub_nonces.json: the random strings T that
zcash-test-vectors' sapling/redjubjub.py drew for each signature of
sapling_signatures.json, so that the signatures can be reproduced exactly.

The script replays the generator's random stream (Random(0xabad533d), one
randrange(0, 256) per byte): per vector, 64 bytes for sk, 80 for alpha, then
80 for the signature under sk and 80 for the signature under rsk. It checks
the replay against the sk and alpha columns of the vectors.

Usage: redjubjub_nonces.py sapling_signatures.json > redjubjub_nonces.json
"""
import json
import sys
from hashlib import blake2b
from random import Random

R_J = 6554484396890773809930967563523245729705921265872317281365359162392183254199

rng = Random(0xABAD533D)


def randbytes(n):
    return bytes(rng.randrange(0, 256) for _ in range(n))


def scalar(b):
    return (int.from_bytes(b, "little") % R_J).to_bytes(32, "little").hex()


vectors = json.load(open(sys.argv[1]))[2:]
out = []
for v in vectors:
    sk = randbytes(64)
    assert scalar(sk) == v[0], "sk mismatch"
    alpha = randbytes(80)
    h = blake2b(alpha, person=b"Zcash_RedJubjubH").digest()
    assert scalar(h) == v[2], "alpha mismatch"
    out.append([randbytes(80).hex(), randbytes(80).hex()])

print("[")
print('    ["Replayed from zcash_test_vectors/sapling/redjubjub.py by redjubjub_nonces.py"],')
print('    ["t_sig, t_rsig"],')
print(",\n".join("    " + json.dumps(row) for row in out))
print("]")
