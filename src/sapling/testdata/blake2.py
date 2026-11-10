#!/usr/bin/env python3
"""Regenerates blake2.txt: personalized BLAKE2 known answers from hashlib."""
import hashlib

print(hashlib.blake2s(b"abc", person=b"Zcash_nf").hexdigest())
print(hashlib.blake2b(b"abc", person=b"Zcash_ExpandSeed").hexdigest())
print(hashlib.blake2b(b"abc", digest_size=32, person=b"Zcash_ExpandSeed").hexdigest())
