#!/usr/bin/env python3
"""Check this suite's own RFC 6962 and Ed25519 code before trusting anything it reports.

    python3 selftest.py

The Merkle answers in rfc6962_kat.json were produced by github.com/transparency-dev/merkle
(testonly.Tree), a different implementation in a different language. The Ed25519 vector is
test 1 from RFC 8032 section 7.1. Exits non-zero on any mismatch.
"""
import base64
import binascii
import json
import os
import sys

import ed25519
from gauntlet import consistency, leaf_hash, mth

FAILED = []


def check(name, got, want):
    ok = got == want
    print("%-4s %s" % ("PASS" if ok else "FAIL", name))
    if not ok:
        FAILED.append(name)
        print("       got  %s\n       want %s" % (got, want))


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    kat = json.load(open(os.path.join(here, "rfc6962_kat.json")))
    leaves = [leaf_hash(b"gauntlet-%d" % i) for i in range(50)]
    b64 = lambda b: base64.b64encode(b).decode()

    bad = [n for n, want in kat["roots"].items() if b64(mth(leaves[:int(n)])) != want]
    check("roots for sizes 0..50 match transparency-dev/merkle",
          bad, [])
    for p in kat["consistency"]:
        check("consistency proof %d -> %d" % (p["Old"], p["New"]),
              [b64(h) for h in consistency(leaves[:p["New"]], p["Old"])], p["Proof"])

    # RFC 8032 section 7.1, test 1.
    sk = binascii.unhexlify("9d61b19deffd5a60ba844af492ec2cc4"
                            "4449c5697b326919703bac031cae7f60")
    pk = binascii.unhexlify("d75a980182b10ab7d54bfed3c964073a"
                            "0ee172f3daa62325af021a68f707511a")
    sig = binascii.unhexlify("e5564300c360ac729086e2cc806e828a"
                             "84877f1eb8e5d974d873e06522490155"
                             "5fb8821590a33bacc61e39701cf9b46b"
                             "d25bf5f0595bbe24655141438e7a100b")
    check("ed25519 public key (RFC 8032 test 1)", ed25519.publickey(sk), pk)
    check("ed25519 signature (RFC 8032 test 1)", ed25519.signature(b"", sk, pk), sig)
    check("ed25519 verify (RFC 8032 test 1)", ed25519.checkvalid(sig, b"", pk) is not False, True)

    print("\n%d checks, %d failures" % (3 + 1 + len(kat["consistency"]), len(FAILED)))
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
