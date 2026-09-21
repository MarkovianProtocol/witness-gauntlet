#!/usr/bin/env python3
"""Drive a C2SP tlog-witness through a set of adversarial checkpoints and report what it did.

    python3 gauntlet.py --url http://127.0.0.1:8477 --origin test.example/log --seed-hex <64 hex>

The suite signs its own test log, so the witness under test has to be configured to trust
that log's key for that origin first; `--print-vkey` emits the vkey line and exits. Nothing
here touches a production witness's state: every case is about one origin, the one the
operator pointed at this suite.

Stdlib only. The Ed25519 beside this file is a from-scratch RFC 8032 implementation, so a
run does not depend on the same crypto library the witness under test uses.

Each case states the rule it checks and where the rule comes from:

  spec   c2sp.org/tlog-witness or c2sp.org/tlog-checkpoint says so. A FAIL is a defect.
  strict stricter than the Go reference witness (transparency-dev/witness), which accepts
         the input. A FAIL is a choice, not a defect - it is reported as STRICT-MISS so the
         operator can decide.

Exit code is 1 if any spec case fails, 0 otherwise. STRICT-MISS never fails the run.
"""
import argparse
import base64
import hashlib
import json
import sys
import urllib.error
import urllib.request

import ed25519

# ---------------------------------------------------------------- RFC 6962

def leaf_hash(b):
    return hashlib.sha256(b"\x00" + b).digest()


def node_hash(l, r):
    return hashlib.sha256(b"\x01" + l + r).digest()


def _split(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(leaves):
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return node_hash(mth(leaves[:k]), mth(leaves[k:]))


def consistency(leaves, first):
    """RFC 6962 section 2.1.2 consistency proof from `first` to len(leaves)."""
    def sub(m, ls, b):
        if m == len(ls):
            return [] if b else [mth(ls)]
        k = _split(len(ls))
        if m <= k:
            return sub(m, ls[:k], b) + [mth(ls[k:])]
        return sub(m - k, ls[k:], False) + [mth(ls[:k])]
    return sub(first, leaves, True)


# ---------------------------------------------------------------- notes

def key_id(name, pub):
    """C2SP signed-note key id: SHA-256(name || 0x0A || 0x01 || pubkey)[:4]."""
    return hashlib.sha256(name.encode() + b"\n" + bytes([1]) + pub).digest()[:4]


def vkey(name, pub):
    return "%s+%08x+%s" % (name, int.from_bytes(key_id(name, pub), "big"),
                           base64.b64encode(bytes([1]) + pub).decode())


def signed_note(text, name, sk, pub):
    """A signed note over exactly `text` (which ends in a newline)."""
    sig = ed25519.signature(text.encode(), sk, pub)
    line = "— %s %s\n" % (name, base64.b64encode(key_id(name, pub) + sig).decode())
    return text + "\n" + line


def checkpoint(origin, size, root_b64):
    return "%s\n%d\n%s\n" % (origin, size, root_b64)


# ---------------------------------------------------------------- transport

def add_checkpoint(url, old_size, proof_b64, note, timeout=30):
    body = ("old %d\n" % old_size + "".join(p + "\n" for p in proof_b64) + "\n" + note).encode()
    req = urllib.request.Request(url.rstrip("/") + "/add-checkpoint", data=body,
                                 headers={"Content-Type": "text/plain; charset=utf-8"},
                                 method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)


# ---------------------------------------------------------------- the cases

class Suite:
    def __init__(self, url, origin, sk):
        self.url, self.origin = url, origin
        self.sk, self.pub = sk, ed25519.publickey(sk)
        self.leaves = [leaf_hash(b"gauntlet-%d" % i) for i in range(50)]
        self.results = []

    def vkey(self):
        return vkey(self.origin, self.pub)

    def root(self, n):
        return mth(self.leaves[:n])

    def cp(self, n, root=None, root_b64=None, origin=None):
        rb = root_b64 if root_b64 is not None else base64.b64encode(
            root if root is not None else self.root(n)).decode()
        return signed_note(checkpoint(origin or self.origin, n, rb), self.origin, self.sk, self.pub)

    def proof(self, old, new):
        return [base64.b64encode(h).decode() for h in consistency(self.leaves[:new], old)]

    def case(self, name, tier, rule, want, old, note, proof=()):
        status, body, headers = add_checkpoint(self.url, old, list(proof), note)
        ok = status in want
        verdict = "PASS" if ok else ("FAIL" if tier == "spec" else "STRICT-MISS")
        self.results.append((verdict, name, tier, status, want, rule,
                             body.decode("utf-8", "replace").strip()[:60]))
        return status, body, headers

    def run(self):
        c = self.case
        # Order matters. A witness holding state for this origin refuses a mismatched old
        # size before it ever looks at the root, so the size-0 case has to run while the
        # stored size is still 0 - otherwise the suite reads its own staleness as a defect.
        c("size-0 checkpoint, non-empty root", "spec",
          "tlog-checkpoint: an empty tree's root is MTH({}) = SHA-256(\"\")",
          (400, 422), 0, self.cp(0, root=hashlib.sha256(b"not-empty").digest()))
        # The witness must start from nothing for this origin, or the next case is not
        # trust-on-first-use. A witness that already holds state answers 409 with its size.
        st, body, _ = add_checkpoint(self.url, 0, [], self.cp(5))
        if st == 409:
            print("this witness already holds state for %s at size %s - "
                  "point the suite at a fresh origin" % (self.origin, body.decode().strip()),
                  file=sys.stderr)
            return 2
        self.results.append(("PASS" if st == 200 else "FAIL", "trust on first use", "spec",
                             st, (200,), "tlog-witness: first checkpoint of an unknown tree",
                             body.decode("utf-8", "replace").strip()[:60]))

        c("growth without a proof", "spec",
          "tlog-witness: a larger tree MUST come with a consistency proof that verifies",
          (422,), 5, self.cp(25))
        c("growth with a real proof", "spec",
          "tlog-witness: a proven extension is cosigned", (200,), 5, self.cp(25),
          self.proof(5, 25))
        c("stale old size", "spec",
          "tlog-witness: old size MUST equal the size last cosigned; 409 carries our size",
          (409,), 5, self.cp(25), self.proof(5, 25))
        c("garbage consistency proof", "spec",
          "tlog-witness: an extension whose proof does not verify MUST be refused",
          (422,), 25, self.cp(40), [base64.b64encode(bytes(32)).decode() for _ in range(4)])
        fork = mth(self.leaves[:24] + [leaf_hash(b"FORK")])
        c("second root at a cosigned size", "spec",
          "tlog-witness: one size, one root - this pair is equivocation evidence",
          (422,), 25, self.cp(25, root=fork))
        c("rollback below our size", "spec",
          "tlog-witness: a smaller tree than the one cosigned MUST be refused",
          (400, 409), 25, self.cp(10))
        c("unknown origin", "spec",
          "tlog-witness: a log this witness does not know MUST be 404",
          (404,), 0, self.cp(5, origin=self.origin + ".unknown"))
        bad = self.cp(25, root=fork)
        c("signature that does not verify", "spec",
          "tlog-witness: no trusted signature on the checkpoint MUST be 403",
          (403,), 25, bad[:-8] + "AAAAAAA\n")
        c("more than 63 proof lines", "spec",
          "tlog-witness: a client MUST NOT send more than 63 proof lines",
          (400, 422), 25, self.cp(40), [base64.b64encode(bytes(32)).decode() for _ in range(64)])
        # strict tier: the Go reference witness accepts both of these.
        alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        rb = base64.b64encode(self.root(25)).decode()
        noncanon = rb[:-2] + alph[(alph.index(rb[-2]) + 1) % 64] + "="
        assert base64.b64decode(noncanon) == self.root(25)
        c("non-canonical base64 root", "strict",
          "same bytes, different text: two checkpoints for one tree state",
          (400, 422), 25, self.cp(25, root_b64=noncanon))
        # This case cannot isolate a length check over this interface: the witness already
        # holds a root at size 25, so a refusal may be the ordinary mismatch rather than a
        # judgement about the length. What it does show is WHICH refusal the witness picks,
        # and a witness that calls this equivocation is accusing a log over a malformed root.
        c("wrong-length root at a size held", "strict",
          "refused either way; the interesting part is whether it is called equivocation",
          (400, 422), 25, self.cp(25, root=self.root(25) + b"\x00"))
        # A fork at a size the witness cosigned earlier and has moved past. The protocol
        # answer is the stale-size refusal either way; what differs is whether the witness
        # keeps the pair. That is not visible over this interface, so the case only records
        # the refusal.
        c("fork below the current size", "spec",
          "tlog-witness: refused as stale; whether the pair is kept is not visible here",
          (400, 409), 5, self.cp(5, root=mth(self.leaves[:4] + [leaf_hash(b"LATE")])))
        return 0

    def report(self, as_json=False):
        if as_json:
            print(json.dumps([{"verdict": v, "case": n, "tier": t, "status": s,
                               "expected": list(w), "rule": r, "body": b}
                              for v, n, t, s, w, r, b in self.results], indent=1))
        else:
            width = max(len(n) for _, n, *_ in self.results)
            for v, n, t, s, w, r, b in self.results:
                mark = {"PASS": "PASS", "FAIL": "FAIL", "STRICT-MISS": "MISS"}[v]
                print("%-4s %-*s  got %-3s want %-12s %s" %
                      (mark, width, n, s, "/".join(str(x) for x in w), r))
                if v != "PASS" and b:
                    print("     %s%s" % (" " * width, "  said: " + b))
        fails = sum(1 for v, *_ in self.results if v == "FAIL")
        miss = sum(1 for v, *_ in self.results if v == "STRICT-MISS")
        print("\n%d cases, %d spec failures, %d stricter-than-reference misses"
              % (len(self.results), fails, miss))
        return 1 if fails else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--url", help="witness base URL, e.g. http://127.0.0.1:8477")
    ap.add_argument("--origin", default="gauntlet.example/log")
    ap.add_argument("--seed-hex", default="00" * 31 + "01",
                    help="32-byte test log seed, hex (default: a fixed test seed)")
    ap.add_argument("--print-vkey", action="store_true",
                    help="print the test log's vkey line and exit")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    sk = bytes.fromhex(a.seed_hex)
    if len(sk) != 32:
        ap.error("seed must be 32 bytes")
    s = Suite(a.url, a.origin, sk)
    if a.print_vkey:
        print(s.vkey())
        return 0
    if not a.url:
        ap.error("--url is required (or --print-vkey)")
    rc = s.run()
    if rc:
        return rc
    return s.report(a.json)


if __name__ == "__main__":
    sys.exit(main())
