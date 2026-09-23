#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Run every aab-00 test vector against the Python reference implementation.

Usage::

    python3 companion-spec/vectors/run.py [--group ENC] [--fail-fast] [--no-crypto] [-v]

The signature backend is ``cryptography`` when that package imports, else
none (standard library only). ``--no-crypto`` (or ``AAB_BACKEND=none``)
forces the stdlib-only mode.

For each vector file (spec Section 12.2):

* ``expected.status == "provisional"``: the outcome must contain every
  expected key with an equal value; ``differs_from`` / ``same_as`` compare
  the digest with another vector's expected digest.
* ``"requires": ["crypto"]`` and no backend: the vector cannot be decided
  and is counted in the ``no-crypto`` column, never as a failure. Its
  ``precheck.stdlib`` (what the stdlib-only mode must reach, normally
  ``needs-crypto`` at the signature step) is still checked.
* ``expected.status == "pending"``: counted as pending; the ``precheck``
  for the active backend, if any, is checked, so pending vectors still guard
  against regressions.

The runner also checks that every vector ID in Appendix B of the spec has a
file. It exits non-zero on any mismatch or missing file.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
import warnings

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = os.path.join(HERE, "..", "agent-action-binding-draft-00.md")
sys.path.insert(0, os.path.join(HERE, "..", "reference", "python"))

warnings.simplefilter("ignore", RuntimeWarning)
from aab import encoding, sigs  # noqa: E402
from aab.vectorexec import execute  # noqa: E402

GROUPS = ["ENC", "FP", "ACT", "WA", "DK", "LS", "LOG", "E2E"]
META = {"status", "source"}
RELATIONS = {"differs_from": False, "same_as": True}  # expected.<key>: other vector id
STATUSES = ("pass", "fail", "pending", "no-crypto")


def subset(expect, got) -> bool:
    if isinstance(expect, dict):
        return isinstance(got, dict) and all(k in got and subset(v, got[k]) for k, v in expect.items())
    if isinstance(expect, list):
        return isinstance(got, list) and len(expect) == len(got) and all(subset(a, b) for a, b in zip(expect, got))
    return expect == got


def catalogue_ids():
    with open(SPEC, encoding="utf-8") as fh:
        text = fh.read()
    start = text.index("## Appendix B.")
    end = text.index("## Appendix C.")
    return re.findall(r"^\| ([A-Z0-9]+-\d{3})\b", text[start:end], flags=re.M)


def _precheck(v: dict, backend, mode: str):
    pre = v.get("precheck", {}).get(mode)
    if pre is None:
        return None
    got = execute(v, backend=backend)
    if not subset(pre, got):
        return "precheck.%s mismatch: got %s" % (mode, json.dumps(got)[:300])
    return None


def check(v: dict, by_id: dict, backend=None):
    """Return (status, message), status one of STATUSES."""
    backend = backend or sigs.default_backend()
    mode = "crypto" if sigs.has_crypto(backend) else "stdlib"
    exp = v.get("expected", {})
    if exp.get("status") == "pending":
        err = _precheck(v, backend, mode)
        return ("fail", err) if err else ("pending", v.get("note", ""))
    if "crypto" in v.get("requires", []) and mode == "stdlib":
        err = _precheck(v, backend, mode)
        return ("fail", err) if err else ("no-crypto", "needs a crypto backend")
    got = execute(v, backend=backend)
    want = {k: val for k, val in exp.items() if k not in META and k not in RELATIONS}
    if not subset(want, got):
        return "fail", "got %s" % json.dumps(got)[:300]
    for key, same in RELATIONS.items():
        if key in exp:
            other = by_id[exp[key]]["expected"].get("digest")
            if other is None or (got.get("digest") == other) != same:
                return "fail", "%s %s violated" % (key, exp[key])
    return "pass", ""


def load_vectors():
    vectors = []
    for path in sorted(glob.glob(os.path.join(HERE, "*", "*.json"))):
        with open(path, encoding="utf-8") as fh:
            v = json.load(fh)
        rel = os.path.relpath(path, HERE)
        if rel != os.path.join(v["group"], v["id"] + ".json"):
            raise SystemExit("FAIL %s: id/group do not match the file name" % rel)
        vectors.append(v)
    return vectors


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--group", action="append", help="run only this group (repeatable)")
    ap.add_argument("--fail-fast", action="store_true", help="stop at the first mismatch (Section 12.2)")
    ap.add_argument("--no-crypto", action="store_true", help="force the stdlib-only mode (no signature backend)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    backend = sigs.NullBackend() if args.no_crypto else sigs.default_backend()
    print("Python %s, unicodedata %s (spec pins %s)%s" % (
        sys.version.split()[0], encoding.UNICODE_VERSION, encoding.PINNED_UNICODE_VERSION,
        "" if encoding.UNICODE_PIN_OK else "  WARNING: Unicode pin not honoured"))
    print("Signature backend: %s" % getattr(backend, "name", type(backend).__name__))
    vectors = load_vectors()
    by_id = {v["id"]: v for v in vectors}
    missing = [i for i in catalogue_ids() if i not in by_id]
    groups = args.group or GROUPS
    counts = {g: dict.fromkeys(STATUSES, 0) for g in groups}
    failed = False
    for v in vectors:
        if v["group"] not in groups:
            continue
        status, msg = check(v, by_id, backend)
        counts[v["group"]][status] += 1
        if status == "fail":
            failed = True
            print("FAIL %s: %s" % (v["id"], msg))
            if args.fail_fast:
                break
        elif args.verbose:
            print("%-9s %s %s" % (status.upper(), v["id"], msg[:100]))
    print()
    print("%-5s %5s %5s %8s %10s" % ("group", *STATUSES))
    tot = dict.fromkeys(STATUSES, 0)
    for g in groups:
        c = counts[g]
        print("%-5s %5d %5d %8d %10d" % (g, *(c[s] for s in STATUSES)))
        for k in tot:
            tot[k] += c[k]
    print("%-5s %5d %5d %8d %10d" % ("total", *(tot[s] for s in STATUSES)))
    if tot["no-crypto"]:
        print("\n%d vectors need a signature backend and were not decided (install `cryptography`)."
              % tot["no-crypto"])
    if missing:
        failed = True
        print("MISSING vector files for Appendix B ids: %s" % ", ".join(missing))
    print("\nAll expected values are provisional (source reference-python-1) until a second, "
          "independent implementation agrees (spec Section 12.3).")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
