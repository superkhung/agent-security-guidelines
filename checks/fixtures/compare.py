#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compare an asal probe report with the expected statuses of a fixture.

Usage: python3 checks/fixtures/compare.py report.json checks/fixtures/expected/<fixture>.json
Exits 1 if any expected probe is missing or has another status.
"""
import json, sys


def main(report_path, expected_path):
    with open(report_path, encoding="utf-8") as f:
        report = json.load(f)
    with open(expected_path, encoding="utf-8") as f:
        expected = json.load(f)
    got = {r["probe"]: r for r in report["results"]}
    bad = 0
    print("fixture: %s — %s" % (expected["fixture"], expected.get("description", "")))
    for probe, want in sorted(expected["expect"].items()):
        r = got.get(probe)
        have = r["status"] if r else "missing"
        ok = have == want
        bad += not ok
        print("  %-4s %-26s expected %-8s got %-8s %s" % ("ok" if ok else "FAIL", probe, want, have, r["message"] if r else ""))
    print("%d of %d expectations met" % (len(expected["expect"]) - bad, len(expected["expect"])))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
