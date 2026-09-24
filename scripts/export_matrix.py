#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Export the 3.4 control matrix of the guideline to checks/asal_matrix.json.

The asal report command reads this file to know which controls each ASAL level
requires. It is generated, never edited by hand; scripts/lint.py fails when it is
out of date.

Usage: python3 scripts/export_matrix.py            # write the file
       python3 scripts/export_matrix.py --check    # exit 1 if the file is out of date
"""
import json, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GUIDE = os.path.join(ROOT, "guideline", "agent-security-guidelines.md")
OUT = os.path.join(ROOT, "checks", "asal_matrix.json")
LEVELS = ["ASAL-0", "ASAL-1", "ASAL-2", "ASAL-3a", "ASAL-3b"]
CONTROL_ID = r"(?:SC|ISO|NET|CRED|ACT|RES|OBS|MEM|MA)-\d\d"
MARKS = {"●": "required", "◐": "recommended", "○": "optional", "–": "not-applicable"}


def build(guide_text):
    version = re.search(r"^\| Phiên bản \| ([^|]+?) \|", guide_text, re.M).group(1)
    start = guide_text.index("### 3.4.")
    end = guide_text.index("\n### ", start + 1)
    controls = {}
    for m in re.finditer(r"^\| (%s) ([^|]*)\|(.*)\|\s*$" % CONTROL_ID, guide_text[start:end], re.M):
        cells = [c.strip() for c in m.group(3).split("|")]
        if len(cells) != len(LEVELS):
            raise ValueError("matrix row %s has %d level cells" % (m.group(1), len(cells)))
        controls[m.group(1)] = {
            "name": m.group(2).strip(),
            "levels": {lvl: MARKS[cell[0]] for lvl, cell in zip(LEVELS, cells)},
            "notes": {lvl: cell[1:].strip(" ()") for lvl, cell in zip(LEVELS, cells) if cell[1:].strip()},
        }
    for cid in controls:
        if not controls[cid]["notes"]:
            del controls[cid]["notes"]
    return {"schema": "asal-matrix/1", "guideline_version": version, "levels": LEVELS, "controls": controls}


def render(matrix):
    return json.dumps(matrix, ensure_ascii=False, indent=2) + "\n"


def main():
    with open(GUIDE, encoding="utf-8") as f:
        text = render(build(f.read()))
    if "--check" in sys.argv:
        try:
            with open(OUT, encoding="utf-8") as f:
                current = f.read()
        except OSError:
            current = ""
        if current != text:
            print("checks/asal_matrix.json is out of date: run python3 scripts/export_matrix.py")
            sys.exit(1)
        return
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(text)
    print("wrote", os.path.relpath(OUT, ROOT))


if __name__ == "__main__":
    main()
