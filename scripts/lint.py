#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Consistency checks for the guideline repo. Standard library only.

Usage: python3 scripts/lint.py
Exits non-zero if any check fails. Each failure names the file and line.

Checks:
  1. Every control card has the level table and the eight labelled fields, in order.
  2. The 3.4 matrix lists exactly the controls that have a card.
  3. Each card's "Cấp" agrees with the first mandatory level in the matrix.
  4. Phụ lục C lists exactly the mandatory controls of each level in the matrix.
  5. Markdown tables have the same number of columns on every row.
  6. Relative links in markdown files point to files that exist.
  7. No runs of two or more blank lines outside code blocks.
  8. Companion spec: every E_ code used is defined in Section 10 and vice versa;
     every OI-n referenced exists in Appendix C and vice versa.
  9. The version in the guideline, README and CHANGELOG agree.
"""
import glob, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GUIDE = os.path.join(ROOT, "guideline", "agent-security-guidelines.md")
SPEC = os.path.join(ROOT, "companion-spec", "agent-action-binding-draft-00.md")

LEVELS = ["ASAL-0", "ASAL-1", "ASAL-2", "ASAL-3a", "ASAL-3b"]
FIELDS = ["Mục tiêu", "Chặn được", "Không chặn được", "Tổ chức cần có",
          "Làm thế nào", "Kiểm chứng", "Bỏ qua khi", "Sai lầm hay gặp"]
CONTROL_ID = r"(?:SC|ISO|NET|CRED|ACT|RES|OBS|MEM|MA)-\d\d"

errors = []

def fail(path, line, msg):
    errors.append("%s:%s: %s" % (os.path.relpath(path, ROOT), line, msg))

def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()

def lineno(text, pos):
    return text.count("\n", 0, pos) + 1

def outside_code(lines):
    """Yield (number, line) for lines outside fenced code blocks."""
    fence = False
    for i, line in enumerate(lines, 1):
        if line.startswith("```"):
            fence = not fence
            continue
        if not fence:
            yield i, line

def section(text, start_heading, end_pattern):
    i = text.index(start_heading)
    m = re.compile(end_pattern, re.M).search(text, i + len(start_heading))
    return text[i:m.start() if m else len(text)], i


# 1-3. Control cards and the 3.4 matrix -------------------------------------------------

guide = read(GUIDE)

cards = {}
for m in re.finditer(r"^#### (%s) · (.+)$" % CONTROL_ID, guide, re.M):
    cid = m.group(1)
    nxt = re.compile(r"^#{2,4} ", re.M).search(guide, m.end())
    body = guide[m.end():nxt.start() if nxt else len(guide)]
    line = lineno(guide, m.start())
    if cid in cards:
        fail(GUIDE, line, "%s has two cards" % cid)
    level_row = re.search(r"^\| :--- \| :--- \| :--- \| :--- \|\n\| (.+?) \|", body, re.M)
    if not level_row:
        fail(GUIDE, line, "%s: no level table (Cấp | Độ khó | Công sức | Cần ai)" % cid)
    found = re.findall(r"^\*\*(.+?)\.\*\* ", body, re.M)
    if found != FIELDS:
        fail(GUIDE, line, "%s: fields are %s, expected %s" % (cid, found, FIELDS))
    cards[cid] = (line, level_row.group(1) if level_row else "")

matrix_text, matrix_pos = section(guide, "### 3.4.", r"^### ")
matrix = {}
for m in re.finditer(r"^\| (%s) [^|]*\|(.*)\|\s*$" % CONTROL_ID, matrix_text, re.M):
    cells = [c.strip() for c in m.group(2).split("|")]
    line = lineno(guide, matrix_pos + m.start())
    if len(cells) != len(LEVELS):
        fail(GUIDE, line, "%s: matrix row has %d level cells" % (m.group(1), len(cells)))
        continue
    matrix[m.group(1)] = (line, [c.startswith("●") for c in cells])

for cid in sorted(set(cards) - set(matrix)):
    fail(GUIDE, cards[cid][0], "%s has a card but no row in the 3.4 matrix" % cid)
for cid in sorted(set(matrix) - set(cards)):
    fail(GUIDE, matrix[cid][0], "%s is in the 3.4 matrix but has no card" % cid)

for cid, (line, level) in cards.items():
    if cid not in matrix:
        continue
    required = matrix[cid][1]
    first = next((LEVELS[i] for i, r in enumerate(required) if r), None)
    level_first = level.split("<br>")[0]
    if level_first.startswith("Nên"):
        if first:
            fail(GUIDE, line, "%s: card says '%s' but the matrix makes it mandatory at %s" % (cid, level_first, first))
        continue
    m = re.search(r"ASAL-(\d[ab]?)", level_first)
    if not m or not first:
        fail(GUIDE, line, "%s: cannot compare card level '%s' with matrix (%s)" % (cid, level, first))
        continue
    card_level = "ASAL-" + m.group(1)
    ok = first == card_level or (card_level == "ASAL-3" and first in ("ASAL-3a", "ASAL-3b"))
    if not ok:
        fail(GUIDE, line, "%s: card level %s, matrix first ● at %s" % (cid, card_level, first))


# 4. Phụ lục C -------------------------------------------------------------------------

appc, appc_pos = section(guide, "## Phụ lục C", r"^## ")
rows = {}
for m in re.finditer(r"^\| \*\*(ASAL-[0-9ab]+)\*\* \| (.+?) \| \[ \] \|$", appc, re.M):
    rows[m.group(1)] = (lineno(guide, appc_pos + m.start()), m.group(2))

def ids(s):
    return set(re.findall(CONTROL_ID, s))

expected = {lvl: {c for c, (_, req) in matrix.items() if req[i]} for i, lvl in enumerate(LEVELS)}
listed = {}
for lvl in LEVELS:
    if lvl not in rows:
        fail(GUIDE, lineno(guide, appc_pos), "Phụ lục C has no row for %s" % lvl)
        continue
    line, text = rows[lvl]
    if lvl == "ASAL-3b":
        m = re.match(r"Như ASAL-3a, trừ ([^(;]+)", text)
        if not m or "ASAL-3a" not in listed:
            fail(GUIDE, line, "ASAL-3b row must start with 'Như ASAL-3a, trừ ...'")
            continue
        listed[lvl] = listed["ASAL-3a"] - ids(m.group(1))
    else:
        m = re.match(r"Toàn bộ (ASAL-[0-9ab]+), cộng (.+)", text)
        if m:
            listed[lvl] = listed.get(m.group(1), set()) | ids(m.group(2))
        else:
            listed[lvl] = ids(text)
    missing, extra = expected[lvl] - listed[lvl], listed[lvl] - expected[lvl]
    if missing:
        fail(GUIDE, line, "Phụ lục C %s is missing %s (● in the 3.4 matrix)" % (lvl, ", ".join(sorted(missing))))
    if extra:
        fail(GUIDE, line, "Phụ lục C %s lists %s, not ● in the 3.4 matrix" % (lvl, ", ".join(sorted(extra))))


# 5-7. All markdown files --------------------------------------------------------------

md_files = [p for p in glob.glob(os.path.join(ROOT, "**", "*.md"), recursive=True)
            if "/dist/" not in p and "/.git/" not in p]

for path in md_files:
    text = read(path)
    lines = text.split("\n")
    cols, blank, prev = None, 0, 0
    for i, line in outside_code(lines):
        if i != prev + 1:   # skipped a code block
            blank, cols = 0, None
        prev = i
        if line.startswith("|"):
            n = len(re.findall(r"(?<!\\)\|", re.sub(r"`[^`]*`", "", line)))
            if cols is None:
                cols = n
            elif n != cols:
                fail(path, i, "table row has %d cells, header has %d" % (n - 1, cols - 1))
        else:
            cols = None
        blank = blank + 1 if line.strip() == "" else 0
        if blank == 2:
            fail(path, i, "two blank lines in a row")
    for i, line in outside_code(lines):
        for target in re.findall(r"\]\(([^)\s]+)\)", re.sub(r"`[^`]*`", "", line)):
            if re.match(r"[a-z]+:", target) or target.startswith("#"):
                continue
            rel = target.split("#")[0]
            if rel.startswith("../../"):   # GitHub-relative links such as ../../releases
                continue
            if not os.path.exists(os.path.normpath(os.path.join(os.path.dirname(path), rel))):
                fail(path, i, "broken relative link: %s" % target)


# 8. Companion spec --------------------------------------------------------------------

if os.path.exists(SPEC):
    spec = read(SPEC)
    sec10, _ = section(spec, "## 10. Error codes", r"^## ")
    appc_spec, _ = section(spec, "## Appendix C", r"^## ")
    rest = spec.replace(sec10, "")
    code = r"\bE_[A-Z]+(?:_[A-Z]+)*\b"
    used, defined = set(re.findall(code, rest)), set(re.findall(code, sec10))
    for c in sorted(used - defined):
        fail(SPEC, lineno(spec, spec.index(c)), "%s is used but not defined in Section 10" % c)
    for c in sorted(defined - used):
        fail(SPEC, lineno(spec, spec.index(c)), "%s is defined in Section 10 but never used" % c)
    body = spec.replace(appc_spec, "")
    refs = set(re.findall(r"OI-(\d+)", body))
    defs = set(re.findall(r"^\| OI-(\d+) \|", appc_spec, re.M))
    for n in sorted(refs - defs, key=int):
        fail(SPEC, lineno(spec, spec.index("OI-%s" % n)), "OI-%s is referenced but not in Appendix C" % n)
    for n in sorted(defs - refs, key=int):
        fail(SPEC, lineno(spec, spec.index("| OI-%s |" % n)), "OI-%s is in Appendix C but never referenced" % n)


# 9. Version -----------------------------------------------------------------------------

m = re.search(r"^\| Phiên bản \| ([^|]+?) \|", guide, re.M)
version = m.group(1) if m else None
readme = read(os.path.join(ROOT, "README.md"))
if not version:
    fail(GUIDE, 1, "no 'Phiên bản' row in the document info table")
else:
    if "phiên bản %s" % version not in readme:
        fail(os.path.join(ROOT, "README.md"), 3, "README does not mention 'phiên bản %s'" % version)
    changelog = read(os.path.join(ROOT, "CHANGELOG.md"))
    released = re.findall(r"^## \[(\d[^\]]*)\]", changelog, re.M)
    if not released or released[0] != version:
        fail(os.path.join(ROOT, "CHANGELOG.md"), 1,
             "latest released CHANGELOG entry is %s, guideline says %s" % (released[:1], version))
    tag = os.environ.get("RELEASE_TAG")
    if tag and tag != "v" + version:
        fail(GUIDE, 1, "release tag %s does not match guideline version %s" % (tag, version))


if errors:
    print("\n".join(errors))
    print("\n%d problem(s)" % len(errors))
    sys.exit(1)
print("lint: %d control cards, %d markdown files, all checks passed" % (len(cards), len(md_files)))
