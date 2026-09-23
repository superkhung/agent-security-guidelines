#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Export the guideline markdown to a styled PDF.

Requirements: pandoc, the WeasyPrint command line tool (brew install weasyprint,
or pip install weasyprint), fonts "Be Vietnam Pro" and "JetBrains Mono" installed
(both free on Google Fonts).

Usage: python3 pdf/build.py [input.md] [output.pdf]
Defaults: guideline/agent-security-guidelines.md -> dist/agent-security-guidelines-v<version>.pdf,
where <version> is read from the "Phiên bản" row of the document info table.
"""
import os, re, subprocess, sys, tempfile

here = os.path.dirname(os.path.abspath(__file__))
root = os.path.dirname(here)
src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(root, "guideline", "agent-security-guidelines.md")

with open(src, encoding="utf-8") as f:
    md = f.read().replace("\r\n", "\n")

def info(label):
    """Value of a row in the document info table."""
    m = re.search(r"^\|\s*%s\s*\|\s*(.+?)\s*\|\s*$" % re.escape(label), md, flags=re.M)
    if not m:
        sys.exit("build.py: no '%s' row in the document info table" % label)
    return m.group(1)

version = info("Phiên bản")
if not re.fullmatch(r"[0-9A-Za-z.+-]+", version):
    sys.exit("build.py: unexpected version string %r" % version)
status = info("Trạng thái").split(",")[0]
author = info("Tác giả")

if len(sys.argv) > 2:
    out = sys.argv[2]
else:
    os.makedirs(os.path.join(root, "dist"), exist_ok=True)
    out = os.path.join(root, "dist", "agent-security-guidelines-v%s.pdf" % version)

# The H1 lives on the cover only; keep it out of the auto-generated TOC.
md, n = re.subn(r"^# (.+)$", r'<p class="doc-title">\1</p>', md, count=1, flags=re.M)
if n != 1:
    sys.exit("build.py: no H1 title found")
md = md.replace('<p class="doc-title">Hướng dẫn kỹ thuật an ninh cho AI Agent', '<p class="doc-title">Hướng dẫn kỹ thuật an ninh cho AI&nbsp;Agent', 1)

# Drop the hand-written table of contents; the PDF gets an auto-generated one with page numbers.
md, n = re.subn(r"\n## Mục lục\n.*?\n---\n", "\n---\n", md, count=1, flags=re.S)
if n != 1:
    sys.exit("build.py: hand-written '## Mục lục' section not found (it must end with a '---' line)")

def pandoc(mdp, template, *extra):
    return subprocess.run(
        ["pandoc", mdp, "-f", "gfm", "-t", "html5", "-s", "--template", os.path.join(here, template), *extra],
        check=True, capture_output=True, encoding="utf-8").stdout

with tempfile.TemporaryDirectory() as tmp:
    mdp = os.path.join(tmp, "in.md")
    with open(mdp, "w", encoding="utf-8") as f:
        f.write(md)
    html = pandoc(mdp, "template.html", "--metadata", "pagetitle=Agent Security Technical Guidelines")
    # pandoc's template puts $body$ only; build the TOC separately and splice cover + TOC + body.
    toc = pandoc(mdp, "toc-only.html", "--toc", "--toc-depth=3")

head, body = html.split("<body>", 1)
body = body.rsplit("</body>", 1)[0]
if "<hr />" not in body:
    sys.exit("build.py: no '---' after the document info table; cannot find the end of the cover")
cover, rest = body.split("<hr />", 1)

# Running header and footer carry the version and status read from the document.
running = ('<style>@page { @top-left { content: "Agent Security Technical Guidelines · v%s"; }'
           ' @bottom-left { content: "%s · %s"; } }</style>\n'
           % (version, author.replace('"', ""), status.replace('"', "")))
head = head.replace("</head>", running + "</head>", 1)

page = (head + "<body>\n"
        + '<section class="cover">' + cover + "</section>\n"
        + toc + "\n" + rest + "\n</body>\n</html>\n")

with tempfile.TemporaryDirectory() as tmp:
    htmlp = os.path.join(tmp, "page.html")
    with open(htmlp, "w", encoding="utf-8") as f:
        f.write(page)
    subprocess.run(["weasyprint", "--base-url", here, htmlp, out], check=True)
print("wrote", out)
