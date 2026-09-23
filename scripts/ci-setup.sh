#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Install the PDF toolchain on an Ubuntu CI runner: pandoc, WeasyPrint (pinned),
# and the two fonts from google/fonts at a pinned commit.
set -euo pipefail

WEASYPRINT_VERSION=70.0
FONTS_COMMIT=b5efa9c32e8f9b63005f5cdb1ad5527a77d2cd04   # google/fonts
FONTS_BASE="https://raw.githubusercontent.com/google/fonts/${FONTS_COMMIT}/ofl"

sudo apt-get update -qq
sudo apt-get install -y -qq pandoc fontconfig >/dev/null

python3 -m venv "$HOME/.venv-pdf"
"$HOME/.venv-pdf/bin/pip" install -q "weasyprint==${WEASYPRINT_VERSION}"
echo "$HOME/.venv-pdf/bin" >> "${GITHUB_PATH:-/dev/null}"

dest="$HOME/.local/share/fonts"
mkdir -p "$dest"
for w in Regular Italic Medium MediumItalic SemiBold SemiBoldItalic Bold BoldItalic; do
  curl -fsSL -o "$dest/BeVietnamPro-$w.ttf" "$FONTS_BASE/bevietnampro/BeVietnamPro-$w.ttf"
done
curl -fsSL -o "$dest/JetBrainsMono[wght].ttf" "$FONTS_BASE/jetbrainsmono/JetBrainsMono%5Bwght%5D.ttf"
curl -fsSL -o "$dest/JetBrainsMono-Italic[wght].ttf" "$FONTS_BASE/jetbrainsmono/JetBrainsMono-Italic%5Bwght%5D.ttf"
fc-cache -f >/dev/null
fc-match "Be Vietnam Pro" | grep -q BeVietnamPro || { echo "Be Vietnam Pro not found by fontconfig"; exit 1; }
fc-match "JetBrains Mono" | grep -q JetBrainsMono || { echo "JetBrains Mono not found by fontconfig"; exit 1; }
pandoc --version | head -1
"$HOME/.venv-pdf/bin/weasyprint" --version
