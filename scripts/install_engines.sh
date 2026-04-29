#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

echo "[1/5] Installing Python app dependencies"
python3 -m pip install --break-system-packages -r requirements.txt

echo "[2/5] Installing Python optional engines"
python3 -m pip install --break-system-packages --ignore-installed cryptography -r requirements-engines.txt
python3 -m pip install --break-system-packages -r requirements.txt

if command -v brew >/dev/null 2>&1; then
  echo "[3/5] Installing Homebrew engines"
  brew install nuclei katana ffuf semgrep gitleaks osv-scanner || true
  brew install --cask owasp-zap || true
else
  echo "[3/5] Homebrew not found, skipping Go/ZAP engines"
fi

if command -v npm >/dev/null 2>&1; then
  echo "[4/5] Installing Retire.js"
  npm install --prefix .tools retire || true
else
  echo "[4/5] npm not found, skipping Retire.js"
fi

echo "[5/5] Preparing engine data"
if command -v nuclei >/dev/null 2>&1; then
  nuclei -update-templates || true
fi
if command -v playwright >/dev/null 2>&1; then
  python3 -m playwright install chromium || true
fi

echo "Done. Run: python3 app.py"
