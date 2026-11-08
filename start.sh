#!/usr/bin/env bash
# Start the local prototype on macOS / Linux / WSL.
set -euo pipefail
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  PYTHON=python
fi

if [ ! -d ".venv" ]; then
  echo "Creating virtual environment in .venv ..."
  "$PYTHON" -m venv .venv
fi

# shellcheck disable=SC1091
. .venv/bin/activate
python -m pip install --disable-pip-version-check -q -r requirements.txt
exec python run.py "$@"
