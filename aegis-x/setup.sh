#!/usr/bin/env bash
#
# Aegis-X — Download Inspection Engine
# Setup script for REMnux (Ubuntu Linux x86_64)
#
# What this does:
#   1. Installs required system packages via apt (libmagic, python3-venv,
#      python3-tk for the optional desktop popup, build tools for pefile).
#   2. Creates a Python virtual environment in backend/venv.
#   3. Installs Python dependencies from requirements.txt.
#   4. Copies .env.example -> .env if one doesn't already exist.
#   5. Creates the data/ and logs/ directories used by the app.
#
# Usage:
#   cd aegis-x
#   chmod +x setup.sh
#   ./setup.sh
#
# After setup:
#   source backend/venv/bin/activate
#   cd backend
#   python -m app.main                 # start the watcher (+ popup if a display is available)
#   python -m app.api.server           # start the dashboard/API (separate terminal)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="${SCRIPT_DIR}/backend"

echo "== Aegis-X setup (REMnux / Ubuntu Linux x86_64) =="

if [ ! -d "${BACKEND_DIR}" ]; then
    echo "ERROR: expected a 'backend' directory next to this script at ${BACKEND_DIR}" >&2
    exit 1
fi

# ---------------------------------------------------------------------
# 1. System packages
# ---------------------------------------------------------------------
if command -v apt-get >/dev/null 2>&1; then
    echo "-- Installing system packages via apt-get (sudo required) --"
    SUDO=""
    if [ "$(id -u)" -ne 0 ]; then
        SUDO="sudo"
    fi
    ${SUDO} apt-get update -y
    ${SUDO} apt-get install -y \
        python3 \
        python3-venv \
        python3-pip \
        python3-tk \
        libmagic1
else
    echo "WARNING: apt-get not found. Skipping system package install." >&2
    echo "         Ensure python3, python3-venv, python3-tk, and libmagic1" >&2
    echo "         (or your distro's equivalents) are installed manually." >&2
fi

# ---------------------------------------------------------------------
# 2. Virtual environment
# ---------------------------------------------------------------------
echo "-- Creating Python virtual environment --"
python3 -m venv "${BACKEND_DIR}/venv"
# shellcheck disable=SC1091
source "${BACKEND_DIR}/venv/bin/activate"
python -m pip install --upgrade pip

# ---------------------------------------------------------------------
# 3. Python dependencies
# ---------------------------------------------------------------------
echo "-- Installing Python dependencies --"
pip install -r "${BACKEND_DIR}/requirements.txt"

# ---------------------------------------------------------------------
# 4. .env
# ---------------------------------------------------------------------
if [ ! -f "${BACKEND_DIR}/.env" ]; then
    echo "-- Creating backend/.env from .env.example --"
    cp "${BACKEND_DIR}/.env.example" "${BACKEND_DIR}/.env"
    echo "   Edit backend/.env to set CHROME_DOWNLOAD_PATH and (optionally) AI_PROVIDER."
else
    echo "-- backend/.env already exists; leaving it untouched --"
fi

# ---------------------------------------------------------------------
# 5. Data/log directories
# ---------------------------------------------------------------------
mkdir -p "${BACKEND_DIR}/data" "${BACKEND_DIR}/logs"

echo ""
echo "== Setup complete =="
echo ""
echo "Next steps:"
echo "  1. Edit backend/.env — set CHROME_DOWNLOAD_PATH to a real Downloads"
echo "     folder on this REMnux VM, e.g. /home/remnux/Downloads"
echo "  2. source backend/venv/bin/activate"
echo "  3. cd backend"
echo "  4. python -m app.main            # start the watcher"
echo "  5. python -m app.api.server      # (separate terminal) dashboard + API"
echo ""
echo "Dashboard:  http://127.0.0.1:8000/            (open in Firefox inside the VM)"
echo "JSON API:   curl http://127.0.0.1:8000/reports"
echo ""
echo "To expose the dashboard to the VirtualBox host or other machines,"
echo "set API_HOST=0.0.0.0 in backend/.env before starting app.api.server,"
echo "and set up a VirtualBox port-forward / host-only adapter as needed."
