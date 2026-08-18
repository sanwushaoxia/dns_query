#!/usr/bin/env bash
# Query public DNS for the fastest IPs and manage a marked block in /etc/hosts.
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SRC_DIR}/.." && pwd)"
PYTHON="${ROOT}/.venv/bin/python"

if [[ ! -x "${PYTHON}" ]]; then
  echo "missing ${PYTHON}; run: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt" >&2
  exit 1
fi

cd "${ROOT}"
exec "${PYTHON}" -m src.apply "$@"
