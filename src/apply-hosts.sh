#!/usr/bin/env bash
# Query public DNS for the fastest IPs and manage a marked block in the system hosts file.
# Works on Linux/macOS and Git Bash on Windows (Python handles platform-specific paths).
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SRC_DIR}/.." && pwd)"

python_has_dns() {
  "${1}" -c "import dns" >/dev/null 2>&1
}

find_python() {
  local candidates=()

  if [[ -n "${CONDA_PREFIX:-}" ]]; then
    if [[ -x "${CONDA_PREFIX}/python.exe" ]]; then
      candidates+=("${CONDA_PREFIX}/python.exe")
    fi
    if [[ -x "${CONDA_PREFIX}/bin/python" ]]; then
      candidates+=("${CONDA_PREFIX}/bin/python")
    fi
  fi

  if [[ -d "${HOME}/miniconda3/envs" ]]; then
    local env_py
    for env_py in "${HOME}/miniconda3/envs/"*/python.exe; do
      [[ -x "${env_py}" ]] && candidates+=("${env_py}")
    done
  fi
  if [[ -d "${HOME}/anaconda3/envs" ]]; then
    local env_py
    for env_py in "${HOME}/anaconda3/envs/"*/python.exe; do
      [[ -x "${env_py}" ]] && candidates+=("${env_py}")
    done
  fi

  if [[ -x "${ROOT}/.venv/bin/python" ]]; then
    candidates+=("${ROOT}/.venv/bin/python")
  fi
  if [[ -x "${ROOT}/.venv/Scripts/python.exe" ]]; then
    candidates+=("${ROOT}/.venv/Scripts/python.exe")
  fi
  if command -v python3 >/dev/null 2>&1; then
    candidates+=("python3")
  fi
  if command -v python >/dev/null 2>&1; then
    candidates+=("python")
  fi

  local py
  for py in "${candidates[@]}"; do
    if python_has_dns "${py}"; then
      echo "${py}"
      return 0
    fi
  done

  return 1
}

PYTHON="$(find_python || true)"
if [[ -z "${PYTHON}" ]]; then
  echo "no usable Python found (need dnspython); install with: pip install -r requirements.txt" >&2
  exit 1
fi

cd "${ROOT}"
exec "${PYTHON}" -m src.apply "$@"
