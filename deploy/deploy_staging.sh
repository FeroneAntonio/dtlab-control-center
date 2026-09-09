#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: deploy_staging.sh {install|rollback} [arguments]" >&2
  exit 2
fi

action="$1"
shift
case "${action}" in
  install|rollback) ;;
  *)
    echo "deploy_staging.sh accepts only install or rollback" >&2
    exit 2
    ;;
esac

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "${script_dir}/staging_tool.py" "${action}" "$@"
