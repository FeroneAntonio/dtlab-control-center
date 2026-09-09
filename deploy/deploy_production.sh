#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: deploy_production.sh {promote|rollback} [arguments]" >&2
  exit 2
fi

action="$1"
shift
case "${action}" in
  promote|rollback) ;;
  *)
    echo "deploy_production.sh accepts only promote or rollback" >&2
    exit 2
    ;;
esac

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 -B "${script_dir}/production_tool.py" "${action}" "$@"
