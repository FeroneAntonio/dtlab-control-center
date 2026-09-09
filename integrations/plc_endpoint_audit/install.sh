#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Eseguire come root in una change window approvata." >&2
  exit 2
fi

python2_bin="${DTLAB_PYTHON2_BIN:-/usr/bin/python2}"
if [[ ! -x "${python2_bin}" ]]; then
  echo "Python 2.7 non trovato in ${python2_bin}; installazione interrotta." >&2
  exit 2
fi

python2_site="$("${python2_bin}" -c \
  'from distutils.sysconfig import get_python_lib; print(get_python_lib())')"
if [[ -z "${python2_site}" || "${python2_site}" != /* ]]; then
  echo "Percorso site-packages Python 2.7 non valido: ${python2_site}" >&2
  exit 2
fi

source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
install_root="/opt/dtlab-plc-endpoint-audit"
config_root="/etc/dtlab"
state_root="/var/lib/dtlab-plc-audit"
key_path="${config_root}/plc-endpoint-audit.key"
config_path="${config_root}/plc-endpoint-audit.json"
python2_pth="${python2_site}/dtlab_plc_endpoint_audit.pth"

install -d -m 0755 \
  "${install_root}" \
  "${install_root}/dtlab_plc_audit" \
  "${install_root}/schemas"
install -d -m 0700 "${config_root}" "${state_root}"
install -m 0644 "${source_dir}"/dtlab_plc_audit/*.py "${install_root}/dtlab_plc_audit/"
install -m 0644 "${source_dir}"/schemas/*.json "${install_root}/schemas/"

PYTHONPATH="${install_root}" "${python2_bin}" -m py_compile \
  "${install_root}/dtlab_plc_audit/__init__.py" \
  "${install_root}/dtlab_plc_audit/core.py" \
  "${install_root}/dtlab_plc_audit/spool.py" \
  "${install_root}/dtlab_plc_audit/runtime.py" \
  "${install_root}/dtlab_plc_audit/audit_hook.py" \
  "${install_root}/dtlab_plc_audit/sender.py"
PYTHONPATH="${install_root}" "${python2_bin}" -c \
  'import pymodbus; assert pymodbus.__version__ == "2.5.3"; from dtlab_plc_audit.audit_hook import ModbusServerFactory; assert ModbusServerFactory is not None'

install -d -m 0755 "${python2_site}"
printf '%s\n' "${install_root}" > "${python2_pth}"
chmod 0644 "${python2_pth}"
env -u PYTHONPATH "${python2_bin}" -c \
  'from dtlab_plc_audit.audit_hook import StartAuditedTcpServer; assert StartAuditedTcpServer is not None'

if [[ ! -e "${key_path}" ]]; then
  umask 077
  openssl rand -hex 32 > "${key_path}"
fi
chmod 0600 "${key_path}"

if [[ ! -e "${config_path}" ]]; then
  install -m 0600 "${source_dir}/config.example.json" "${config_path}"
  echo "Creato ${config_path}: verificare endpoint, asset ID e IP prima dell'avvio."
fi

install -m 0644 \
  "${source_dir}/systemd/dtlab-plc-audit-sender.service" \
  "/etc/systemd/system/dtlab-plc-audit-sender.service"
systemctl daemon-reload

echo "Pacchetto installato ma NON avviato."
echo "Il programma PLC non è stato modificato o riavviato."
echo "Import Python 2.7 registrato in ${python2_pth}."
echo "Seguire README.md, registrare la chiave nel receiver e validare la configurazione."
