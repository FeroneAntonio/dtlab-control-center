#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Eseguire come root." >&2
  exit 1
fi

bootstrap_dir=${1:-/home/websiteubuntu/dtlab-bootstrap}
app_user=websiteubuntu
app_group=websiteubuntu
app_root=/opt/dtlab-control-center
data_root=/var/lib/dtlab-control-center
config_root=/etc/dtlab-control-center
release_id=$(date -u +%Y%m%dT%H%M%SZ)
release_root=${app_root}/releases/${release_id}
venv_root=${app_root}/venvs/${release_id}

required=(
  release.tar.gz
  release.tar.gz.sha256
  store.tar.gz
  tickets.sqlite3
  host-ot-state.tar.gz
  dtlab.local.toml
  credentials.json
)
for name in "${required[@]}"; do
  if [[ ! -f ${bootstrap_dir}/${name} ]]; then
    echo "File bootstrap mancante: ${name}" >&2
    exit 1
  fi
done

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl nginx
if ! command -v uv >/dev/null 2>&1; then
  uv_installer=$(mktemp /var/tmp/dtlab-uv-install.XXXXXX.sh)
  curl --fail --silent --show-error --location https://astral.sh/uv/install.sh \
    --output "${uv_installer}"
  env UV_INSTALL_DIR=/usr/local/bin sh "${uv_installer}"
  case "${uv_installer}" in
    /var/tmp/dtlab-uv-install.*.sh) rm -f -- "${uv_installer}" ;;
    *) echo "Percorso installer uv inatteso; pulizia rifiutata." >&2 ;;
  esac
fi
export UV_PYTHON_INSTALL_DIR=${app_root}/python
uv python install 3.12

install -d -m 0755 "${app_root}/releases" "${app_root}/venvs"
install -d -m 0750 -o "${app_user}" -g "${app_group}" \
  "${data_root}/store" "${data_root}/raw" "${data_root}/tickets" \
  "${data_root}/host-ot"
install -d -m 0750 -o root -g "${app_group}" "${config_root}"

expected_checksum=$(awk '{print $1}' "${bootstrap_dir}/release.tar.gz.sha256")
actual_checksum=$(sha256sum "${bootstrap_dir}/release.tar.gz" | awk '{print $1}')
if [[ ${expected_checksum} != "${actual_checksum}" ]]; then
  echo "Checksum release non valido." >&2
  exit 1
fi

install -d -m 0755 "${release_root}"
tar -xzf "${bootstrap_dir}/release.tar.gz" -C "${release_root}" --strip-components=1
uv venv --python 3.12 "${venv_root}"
uv pip install --python "${venv_root}/bin/python" -r "${release_root}/requirements.txt"
chmod -R a+rX "${app_root}/python" "${venv_root}"

tar -xzf "${bootstrap_dir}/store.tar.gz" -C "${data_root}"
if [[ -f ${data_root}/store/store/current/manifest.json ]]; then
  mv "${data_root}/store/store"/* "${data_root}/store/"
  rmdir "${data_root}/store/store"
fi
install -m 0600 -o "${app_user}" -g "${app_group}" \
  "${bootstrap_dir}/tickets.sqlite3" "${data_root}/tickets/tickets.sqlite3"

host_tmp=$(mktemp -d /var/tmp/dtlab-host-state.XXXXXX)
cleanup_host_tmp() {
  case "${host_tmp}" in
    /var/tmp/dtlab-host-state.*) rm -rf -- "${host_tmp}" ;;
    *) echo "Percorso temporaneo inatteso; pulizia rifiutata." >&2 ;;
  esac
}
trap cleanup_host_tmp EXIT
tar -xzf "${bootstrap_dir}/host-ot-state.tar.gz" -C "${host_tmp}"
cp -a "${host_tmp}/modbus-dashboard-host-ot-data/." "${data_root}/host-ot/"
install -m 0640 -o root -g "${app_group}" \
  "${host_tmp}/modbus-dashboard-host-ot-secrets/keyring.json" \
  "${config_root}/host-ot-keyring.json"
install -m 0640 -o root -g "${app_group}" \
  "${bootstrap_dir}/credentials.json" "${config_root}/credentials.json"
install -m 0640 -o root -g "${app_group}" \
  "${bootstrap_dir}/dtlab.local.toml" "${config_root}/dtlab.local.toml"
sed -i 's|^local_store = .*|local_store = "/var/lib/dtlab-control-center/store"|' \
  "${config_root}/dtlab.local.toml"
sed -i 's|^raw_directory = .*|raw_directory = "/var/lib/dtlab-control-center/raw"|' \
  "${config_root}/dtlab.local.toml"
sed -i 's|^enabled = true$|enabled = false|' "${config_root}/dtlab.local.toml"

chown -R "${app_user}:${app_group}" "${data_root}"
find "${data_root}" -type d -exec chmod 0750 {} +
find "${data_root}" -type f -exec chmod 0640 {} +
chmod 0600 "${data_root}/tickets/tickets.sqlite3"
ln -sfn "${release_root}" "${app_root}/current"
ln -sfn "${venv_root}" "${app_root}/venv-current"

cat >/etc/systemd/system/dtlab-dashboard.service <<'EOF'
[Unit]
Description=DTLab Control Center local dashboard
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=websiteubuntu
Group=websiteubuntu
WorkingDirectory=/opt/dtlab-control-center/current
Environment=PYTHONPATH=/opt/dtlab-control-center/current/src
Environment=DTLAB_SNAPSHOT_STORE=/var/lib/dtlab-control-center/store
Environment=DTLAB_TICKET_STORE=/var/lib/dtlab-control-center/tickets/tickets.sqlite3
Environment=DTLAB_HOST_OT_EVENT_STORE=/var/lib/dtlab-control-center/host-ot
Environment=DTLAB_UI_REFRESH_SECONDS=3
Environment=STREAMLIT_BROWSER_GATHER_USAGE_STATS=false
ExecStart=/opt/dtlab-control-center/venv-current/bin/python -m streamlit run app.py --server.address=127.0.0.1 --server.port=8517 --server.headless=true
Restart=on-failure
RestartSec=3
UMask=0027
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/dtlab-host-ot-ingress.service <<'EOF'
[Unit]
Description=DTLab authenticated host OT event ingress
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=websiteubuntu
Group=websiteubuntu
WorkingDirectory=/opt/dtlab-control-center/current
Environment=PYTHONPATH=/opt/dtlab-control-center/current/src
Environment=DTLAB_TICKET_STORE=/var/lib/dtlab-control-center/tickets/tickets.sqlite3
Environment=DTLAB_HOST_OT_EVENT_STORE=/var/lib/dtlab-control-center/host-ot
Environment=DTLAB_HOST_OT_KEY_FILE=/etc/dtlab-control-center/host-ot-keyring.json
Environment=DTLAB_HOST_OT_BIND=127.0.0.1
Environment=DTLAB_HOST_OT_PORT=8520
ExecStart=/opt/dtlab-control-center/venv-current/bin/python -m dtlab.services.host_ot_ingress
Restart=on-failure
RestartSec=3
UMask=0027
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

cat >/etc/systemd/system/dtlab-collector.service <<'EOF'
[Unit]
Description=DTLab direct ESXi and Cyber Vision collection
After=network-online.target dtlab-host-ot-ingress.service
Wants=network-online.target

[Service]
Type=oneshot
User=websiteubuntu
Group=websiteubuntu
WorkingDirectory=/opt/dtlab-control-center/current
Environment=PYTHONPATH=/opt/dtlab-control-center/current/src
Environment=DTLAB_CREDENTIAL_FILE=/etc/dtlab-control-center/credentials.json
Environment=DTLAB_SNAPSHOT_STORE=/var/lib/dtlab-control-center/store
Environment=DTLAB_TICKET_STORE=/var/lib/dtlab-control-center/tickets/tickets.sqlite3
ExecStart=/opt/dtlab-control-center/venv-current/bin/python -m dtlab.collector.sync --config /etc/dtlab-control-center/dtlab.local.toml --local-only --skip-vpn-check --snapshot-retention 240
ExecStart=/opt/dtlab-control-center/venv-current/bin/python -m dtlab.services.ticket_ingest_worker
ExecStartPost=/opt/dtlab-control-center/venv-current/bin/python /opt/dtlab-control-center/current/tools/prune_raw_snapshots.py --root /var/lib/dtlab-control-center/raw --retain 100
UMask=0027
NoNewPrivileges=true
PrivateTmp=true
EOF

cat >/etc/systemd/system/dtlab-collector.timer <<'EOF'
[Unit]
Description=Run DTLab collection every 30 seconds

[Timer]
OnBootSec=20s
OnUnitInactiveSec=30s
AccuracySec=1s
Persistent=true

[Install]
WantedBy=timers.target
EOF

cat >/etc/nginx/sites-available/dtlab-control-center <<'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    client_max_body_size 32m;

    location = /api/host-ot/v1/events {
        proxy_pass http://127.0.0.1:8520/v1/events;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /_stcore/stream {
        proxy_pass http://127.0.0.1:8517/_stcore/stream;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 600s;
    }

    location / {
        proxy_pass http://127.0.0.1:8517;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 600s;
    }
}
EOF

rm -f /etc/nginx/sites-enabled/default
ln -sfn /etc/nginx/sites-available/dtlab-control-center \
  /etc/nginx/sites-enabled/dtlab-control-center
nginx -t
systemctl daemon-reload
systemctl enable --now dtlab-dashboard.service dtlab-host-ot-ingress.service
systemctl enable --now dtlab-collector.timer
systemctl enable --now nginx
systemctl start dtlab-collector.service

curl --fail --silent --show-error http://127.0.0.1:8517/_stcore/health
curl --fail --silent --show-error http://127.0.0.1:8520/health
echo "DTLab Control Center locale installato: release ${release_id}."
