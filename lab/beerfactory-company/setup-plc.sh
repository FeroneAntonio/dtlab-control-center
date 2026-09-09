#!/bin/bash
# ============================================================
#  Setup VM PLC - Ambiente OT BeerFactory (Python 2.7)
#  RICHIEDE Ubuntu 20.04 (Python 2 NON disponibile su 26.04)
#  Eseguire dalla cartella che contiene requirements-plc.txt
# ============================================================
set -e

echo "[1/5] Pacchetti di sistema..."
sudo apt update
sudo apt install -y python2 python2-dev \
    libsdl1.2debian libsdl-image1.2 libsdl-mixer1.2 libsdl-ttf2.0-0 \
    libsmpeg0 libportmidi0 libfreetype6 \
    net-tools curl xvfb x11vnc x11-utils git websockify

echo "[2/5] Installazione pip per Python 2..."
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py -o /tmp/get-pip.py
sudo python2 /tmp/get-pip.py

echo "[3/5] Librerie Python (requirements-plc.txt)..."
sudo python2 -m pip install -r requirements-plc.txt

echo "[4/5] Installazione noVNC..."
if [ ! -d /opt/novnc ]; then
    sudo git clone --branch v1.3.0 https://github.com/novnc/noVNC /opt/novnc
    sudo ln -sf /opt/novnc/vnc.html /opt/novnc/index.html
fi

echo "[5/5] Verifica..."
python2 --version
python2 -m pip list 2>/dev/null | grep -iE 'pymodbus|pygame|pymunk|twisted' || true

echo ""
echo "=== Setup PLC completato ==="
echo "Ricorda: copiare world.py e Factory_bkg.png nella cartella di lavoro"
echo "e lanciare avvia_plc.sh per avviare il PLC (browser su :6080)."