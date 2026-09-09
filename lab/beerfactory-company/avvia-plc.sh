#!/bin/bash
# ============================================================
#  Avvio PLC - BeerFactory
#  Sinottico accessibile via browser su http://<IP>:6080/vnc.html
#  Eseguire dalla cartella che contiene world.py e Factory_bkg.png
# ============================================================

# Pulizia istanze precedenti
sudo pkill -f "Xvfb :99"
pkill -f "x11vnc.*5900"
pkill -f "novnc_proxy.*6080"
sudo pkill -f "world.py"
pkill -f "matchbox.*:99"
sleep 1
rm -f /tmp/.X99-lock /tmp/.X11-unix/X99

# Cintura di sicurezza per sistemi con Wayland
unset WAYLAND_DISPLAY

# 1) Schermo virtuale X11 dedicato
Xvfb :99 -screen 0 1824x984x24 -ac +extension GLX +render -noreset &
export DISPLAY=:99
for i in $(seq 1 10); do
    xdpyinfo -display :99 >/dev/null 2>&1 && break
    sleep 1
done

# 2) Window manager (rendering corretto)
matchbox-window-manager -display :99 &
sleep 1

# 3) Server VNC sullo schermo :99
env -u WAYLAND_DISPLAY x11vnc -display :99 -forever -nopw -shared \
    -rfbport 5900 -xkb -noxrecord -noxfixes -noxdamage &
sleep 2

# 4) noVNC su browser (porta 6080)
/opt/novnc/utils/novnc_proxy --vnc localhost:5900 --listen 6080 &
sleep 2

# 5) Avvio del PLC (richiede root per la porta Modbus 502)
#    Lanciare lo script dalla cartella con world.py e Factory_bkg.png
exec sudo -E env DISPLAY=:99 python2 world.py