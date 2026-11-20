#!/bin/bash
set -euo pipefail
# Run from the unpacked application directory as root, after provisioning runtime and environment.
test "$(id -u)" = 0
test -x /opt/sbc-console-runtime/python/bin/python3
test -f /etc/sbc-console/environment
id sbc-console >/dev/null 2>&1 || useradd --system --home-dir /var/lib/sbc-console --shell /sbin/nologin sbc-console
install -d -m 755 /opt/sbc-console /opt/sbc-console/static
install -d -m 700 -o sbc-console -g sbc-console /var/lib/sbc-console
install -d -m 750 -o root -g sbc-console /etc/sbc-console
install -m 644 server.py rest_activity.py trace_tools.py snmp_tools.py snmp_catalog.json trap_tools.py trap_catalog.json cdr_tools.py cdr_catalog.json recordings_tools.py recordings_supervisor.py transcription_worker.py /opt/sbc-console/
install -m 644 static/index.html static/app.js static/rest-activity.js static/lrt.js static/diagnostics.js static/diagnostic-charts.js static/traces.js static/snmp.js static/traps.js static/cdr.js static/recordings.js static/style.css /opt/sbc-console/static/
if [ ! -f /etc/sbc-console/tls.key ]; then
  openssl req -x509 -nodes -newkey rsa:3072 -sha256 -days 365 \
    -keyout /etc/sbc-console/tls.key -out /etc/sbc-console/tls.crt \
    -subj '/CN=192.168.226.190' \
    -extensions v3_req -config <(cat /etc/pki/tls/openssl.cnf; printf '\n[v3_req]\nsubjectAltName=IP:192.168.226.190,DNS:sbc-console\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
fi

if [ -x /opt/sbc-transcription/venv/bin/python ] && [ -f /opt/sbc-transcription/model/model.bin ]; then
  install -m 644 sbc-transcription.service /etc/systemd/system/sbc-transcription.service
  restorecon /etc/systemd/system/sbc-transcription.service || true
  systemctl daemon-reload
  systemctl enable --now sbc-transcription.service
fi
chown root:sbc-console /etc/sbc-console/tls.key /etc/sbc-console/tls.crt
chmod 640 /etc/sbc-console/tls.key /etc/sbc-console/tls.crt
chmod 600 /etc/sbc-console/environment
install -m 644 sbc-console.service /etc/systemd/system/sbc-console.service
restorecon -R /opt/sbc-console /opt/sbc-console-runtime /etc/sbc-console /var/lib/sbc-console /etc/systemd/system/sbc-console.service || true
install -m 644 sbc-traps.service sbc-traps.socket /etc/systemd/system/
restorecon /etc/systemd/system/sbc-traps.service /etc/systemd/system/sbc-traps.socket || true
systemctl daemon-reload
systemctl enable --now sbc-traps.socket sbc-traps.service
systemctl enable sbc-console
systemctl restart sbc-console
if systemctl is-active --quiet firewalld; then
  firewall-cmd --permanent --add-port=8443/tcp
  firewall-cmd --add-port=8443/tcp
fi
systemctl --no-pager status sbc-console

if [ -x /opt/siprec-runtime/siprec ] && [ -f /etc/sbc-console/siprec.env ]; then
  install -d -m 700 -o sbc-console -g sbc-console /var/lib/sbc-console/recordings
  install -m 644 siprec-recorder.service /etc/systemd/system/siprec-recorder.service
  restorecon /etc/systemd/system/siprec-recorder.service || true
  systemctl daemon-reload
  systemctl enable --now siprec-recorder.service
fi
