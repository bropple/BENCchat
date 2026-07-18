#!/usr/bin/env bash
# BENCchat TLS front-end installer.
#
# Puts stunnel in front of open-oscar-server so BENCchat can connect over TLS.
# It does NOT touch open-oscar-server: no config change, no restart. stunnel
# listens on a new port and forwards to the existing plaintext one on loopback.
#
# Safe to re-run: every step is idempotent.

set -euo pipefail

TLS_PORT="${TLS_PORT:-5191}"
OSCAR_PORT="${OSCAR_PORT:-5190}"
HOSTNAME_FQDN="${HOSTNAME_FQDN:-}"
CONF_DIR=/etc/benchat-tls

say()  { printf '\n\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\n\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run this with sudo:  sudo ./install.sh"
[ -n "$HOSTNAME_FQDN" ] || die "Set the hostname clients will connect to:
       sudo HOSTNAME_FQDN=chat.example.com ./install.sh
     It goes in the certificate, so it must match what clients dial."

say "BENCchat TLS setup"
echo "    server hostname : $HOSTNAME_FQDN"
echo "    TLS port (new)  : $TLS_PORT"
echo "    forwards to     : 127.0.0.1:$OSCAR_PORT  (your existing OSCAR server)"
echo
echo "    open-oscar-server is NOT modified and does NOT need restarting."

# --- 1. Install stunnel ----------------------------------------------------
if command -v stunnel >/dev/null 2>&1 || command -v stunnel4 >/dev/null 2>&1; then
  say "stunnel already installed"
elif command -v apt-get >/dev/null 2>&1; then
  say "Installing stunnel (apt)"
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y stunnel4 openssl
elif command -v dnf >/dev/null 2>&1; then
  say "Installing stunnel (dnf)"
  dnf install -y stunnel openssl
elif command -v yum >/dev/null 2>&1; then
  say "Installing stunnel (yum)"
  yum install -y stunnel openssl
else
  die "No apt/dnf/yum found — install stunnel manually, then re-run."
fi

STUNNEL_BIN="$(command -v stunnel || command -v stunnel4)"

# --- 2. Certificate --------------------------------------------------------
mkdir -p "$CONF_DIR"
chmod 700 "$CONF_DIR"

if [ -s "$CONF_DIR/server.pem" ] && [ -s "$CONF_DIR/server.key" ]; then
  say "Certificate already present in $CONF_DIR — leaving it alone"
else
  say "Generating a self-signed certificate (valid 2 years)"
  warn "Self-signed means BENCchat must run with 'Skip the certificate check' ON."
  warn "Run ./letsencrypt.sh afterwards for a real certificate and turn that off."
  openssl req -new -x509 -days 730 -nodes \
    -newkey rsa:2048 \
    -keyout "$CONF_DIR/server.key" \
    -out    "$CONF_DIR/server.pem" \
    -subj   "/CN=$HOSTNAME_FQDN" \
    -addext "subjectAltName=DNS:$HOSTNAME_FQDN" 2>/dev/null
  chmod 600 "$CONF_DIR/server.key" "$CONF_DIR/server.pem"
fi

# --- 3. stunnel config -----------------------------------------------------
say "Writing $CONF_DIR/stunnel.conf"
cat > "$CONF_DIR/stunnel.conf" <<EOF
; BENCchat TLS front-end for open-oscar-server.
; Terminates TLS on $TLS_PORT and forwards plaintext to the OSCAR server on
; loopback. The OSCAR server is untouched and keeps serving $OSCAR_PORT directly
; for legacy AIM clients.

foreground = yes
syslog = yes
debug = 4

[benchat-oscar]
accept  = 0.0.0.0:$TLS_PORT
connect = 127.0.0.1:$OSCAR_PORT
cert = $CONF_DIR/server.pem
key  = $CONF_DIR/server.key

; Modern TLS only. Legacy AIM 6.x SSL clients need a separate, old-OpenSSL
; stunnel — do not weaken this one to accommodate them.
sslVersionMin = TLSv1.2
ciphers = ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
options = NO_SSLv2
options = NO_SSLv3
options = NO_TLSv1
options = NO_TLSv1_1
EOF
chmod 600 "$CONF_DIR/stunnel.conf"

# --- 4. systemd service ----------------------------------------------------
say "Installing systemd service benchat-tls"
cat > /etc/systemd/system/benchat-tls.service <<EOF
[Unit]
Description=BENCchat TLS front-end (stunnel -> open-oscar-server)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$STUNNEL_BIN $CONF_DIR/stunnel.conf
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable benchat-tls >/dev/null 2>&1 || true
systemctl restart benchat-tls

sleep 1
if ! systemctl is-active --quiet benchat-tls; then
  warn "benchat-tls did not start. Recent log:"
  journalctl -u benchat-tls -n 20 --no-pager || true
  die "Fix the above, then re-run."
fi
say "stunnel is running"

# --- 5. Local firewall -----------------------------------------------------
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  say "Opening $TLS_PORT in firewalld"
  firewall-cmd --permanent --add-port="$TLS_PORT/tcp" >/dev/null
  firewall-cmd --reload >/dev/null
elif command -v ufw >/dev/null 2>&1 && ufw status | grep -qi active; then
  say "Opening $TLS_PORT in ufw"
  ufw allow "$TLS_PORT/tcp" >/dev/null
elif command -v iptables >/dev/null 2>&1; then
  say "Opening $TLS_PORT in iptables"
  iptables -C INPUT -p tcp --dport "$TLS_PORT" -j ACCEPT 2>/dev/null \
    || iptables -I INPUT -p tcp --dport "$TLS_PORT" -j ACCEPT
  if command -v netfilter-persistent >/dev/null 2>&1; then
    netfilter-persistent save >/dev/null 2>&1 || true
  elif [ -d /etc/iptables ]; then
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
  else
    warn "Could not persist the iptables rule — it will be lost on reboot."
    warn "Save it with:  iptables-save > /etc/iptables/rules.v4"
  fi
fi

# --- 6. Verify -------------------------------------------------------------
say "Checking the TLS listener"
if command -v openssl >/dev/null 2>&1; then
  if echo | timeout 10 openssl s_client -connect "127.0.0.1:$TLS_PORT" 2>/dev/null | grep -q "CONNECTED"; then
    echo "    TLS handshake on 127.0.0.1:$TLS_PORT: OK"
  else
    warn "Could not complete a local TLS handshake — check: journalctl -u benchat-tls"
  fi
fi

cat <<EOF

================================================================
 Done on this machine.

 ONE MORE STEP — Oracle Cloud blocks the port by default:

   Oracle Cloud console -> Networking -> Virtual Cloud Networks
     -> your VCN -> Security Lists -> Default Security List
     -> Add Ingress Rule:
          Source CIDR   : 0.0.0.0/0
          IP Protocol   : TCP
          Destination   : $TLS_PORT

 Then in BENCchat:
   Settings -> Privacy & Security -> Connection
     [x] Require an encrypted connection (TLS)
     [x] Skip the certificate check      <- needed for the self-signed cert
   Sign-on screen -> change the server to:  $HOSTNAME_FQDN:$TLS_PORT
   Sign off and back on.

 Then run ./letsencrypt.sh for a real certificate so you can turn
 "Skip the certificate check" back OFF.

 Useful:
   systemctl status benchat-tls
   journalctl -u benchat-tls -f
   sudo ./uninstall.sh        (removes everything this script added)
================================================================
EOF
