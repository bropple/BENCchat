#!/usr/bin/env bash
# Removes everything install.sh / ratelimit.sh added. open-oscar-server is
# untouched throughout, so this cannot affect it.
set -euo pipefail

TLS_PORT="${TLS_PORT:-5191}"
OSCAR_PORT="${OSCAR_PORT:-5190}"
[ "$(id -u)" -eq 0 ] || { echo "Run with sudo: sudo ./uninstall.sh" >&2; exit 1; }

remove_ratelimit() {
  for PORT in "$TLS_PORT" "$OSCAR_PORT"; do
    CHAIN="OSCAR_RL_$PORT"
    iptables -D INPUT -p tcp --dport "$PORT" --syn -j "$CHAIN" 2>/dev/null || true
    iptables -F "$CHAIN" 2>/dev/null || true
    iptables -X "$CHAIN" 2>/dev/null || true
  done
  echo "rate limits removed"
}

if [ "${1:-}" = "--ratelimit-only" ]; then
  remove_ratelimit
  exit 0
fi

systemctl stop benchat-tls 2>/dev/null || true
systemctl disable benchat-tls 2>/dev/null || true
rm -f /etc/systemd/system/benchat-tls.service
systemctl daemon-reload
rm -f /etc/letsencrypt/renewal-hooks/deploy/benchat-tls.sh
remove_ratelimit

echo
echo "stunnel service removed. Left in place on purpose:"
echo "  /etc/benchat-tls/        (certificate + config)"
echo "  any Let's Encrypt certs  (remove with: certbot delete)"
echo "  the firewall ACCEPT rule for $TLS_PORT"
echo
echo "open-oscar-server was never modified and is still serving $OSCAR_PORT."
