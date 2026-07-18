#!/usr/bin/env bash
# Optional: slow down password guessing against the OSCAR ports.
#
# open-oscar-server does not throttle failed logins, and it logs them only at
# debug level — so fail2ban would mean running the whole server verbosely. This
# limits new connections per source IP at the firewall instead, which needs no
# logs and costs nothing in normal use.
#
# Limits: 30 new connections per minute per IP, burst of 40.
#
# Only NEW connections count. OSCAR is persistent — messages, presence, profiles
# and buddy icons all ride an already-open socket — so a session costs about two
# connections to sign on, plus one for the chat service and one per room joined.
# A busy user might spend 6-8; a password guesser needs thousands, so this is
# just as useless to them as a tighter limit while leaving real headroom.
#
# Note the budget is per SOURCE IP, so several accounts behind one address share
# it, and a blocked connection TIMES OUT rather than being refused — it looks
# like the server hanging, not like a rate limit.

set -euo pipefail

TLS_PORT="${TLS_PORT:-5191}"
OSCAR_PORT="${OSCAR_PORT:-5190}"

[ "$(id -u)" -eq 0 ] || { echo "Run with sudo: sudo ./ratelimit.sh" >&2; exit 1; }
command -v iptables >/dev/null 2>&1 || { echo "iptables not found." >&2; exit 1; }

for PORT in "$TLS_PORT" "$OSCAR_PORT"; do
  CHAIN="OSCAR_RL_$PORT"
  iptables -N "$CHAIN" 2>/dev/null || iptables -F "$CHAIN"
  iptables -A "$CHAIN" -m limit --limit 30/minute --limit-burst 40 -j RETURN
  iptables -A "$CHAIN" -j DROP
  iptables -C INPUT -p tcp --dport "$PORT" --syn -j "$CHAIN" 2>/dev/null \
    || iptables -I INPUT -p tcp --dport "$PORT" --syn -j "$CHAIN"
  echo "rate limit applied to port $PORT"
done

if command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save >/dev/null 2>&1 || true
elif [ -d /etc/iptables ]; then
  iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
else
  echo "NOTE: rules are not persisted across reboot. Save with:"
  echo "  iptables-save > /etc/iptables/rules.v4"
fi
echo "Done. Undo with: sudo ./uninstall.sh --ratelimit-only"
