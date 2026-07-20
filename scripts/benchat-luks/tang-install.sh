#!/usr/bin/env bash
# tang-install.sh — set up a Tang server on the KEY host.
#
# Run this on the machine that will hold the key material: a Pi, a home server,
# a second small VPS. NOT on the BENCoscar host — a key and the lock it opens in
# the same disk snapshot protects nothing. See README.md, "Where to run Tang".
#
# Tang never learns the volume key. It publishes a public advertisement and
# performs one half of a key exchange; the client's own secret never traverses
# the network. That is why this listener needs no TLS and no authentication —
# but it does need to be reachable ONLY by the machines you intend to unlock,
# because anyone who can reach it can complete an unlock they already hold a
# bound volume for.
#
#   sudo ./tang-install.sh
#   sudo ./tang-install.sh --port 7500
#   sudo ./tang-install.sh --dry-run
#
#   --port N     listen port (default 7500 — Tang's own default is 80, which
#                collides with anything else on the host)
#   --dry-run    show what would happen, change nothing
#   --yes, -y    skip the confirmation
#
# Safe to re-run: it will not regenerate keys that already exist. Rotating keys
# is a deliberate, separate act — see README.md, "Revoking".

set -euo pipefail

PORT="${PORT:-7500}"
DRY_RUN=0
ASSUME_YES=0

say()  { printf '\n\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\n\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
run()  { if [ "$DRY_RUN" -eq 1 ]; then printf '    [dry run] %s\n' "$*"; else "$@"; fi; }

while [ $# -gt 0 ]; do
  case "$1" in
    --port)    shift; PORT="${1:-}"; [ -n "$PORT" ] || die "--port needs a number" ;;
    --dry-run) DRY_RUN=1 ;;
    --yes|-y)  ASSUME_YES=1 ;;
    -h|--help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)         die "unknown option: $1  (try --help)" ;;
  esac
  shift
done

[ "$(id -u)" -eq 0 ] || die "Run this with sudo:  sudo ./tang-install.sh"

case "$PORT" in
  ''|*[!0-9]*) die "--port must be a number, got: $PORT" ;;
esac

KEYDIR=/var/db/tang

say "Tang key server setup"
echo "    listen port : $PORT"
echo "    key dir     : $KEYDIR"
echo
echo "    This host becomes the thing that can revoke access to every volume"
echo "    bound to it. Treat its backups accordingly."

if [ "$DRY_RUN" -eq 0 ] && [ "$ASSUME_YES" -ne 1 ]; then
  echo
  printf 'Proceed? [y/N] '
  read -r reply
  case "$reply" in y|Y|yes|YES) ;; *) die "cancelled" ;; esac
fi

# --- 1. Install ------------------------------------------------------------
if command -v tangd >/dev/null 2>&1 || [ -x /usr/lib/tangd ] || [ -x /usr/libexec/tangd ]; then
  say "tang already installed"
elif command -v apt-get >/dev/null 2>&1; then
  say "Installing tang (apt)"
  run apt-get update -qq
  run env DEBIAN_FRONTEND=noninteractive apt-get install -y tang jose
elif command -v dnf >/dev/null 2>&1; then
  say "Installing tang (dnf)"
  run dnf install -y tang jose
elif command -v yum >/dev/null 2>&1; then
  say "Installing tang (yum)"
  run yum install -y tang jose
else
  die "No apt/dnf/yum found — install the 'tang' package manually, then re-run."
fi

# --- 2. Listen on a non-default port ---------------------------------------
# tangd.socket ships with ListenStream=80. Overriding it in a drop-in leaves the
# packaged unit alone, so a package upgrade cannot quietly move the port back.
# The empty ListenStream= first is required: socket options accumulate across
# drop-ins, and without it the socket would listen on BOTH 80 and $PORT.
say "Pointing tangd.socket at port $PORT"
run mkdir -p /etc/systemd/system/tangd.socket.d
if [ "$DRY_RUN" -eq 1 ]; then
  printf '    [dry run] write /etc/systemd/system/tangd.socket.d/10-port.conf\n'
else
  cat > /etc/systemd/system/tangd.socket.d/10-port.conf <<EOF
[Socket]
ListenStream=
ListenStream=$PORT
EOF
fi

run systemctl daemon-reload
run systemctl enable tangd.socket
run systemctl restart tangd.socket

if [ "$DRY_RUN" -eq 0 ]; then
  sleep 1
  if ! systemctl is-active --quiet tangd.socket; then
    warn "tangd.socket did not start. Recent log:"
    journalctl -u tangd.socket -n 20 --no-pager || true
    die "Fix the above, then re-run."
  fi
  say "tangd.socket is listening on $PORT"
fi

# --- 3. Keys ---------------------------------------------------------------
# Tang generates its signing/exchange keypair on first request if the key
# directory is empty. Forcing that here means the thumbprint can be shown now
# rather than after the first unlock attempt.
say "Checking for keys in $KEYDIR"
if [ "$DRY_RUN" -eq 1 ]; then
  echo "    [dry run] would fetch http://127.0.0.1:$PORT/adv to force key generation"
  echo "    [dry run] would print the key thumbprint"
else
  mkdir -p "$KEYDIR"
  if ! ls "$KEYDIR"/*.jwk >/dev/null 2>&1; then
    echo "    no keys yet — generating by requesting the advertisement"
    curl -fsS "http://127.0.0.1:$PORT/adv" >/dev/null 2>&1 || true
    sleep 1
  fi
  ls "$KEYDIR"/*.jwk >/dev/null 2>&1 || die "Tang did not generate keys in $KEYDIR.
     Check:  journalctl -u tangd.socket -u 'tangd@*' -n 50"

  echo "    keys present:"
  for k in "$KEYDIR"/*.jwk; do echo "      $(basename "$k")"; done

  THP=""
  if command -v jose >/dev/null 2>&1 && command -v curl >/dev/null 2>&1; then
    # The thumbprint of the SIGNING key is what clevis shows you at bind time.
    # Deriving it the same way clevis does avoids reporting a key that is
    # present on disk but not actually being advertised.
    THP="$(curl -fsS "http://127.0.0.1:$PORT/adv" 2>/dev/null \
            | jose fmt -j- -Og payload -Sy -Og keys -Af- 2>/dev/null \
            | jose jwk thp -i- 2>/dev/null | head -n1 || true)"
  fi
fi

# --- 4. Firewall guidance --------------------------------------------------
HOSTIP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"

cat <<EOF

================================================================
 Tang is up on port $PORT.

EOF

if [ "$DRY_RUN" -eq 0 ]; then
  if [ -n "${THP:-}" ]; then
    cat <<EOF
 Key thumbprint:

     $THP

 Write this down. bind-volume.sh will show you a thumbprint before it
 trusts this server; if the two do not match, something is answering
 that is not this host and you should stop.
EOF
  else
    cat <<'EOF'
 Could not compute the thumbprint here (needs the "jose" and "curl"
 tools). Get it with:

     curl -s http://127.0.0.1:PORT/adv \
       | jose fmt -j- -Og payload -Sy -Og keys -Af- \
       | jose jwk thp -i-
EOF
  fi
fi

cat <<EOF

 FIREWALL — do this next, it is the whole security boundary:

   Tang has no authentication. Anyone who can reach this port and who
   already holds a bound volume can unlock it. Restrict it to the
   BENCoscar host's address and nothing else.

   nftables / iptables:
     iptables -A INPUT -p tcp --dport $PORT -s <BENCOSCAR_IP> -j ACCEPT
     iptables -A INPUT -p tcp --dport $PORT -j DROP

   ufw:
     ufw allow from <BENCOSCAR_IP> to any port $PORT proto tcp
     ufw deny $PORT/tcp

   firewalld:
     firewall-cmd --permanent --add-rich-rule \\
       'rule family=ipv4 source address=<BENCOSCAR_IP> port port=$PORT protocol=tcp accept'
     firewall-cmd --reload

   If this host is behind your home router, do NOT port-forward $PORT to
   the internet. Use a VPN or Tailscale tunnel that the BENCoscar host
   dials out over, and read the credential caveat in README.md before
   deciding that is good enough.

 Reachable at (from the BENCoscar host's point of view):
     http://${HOSTIP:-<this-host>}:$PORT

 Confirm from the BENCoscar host before running bind-volume.sh:
     curl -fsS http://${HOSTIP:-<this-host>}:$PORT/adv | head -c 80; echo

 Back up $KEYDIR somewhere offline. Losing it means every volume bound
 to this server stops unlocking — which is exactly the revocation
 property, and exactly the disaster if it happens by accident.
================================================================
EOF
