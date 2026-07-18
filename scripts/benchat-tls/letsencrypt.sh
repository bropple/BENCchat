#!/usr/bin/env bash
# Upgrade the BENCchat TLS front-end from a self-signed certificate to a real
# Let's Encrypt one, so BENCchat can verify it and you can turn OFF
# "Skip the certificate check".
#
# Uses DNS-01 via Cloudflare: no need to open port 80, and it renews unattended.
# You need a Cloudflare API token with Zone:DNS:Edit on the example.com zone.
#   Cloudflare dashboard -> My Profile -> API Tokens -> Create Token
#   -> "Edit zone DNS" template -> Zone Resources: Include -> example.com

set -euo pipefail

HOSTNAME_FQDN="${HOSTNAME_FQDN:-}"
CONF_DIR=/etc/benchat-tls
CF_INI=/root/.cloudflare.ini

say()  { printf '\n\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\n\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run this with sudo:  sudo ./letsencrypt.sh"
[ -n "$HOSTNAME_FQDN" ] || die "Set the hostname the certificate is for:
       sudo HOSTNAME_FQDN=chat.example.com ./letsencrypt.sh"

# --- certbot + the Cloudflare DNS plugin -----------------------------------
if ! command -v certbot >/dev/null 2>&1; then
  say "Installing certbot"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y certbot python3-certbot-dns-cloudflare
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y certbot python3-certbot-dns-cloudflare
  else
    die "Install certbot and the dns-cloudflare plugin manually, then re-run."
  fi
fi

# --- Cloudflare credentials -------------------------------------------------
if [ ! -s "$CF_INI" ]; then
  say "Cloudflare API token needed"
  echo "    Token needs: Zone -> DNS -> Edit, on the example.com zone."
  read -rsp "    Paste the token (input hidden): " CF_TOKEN
  echo
  [ -n "$CF_TOKEN" ] || die "No token entered."
  printf 'dns_cloudflare_api_token = %s\n' "$CF_TOKEN" > "$CF_INI"
  chmod 600 "$CF_INI"
  say "Saved to $CF_INI (root-only)"
else
  say "Using the existing token in $CF_INI"
fi

# --- Issue -----------------------------------------------------------------
say "Requesting a certificate for $HOSTNAME_FQDN"
certbot certonly \
  --dns-cloudflare \
  --dns-cloudflare-credentials "$CF_INI" \
  --dns-cloudflare-propagation-seconds 30 \
  -d "$HOSTNAME_FQDN" \
  --non-interactive --agree-tos --register-unsafely-without-email \
  --key-type rsa

LIVE="/etc/letsencrypt/live/$HOSTNAME_FQDN"
[ -s "$LIVE/fullchain.pem" ] || die "certbot did not produce $LIVE/fullchain.pem"

# --- Point stunnel at it ----------------------------------------------------
# A deploy hook copies the cert on every renewal; stunnel reads plain files and
# does not follow certbot's symlinks after a renewal otherwise.
say "Installing renewal hook"
mkdir -p /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/benchat-tls.sh <<EOF
#!/usr/bin/env bash
set -e
cp -L "$LIVE/fullchain.pem" "$CONF_DIR/server.pem"
cp -L "$LIVE/privkey.pem"   "$CONF_DIR/server.key"
chmod 600 "$CONF_DIR/server.pem" "$CONF_DIR/server.key"
systemctl restart benchat-tls
EOF
chmod +x /etc/letsencrypt/renewal-hooks/deploy/benchat-tls.sh

say "Installing the certificate and restarting stunnel"
/etc/letsencrypt/renewal-hooks/deploy/benchat-tls.sh

systemctl is-active --quiet benchat-tls || die "benchat-tls failed to restart — see: journalctl -u benchat-tls"

cat <<EOF

================================================================
 Real certificate installed and set to auto-renew.

 In BENCchat you can now turn OFF:
   Settings -> Privacy & Security -> [ ] Skip the certificate check

 Leave "Require an encrypted connection (TLS)" ON.

 Check renewal works (no changes made):
   sudo certbot renew --dry-run
================================================================
EOF
