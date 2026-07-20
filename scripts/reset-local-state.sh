#!/usr/bin/env bash
# Reset BENCchat to a blank slate — as if freshly installed.
#
# Clears everything the app remembers: the server address, the remembered screen
# name, the saved password, the encryption identity, remembered device keys,
# room keys and message history. Next launch shows the first-run sign-on screen
# with nothing filled in.
#
#   ./reset-local-state.sh                   # blank slate
#   ./reset-local-state.sh --keep-identity   # keep the encryption keypair
#   ./reset-local-state.sh --keep-history    # keep message history
#   ./reset-local-state.sh --keep-server     # keep the server address
#
#   --account NAME   act on one account only (default: all found)
#   --dry-run        show what would happen, change nothing
#   --yes            skip the confirmation
#
# RUN THIS FROM A DESKTOP TERMINAL, not over SSH. The password and encryption
# key live in the OS keyring, which is reachable only from a session that has
# one — over SSH there is nothing listening and they would silently survive.
#
# NOTHING IS DELETED. Files move to a timestamped backup directory and the
# restore command is printed. Keyring entries are the exception: those cannot be
# backed up, which is why --keep-identity exists.

set -euo pipefail

CONF_DIR="${BENCCHAT_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/BENCchat}"
KEYRING_SERVICE=BENCchat

KEEP_IDENTITY=0
KEEP_HISTORY=0
KEEP_SERVER=0
DRY_RUN=0
ASSUME_YES=0
ONLY_ACCOUNT=""

say()  { printf '\n\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\n\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --keep-identity) KEEP_IDENTITY=1 ;;
    --keep-history)  KEEP_HISTORY=1 ;;
    --keep-server)   KEEP_SERVER=1 ;;
    --account) shift; ONLY_ACCOUNT="${1:-}"; [ -n "$ONLY_ACCOUNT" ] || die "--account needs a name" ;;
    --dry-run) DRY_RUN=1 ;;
    --yes|-y)  ASSUME_YES=1 ;;
    -h|--help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1  (try --help)" ;;
  esac
  shift
done

[ -d "$CONF_DIR" ] || die "No BENCchat config directory at $CONF_DIR
     Nothing to reset — it is already a blank slate."

# --- which accounts --------------------------------------------------------
# One file per account under trust/, history/ and rooms/. The remembered screen
# name in config.json counts too: it is what drives auto-login, so an account
# with no data files still has a keyring entry to clear.
accounts() {
  for d in trust history rooms; do
    [ -d "$CONF_DIR/$d" ] || continue
    find "$CONF_DIR/$d" -maxdepth 1 -name '*.json' -exec basename {} .json \; 2>/dev/null
  done
  if [ -f "$CONF_DIR/config.json" ] && command -v python3 >/dev/null 2>&1; then
    python3 - "$CONF_DIR/config.json" <<'PY' 2>/dev/null || true
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
for k in ("rememberedScreenName", "lastScreenName"):
    if d.get(k):
        print(d[k])
PY
  fi
}

ACCOUNTS="$(accounts | sort -u || true)"
[ -n "$ONLY_ACCOUNT" ] && ACCOUNTS="$ONLY_ACCOUNT"

# --- what will be moved ----------------------------------------------------
TARGETS=()
for a in $ACCOUNTS; do
  [ -f "$CONF_DIR/trust/$a.json" ] && TARGETS+=("trust/$a.json")
  [ -f "$CONF_DIR/rooms/$a.json" ] && TARGETS+=("rooms/$a.json")
  [ "$KEEP_HISTORY" -eq 0 ] && [ -f "$CONF_DIR/history/$a.json" ] && TARGETS+=("history/$a.json")
done
# config.json holds the server address AND the remembered screen name, so it is
# what makes the app auto-sign-on. Keeping it means keeping auto-login.
[ "$KEEP_SERVER" -eq 0 ] && [ -f "$CONF_DIR/config.json" ] && TARGETS+=("config.json")

say "BENCchat reset"
echo "    config dir : $CONF_DIR"
echo "    accounts   : ${ACCOUNTS:-<none found>}"
echo
echo "    will clear :"
[ "$KEEP_SERVER" -eq 0 ]   && echo "                 server address, remembered screen name" \
                           || echo "                 (keeping server address and remembered name)"
echo "                 remembered device keys, room keys"
[ "$KEEP_HISTORY" -eq 0 ]  && echo "                 message history" \
                           || echo "                 (keeping message history)"
echo "                 saved password"
[ "$KEEP_IDENTITY" -eq 0 ] && echo "                 encryption identity (keypair + signing seed)" \
                           || echo "                 (keeping encryption identity)"

if [ ${#TARGETS[@]} -gt 0 ]; then
  echo
  echo "    files      :"
  for t in "${TARGETS[@]}"; do echo "                 $t"; done
fi

if [ "$KEEP_IDENTITY" -eq 0 ]; then
  echo
  warn "This drops this device's ENCRYPTION IDENTITY."
  cat <<'KEYS'
     A new keypair is generated on next sign-on, so every contact sees your
     safety number change and has to re-verify. That warning exists to catch
     an impersonator, so spending it needlessly teaches people to ignore it.
     Pass --keep-identity if you only meant to sign out.
KEYS
fi

if [ "$DRY_RUN" -eq 1 ]; then
  say "[dry run] nothing changed"
  exit 0
fi

if [ "$ASSUME_YES" -ne 1 ]; then
  echo
  printf 'Proceed? [y/N] '
  read -r reply
  case "$reply" in y|Y|yes|YES) ;; *) die "cancelled" ;; esac
fi

# --- move, do not delete ---------------------------------------------------
BACKUP=""
if [ ${#TARGETS[@]} -gt 0 ]; then
  BACKUP="$CONF_DIR/backup-$(date +%Y%m%d-%H%M%S)"
  say "Moving files to $BACKUP"
  for t in "${TARGETS[@]}"; do
    mkdir -p "$BACKUP/$(dirname "$t")"
    mv "$CONF_DIR/$t" "$BACKUP/$t"
    echo "    $t"
  done
fi

# --- keyring ---------------------------------------------------------------
# The saved password is always cleared: leaving it is what makes the app
# auto-sign-on, which is the opposite of a blank slate.
say "Clearing keyring entries"
KEYRING_OK=0
if ! command -v secret-tool >/dev/null 2>&1; then
  warn "secret-tool not found — clear BENCchat's entries by hand (Seahorse, KDE Wallet)."
elif ! timeout 5 secret-tool search service "$KEYRING_SERVICE" >/dev/null 2>&1; then
  # The secret service lives on the D-Bus session bus, so it is simply absent
  # over SSH or from a bare TTY even though it works in the desktop session.
  # Reporting success here would be the worst outcome: the password survives and
  # the app keeps signing itself in, which looks like the reset did nothing.
  warn "No secret service on this session's D-Bus — NOTHING was cleared from the keyring."
  echo "     The keyring only exists inside a desktop session; over SSH or a bare"
  echo "     TTY there is nothing listening. THE SAVED PASSWORD SURVIVED, so the"
  echo "     app will still auto-sign-on. Re-run this from a desktop terminal, or:"
  if [ "$KEEP_IDENTITY" -eq 0 ]; then
    echo "         secret-tool clear service $KEYRING_SERVICE"
  else
    for a in $ACCOUNTS; do
      echo "         secret-tool clear service $KEYRING_SERVICE username $a"
    done
  fi
elif [ "$KEEP_IDENTITY" -eq 0 ]; then
  # Clear by SERVICE, not per account. Anything BENCchat stored goes, including
  # entries for accounts whose files were already removed — enumerating names
  # would leave those orphans behind, and a blank slate should be blank.
  KEYRING_OK=1
  n=0
  while timeout 5 secret-tool clear service "$KEYRING_SERVICE" 2>/dev/null; do
    n=$((n+1))
    # secret-tool clear removes matching items; loop until nothing matches, so a
    # single call that only removes one entry still ends up clearing them all.
    timeout 5 secret-tool search service "$KEYRING_SERVICE" >/dev/null 2>&1 || break
  done
  echo "    cleared every $KEYRING_SERVICE entry"
else
  # Selective: the password goes, the identity stays.
  KEYRING_OK=1
  for a in $ACCOUNTS; do
    if secret-tool clear service "$KEYRING_SERVICE" username "$a" 2>/dev/null; then
      echo "    cleared saved password for $a"
    else
      echo "    (no saved password for $a)"
    fi
  done
  echo "    kept e2ee: and sign: entries"
fi

say "Done."
if [ "$KEYRING_OK" -eq 1 ] && [ "$KEEP_SERVER" -eq 0 ]; then
  echo
  echo "  Next launch shows the first-run sign-on screen with nothing filled in."
fi
if [ -n "$BACKUP" ]; then
  cat <<EOF

  Files were moved, not deleted. To undo:

      cp -r "$BACKUP"/* "$CONF_DIR"/

  Keyring entries cannot be restored — a cleared password must be typed again,
  and a cleared identity is regenerated on next sign-on.
EOF
fi
