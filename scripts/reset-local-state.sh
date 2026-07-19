#!/usr/bin/env bash
# Reset BENCchat's local state.
#
# Mainly for when the SERVER has been rebuilt with a fresh database. The client
# then holds records about keys and rooms that no longer exist, which shows up as
# spurious "safety number changed" warnings and rooms that cannot be rejoined.
#
#   ./reset-local-state.sh                 # clear stale server-linked state
#   ./reset-local-state.sh --history       # ...and message history
#   ./reset-local-state.sh --keys          # ...and the encryption identity
#   ./reset-local-state.sh --all           # ...and the server address (first-run)
#
#   --account NAME   act on one account only (default: all found)
#   --dry-run        show what would happen, change nothing
#   --yes            skip the confirmation
#
# NOTHING IS DELETED. Files are moved to a timestamped backup directory and the
# restore command is printed, because "reset my client" should not be able to
# destroy the only copy of anything.

set -euo pipefail

CONF_DIR="${BENCCHAT_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/BENCchat}"
KEYRING_SERVICE=BENCchat

DO_HISTORY=0
DO_KEYS=0
DO_CONFIG=0
DRY_RUN=0
ASSUME_YES=0
ONLY_ACCOUNT=""

say()  { printf '\n\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\n\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --history) DO_HISTORY=1 ;;
    --keys)    DO_KEYS=1 ;;
    --all)     DO_HISTORY=1; DO_KEYS=1; DO_CONFIG=1 ;;
    --account) shift; ONLY_ACCOUNT="${1:-}"; [ -n "$ONLY_ACCOUNT" ] || die "--account needs a name" ;;
    --dry-run) DRY_RUN=1 ;;
    --yes|-y)  ASSUME_YES=1 ;;
    -h|--help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1  (try --help)" ;;
  esac
  shift
done

[ -d "$CONF_DIR" ] || die "No BENCchat config directory at $CONF_DIR
     Nothing to reset. If your config lives elsewhere, set BENCCHAT_CONFIG_DIR."

# --- which accounts --------------------------------------------------------
accounts() {
  # Accounts are one file per account under trust/, history/ and rooms/.
  for d in trust history rooms; do
    [ -d "$CONF_DIR/$d" ] || continue
    find "$CONF_DIR/$d" -maxdepth 1 -name '*.json' -exec basename {} .json \; 2>/dev/null
  done | sort -u
}

ACCOUNTS="$(accounts || true)"
[ -n "$ONLY_ACCOUNT" ] && ACCOUNTS="$ONLY_ACCOUNT"

# --- what will be touched --------------------------------------------------
TARGETS=()
for a in $ACCOUNTS; do
  # trust/ remembers peers' device keys and this account's own device list.
  # Against a rebuilt server every one of those keys is gone, so keeping the
  # file means being warned that everybody's key "changed" — training you to
  # click through the one warning that is supposed to matter.
  [ -f "$CONF_DIR/trust/$a.json" ] && TARGETS+=("trust/$a.json")
  # rooms/ holds group keys for rooms that no longer exist server-side.
  [ -f "$CONF_DIR/rooms/$a.json" ] && TARGETS+=("rooms/$a.json")
  [ "$DO_HISTORY" -eq 1 ] && [ -f "$CONF_DIR/history/$a.json" ] && TARGETS+=("history/$a.json")
done
[ "$DO_CONFIG" -eq 1 ] && [ -f "$CONF_DIR/config.json" ] && TARGETS+=("config.json")

say "BENCchat local state reset"
echo "    config dir : $CONF_DIR"
echo "    accounts   : ${ACCOUNTS:-<none found>}"
echo
if [ ${#TARGETS[@]} -eq 0 ]; then
  echo "    files      : nothing to move"
else
  echo "    files      :"
  for t in "${TARGETS[@]}"; do echo "                 $t"; done
fi

if [ "$DO_KEYS" -eq 1 ]; then
  echo
  warn "--keys will drop this device's ENCRYPTION IDENTITY from the keyring."
  cat <<'KEYS'
     A new keypair is generated on next sign-on, so every contact sees your
     safety number change and has to re-verify. That is the alarm meant to
     catch an impersonator, so spending it casually teaches people to ignore
     it. Only do this if the key is genuinely lost or you want a clean break.

     Your saved password is cleared too, so you will need to type it again.
KEYS
fi

[ "$DO_CONFIG" -eq 1 ] && warn "--all clears the server address; BENCchat returns to its first-run state."

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
if [ ${#TARGETS[@]} -gt 0 ]; then
  STAMP="$(date +%Y%m%d-%H%M%S)"
  BACKUP="$CONF_DIR/backup-$STAMP"
  say "Moving files to $BACKUP"
  for t in "${TARGETS[@]}"; do
    mkdir -p "$BACKUP/$(dirname "$t")"
    mv "$CONF_DIR/$t" "$BACKUP/$t"
    echo "    $t"
  done
fi

# --- keyring ---------------------------------------------------------------
if [ "$DO_KEYS" -eq 1 ]; then
  say "Clearing keyring entries"
  if ! command -v secret-tool >/dev/null 2>&1; then
    warn "secret-tool not found — clear these by hand (GNOME Seahorse, KDE Wallet):"
    for a in $ACCOUNTS; do
      echo "    service=$KEYRING_SERVICE  username=$a, e2ee:$a, sign:$a"
    done
  elif ! timeout 5 secret-tool search service "$KEYRING_SERVICE" >/dev/null 2>&1; then
    # The secret service lives on the D-Bus session bus, so it is unreachable
    # over SSH or from a bare TTY even though it works fine in the desktop
    # session. Failing loudly beats silently leaving the key in place.
    warn "No secret service on this session's D-Bus."
    echo "     The keyring is only reachable from your desktop session — over SSH"
    echo "     or a plain TTY there is nothing listening. Re-run this from a"
    echo "     terminal inside the desktop, or clear them by hand:"
    for a in $ACCOUNTS; do
      echo "         secret-tool clear service $KEYRING_SERVICE username $a"
      echo "         secret-tool clear service $KEYRING_SERVICE username e2ee:$a"
      echo "         secret-tool clear service $KEYRING_SERVICE username sign:$a"
    done
  else
    for a in $ACCOUNTS; do
      for u in "$a" "e2ee:$a" "sign:$a"; do
        if secret-tool clear service "$KEYRING_SERVICE" username "$u" 2>/dev/null; then
          echo "    cleared $u"
        else
          echo "    (nothing stored for $u)"
        fi
      done
    done
  fi
fi

say "Done."
cat <<EOF

  Next sign-on rebuilds what was cleared: this device republishes its keys,
  and peers' keys are learned again from the server's directory.

EOF
if [ ${#TARGETS[@]} -gt 0 ]; then
  cat <<EOF
  To undo, move the files back:

      cp -r "$BACKUP"/* "$CONF_DIR"/

  The backup is kept until you delete it.
EOF
fi
