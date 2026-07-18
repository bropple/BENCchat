#!/usr/bin/env bash
# backup-db.sh — encrypted, no-downtime backups of open-oscar-server's database.
#
# The database holds the things worth protecting: password material
# (users.authKey / strongMD5Pass / weakMD5Pass), buddy lists, and offline
# messages. Snapshots stored off the box are the copy most likely to leak, so
# they are encrypted before they ever leave.
#
# Encryption is ASYMMETRIC on purpose. The server holds only a PUBLIC key, so it
# can create backups but cannot read them — and neither can anyone who
# compromises it later. Decryption happens on your machine, with a private key
# that never touches the VM.
#
# The copy is taken with sqlite3 .backup, which is consistent against a live
# database, so the server keeps running throughout.
#
#   FIRST, on YOUR machine (not the VM) — create the keypair:
#
#     age-keygen -o benchat-backup.key          # keep this file safe, offline
#     grep 'public key' benchat-backup.key      # copy the age1... value
#
#     ...or with gpg, if you'd rather:
#     gpg --quick-generate-key "benchat-backup" default default never
#     gpg --armor --export benchat-backup > benchat-backup.pub
#
#   THEN, on the VM:
#     sudo ./backup-db.sh --recipient age1xxxxxxxx... /path/to/oscar.sqlite
#     sudo ./backup-db.sh --gpg-key benchat-backup.pub /path/to/oscar.sqlite
#
#   Nightly, via systemd:
#     sudo ./backup-db.sh --install-timer --recipient age1xxx... /path/to/oscar.sqlite
#
#   To restore, on YOUR machine:
#     age -d -i benchat-backup.key backup.sqlite.gz.age | gunzip > oscar.sqlite
#     gpg -d backup.sqlite.gz.gpg | gunzip > oscar.sqlite

set -euo pipefail

DB=""
RECIPIENT=""
GPG_KEY=""
OUTDIR="/var/backups/benchat"
KEEP=14
INSTALL_TIMER=0

say()  { printf '\n\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\n\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --recipient)     RECIPIENT="${2:-}"; shift 2 ;;
    --gpg-key)       GPG_KEY="${2:-}"; shift 2 ;;
    --out)           OUTDIR="${2:-}"; shift 2 ;;
    --keep)          KEEP="${2:-}"; shift 2 ;;
    --install-timer) INSTALL_TIMER=1; shift ;;
    -h|--help)       sed -n '2,40p' "$0"; exit 0 ;;
    -*)              die "unknown option: $1" ;;
    *)               DB="$1"; shift ;;
  esac
done

# --- Locate the database ----------------------------------------------------
if [ -z "$DB" ]; then
  for candidate in ./oscar.sqlite /opt/open-oscar-server/oscar.sqlite \
                   /var/lib/open-oscar-server/oscar.sqlite ~/oscar.sqlite; do
    if [ -f "$candidate" ]; then DB="$candidate"; break; fi
  done
fi
[ -n "$DB" ] || die "Give me the database path:  sudo ./backup-db.sh --recipient age1... /path/to/oscar.sqlite"
[ -f "$DB" ] || die "No such file: $DB"
command -v sqlite3 >/dev/null 2>&1 || die "sqlite3 is not installed."

# --- Pick an encryption method ----------------------------------------------
# Both are asymmetric: the VM encrypts with a public key and cannot decrypt.
if [ -n "$RECIPIENT" ]; then
  command -v age >/dev/null 2>&1 || die "age is not installed. Try: sudo apt-get install age
     (or use --gpg-key with a gpg public key instead)"
  METHOD=age
elif [ -n "$GPG_KEY" ]; then
  command -v gpg >/dev/null 2>&1 || die "gpg is not installed."
  [ -f "$GPG_KEY" ] || die "No such public key file: $GPG_KEY"
  METHOD=gpg
else
  die "Tell me who to encrypt to:
       --recipient age1xxxxx...     (an age public key)
       --gpg-key   /path/to/key.pub (an exported gpg public key)

     Generate the keypair on YOUR machine, never on the server — the whole point
     is that this box cannot read its own backups. See the notes at the top of
     this script."
fi

# --- Optionally install a nightly timer -------------------------------------
if [ "$INSTALL_TIMER" -eq 1 ]; then
  [ "$(id -u)" -eq 0 ] || die "Installing the timer needs root: sudo ./backup-db.sh --install-timer ..."
  SELF="$(readlink -f "$0")"
  ARGS="--out $OUTDIR --keep $KEEP"
  if [ "$METHOD" = age ]; then ARGS="$ARGS --recipient $RECIPIENT"; else ARGS="$ARGS --gpg-key $(readlink -f "$GPG_KEY")"; fi

  say "Installing benchat-backup.service / .timer (nightly at 03:20)"
  cat > /etc/systemd/system/benchat-backup.service <<EOF
[Unit]
Description=Encrypted backup of the BENCchat OSCAR database

[Service]
Type=oneshot
ExecStart=$SELF $ARGS $(readlink -f "$DB")
EOF
  cat > /etc/systemd/system/benchat-backup.timer <<'EOF'
[Unit]
Description=Nightly encrypted backup of the BENCchat OSCAR database

[Timer]
OnCalendar=*-*-* 03:20:00
Persistent=true

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now benchat-backup.timer
  say "Timer installed. Check it with:  systemctl list-timers benchat-backup.timer"
fi

# --- Take the backup --------------------------------------------------------
mkdir -p "$OUTDIR"
chmod 700 "$OUTDIR"

STAMP=$(date +%Y%m%d-%H%M%S)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

say "Copying the database (server keeps running)"
# .backup is consistent against a live database; cp is not.
sqlite3 "$DB" ".backup '$TMP/oscar.sqlite'"
[ -s "$TMP/oscar.sqlite" ] || die "The database copy came out empty — nothing was written."

# Sanity-check the copy before trusting it as a backup.
if ! sqlite3 "$TMP/oscar.sqlite" "PRAGMA integrity_check;" | grep -q '^ok$'; then
  die "The copy failed its integrity check — refusing to store a corrupt backup."
fi
USERS=$(sqlite3 "$TMP/oscar.sqlite" "SELECT COUNT(*) FROM users;" 2>/dev/null || echo "?")

gzip -9 "$TMP/oscar.sqlite"

case "$METHOD" in
  age)
    OUT="$OUTDIR/oscar-$STAMP.sqlite.gz.age"
    say "Encrypting to $RECIPIENT"
    age -r "$RECIPIENT" -o "$OUT" "$TMP/oscar.sqlite.gz"
    ;;
  gpg)
    OUT="$OUTDIR/oscar-$STAMP.sqlite.gz.gpg"
    say "Encrypting to the public key in $GPG_KEY"
    # A throwaway keyring keeps this out of root's own gpg state, and
    # --trust-model always avoids an interactive trust prompt for a key we were
    # handed deliberately.
    GNUPGHOME="$TMP/gnupg"; mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"; export GNUPGHOME
    gpg --batch --quiet --import "$GPG_KEY"
    RECIP=$(gpg --batch --with-colons --list-keys | awk -F: '/^uid:/ {print $10; exit}')
    [ -n "$RECIP" ] || die "Could not read a user ID from $GPG_KEY"
    gpg --batch --yes --trust-model always --encrypt --recipient "$RECIP" \
        --output "$OUT" "$TMP/oscar.sqlite.gz"
    ;;
esac

[ -s "$OUT" ] || die "Encryption produced no output."
chmod 600 "$OUT"

# The plaintext copy only ever existed in $TMP, which the trap removes.
SIZE=$(du -h "$OUT" | cut -f1)
say "Wrote $OUT ($SIZE, $USERS user accounts)"

# --- Prune ------------------------------------------------------------------
if [ "$KEEP" -gt 0 ]; then
  mapfile -t OLD < <(ls -1t "$OUTDIR"/oscar-*.sqlite.gz.* 2>/dev/null | tail -n "+$((KEEP + 1))")
  if [ "${#OLD[@]}" -gt 0 ]; then
    say "Pruning ${#OLD[@]} backup(s) older than the newest $KEEP"
    rm -f "${OLD[@]}"
  fi
fi

cat <<EOF

Backups live in $OUTDIR and are readable only by the holder of the private key —
not by this server. Copy them somewhere else; a backup that only exists on the
machine it protects is not a backup.

Restore on the machine holding the private key:
  age -d -i benchat-backup.key $(basename "$OUT") | gunzip > oscar.sqlite
  gpg -d $(basename "$OUT") | gunzip > oscar.sqlite
EOF
