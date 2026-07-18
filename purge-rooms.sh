#!/usr/bin/env bash
# purge-rooms.sh — delete chat rooms from open-oscar-server's database.
#
# Why this exists: the management API can only delete PUBLIC rooms
# (DELETE /chat/room/public hardcodes the public exchange), while BENCchat
# creates rooms on the PRIVATE exchange. There is no API route for those, so
# direct SQL is the only option.
#
# Room names are permanently unique — UNIQUE (exchange, name) — so every test
# room ever created keeps squatting its name until removed.
#
# This touches the same SQLite file as your user accounts, so it refuses to run
# while the server is up, takes a backup first, shows exactly what it will
# delete, and asks before doing it.
#
# Usage:
#   sudo ./purge-rooms.sh /path/to/oscar.sqlite            # all rooms
#   sudo ./purge-rooms.sh /path/to/oscar.sqlite --private  # private exchange only
#   sudo ./purge-rooms.sh /path/to/oscar.sqlite --yes      # skip the prompt
#   sudo ./purge-rooms.sh /path/to/oscar.sqlite --force    # skip the running-server check

set -euo pipefail

DB="${1:-}"
shift || true

PRIVATE_ONLY=0
ASSUME_YES=0
SKIP_SERVER_CHECK=0
for arg in "$@"; do
  case "$arg" in
    --private) PRIVATE_ONLY=1 ;;
    --yes|-y)  ASSUME_YES=1 ;;
    --force)   SKIP_SERVER_CHECK=1 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

say()  { printf '\n\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\n\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# --- Locate the database ----------------------------------------------------
if [ -z "$DB" ]; then
  for candidate in ./oscar.sqlite /opt/open-oscar-server/oscar.sqlite \
                   /var/lib/open-oscar-server/oscar.sqlite ~/oscar.sqlite; do
    if [ -f "$candidate" ]; then DB="$candidate"; break; fi
  done
fi
[ -n "$DB" ] || die "Give me the database path:  sudo ./purge-rooms.sh /path/to/oscar.sqlite"
[ -f "$DB" ] || die "No such file: $DB"

command -v sqlite3 >/dev/null 2>&1 || die "sqlite3 is not installed. Try: sudo apt-get install sqlite3  (or dnf install sqlite)"

# --- Refuse to run against a live server ------------------------------------
# Deleting rows under a running server leaves it holding stale room state in
# memory, and a write during an active transaction can fail outright.
#
# Matching is on the process NAME (pgrep -x), not the full command line: -f
# would match this very script whenever the database path happens to contain
# the server's name, and the script would refuse to run because it found
# itself.
if [ "$SKIP_SERVER_CHECK" -ne 1 ]; then
  RUNNING=""
  # "open-oscar-server" is 17 characters and Linux truncates a process name to
  # 15, so the truncated form has to be matched too or a running server slips
  # straight past this check.
  for procname in oscar open-oscar-server open-oscar-serv oscar-server; do
    if pgrep -x "$procname" >/dev/null 2>&1; then RUNNING="$procname"; break; fi
  done
  if [ -n "$RUNNING" ]; then
    die "A process named \"$RUNNING\" is still running. Stop the server first, e.g.:
       sudo systemctl stop open-oscar-server
     If that is not the OSCAR server, re-run with --force to skip this check."
  fi
fi

# --- Show what is there -----------------------------------------------------
if [ "$PRIVATE_ONLY" -eq 1 ]; then
  WHERE="WHERE exchange = 4"
  SCOPE="private-exchange rooms (the ones BENCchat creates)"
else
  WHERE=""
  SCOPE="ALL rooms, public and private"
fi

TOTAL=$(sqlite3 "$DB" "SELECT COUNT(*) FROM chatRoom $WHERE;")
if [ "$TOTAL" -eq 0 ]; then
  say "No rooms to remove ($SCOPE). Nothing to do."
  exit 0
fi

say "About to delete $SCOPE — $TOTAL room(s) from $DB"
echo
sqlite3 -header -column "$DB" \
  "SELECT exchange, name, creator, created FROM chatRoom $WHERE ORDER BY exchange, created;"
echo
warn "Anyone currently in these rooms stays connected until they leave; the rooms
     simply stop existing afterwards. Message history is unaffected — the server
     never stored room messages in the first place."

# --- Confirm ----------------------------------------------------------------
if [ "$ASSUME_YES" -ne 1 ]; then
  printf '\nType the number of rooms to confirm deletion (%d), or anything else to abort: ' "$TOTAL"
  read -r answer
  [ "$answer" = "$TOTAL" ] || die "Aborted. Nothing was changed."
fi

# --- Back up ----------------------------------------------------------------
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP="${DB}.backup-${STAMP}"
say "Backing up to $BACKUP"
# .backup produces a consistent copy even if something else has the file open.
sqlite3 "$DB" ".backup '$BACKUP'"
[ -s "$BACKUP" ] || die "Backup failed — refusing to modify the database."

# --- Delete -----------------------------------------------------------------
say "Deleting"
sqlite3 "$DB" "DELETE FROM chatRoom $WHERE;"

REMAINING=$(sqlite3 "$DB" "SELECT COUNT(*) FROM chatRoom;")
say "Done. $TOTAL removed; $REMAINING room(s) remain in the table."

cat <<EOF

Restore the backup if anything looks wrong:
  sudo systemctl stop open-oscar-server
  cp "$BACKUP" "$DB"
  sudo systemctl start open-oscar-server

Otherwise start the server again:
  sudo systemctl start open-oscar-server
EOF
