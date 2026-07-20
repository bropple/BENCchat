#!/usr/bin/env bash
# migrate-db.sh — move BENCoscar's database onto the encrypted volume, and stop
# the server from ever starting without it.
#
# Two jobs, and the second one matters more than the first:
#
#   1. Copy the SQLite database onto the mounted encrypted volume and point
#      BENCoscar at the new path.
#   2. Add RequiresMountsFor= to the BENCoscar systemd unit, so the SERVICE
#      refuses to start when the volume is not mounted — even though the
#      MACHINE boots fine without it.
#
# Job 2 exists because of a silent failure that looks like nothing is wrong. If
# the volume does not mount, the mountpoint is still there and still empty, and
# SQLite will cheerfully create a brand new database on it. The server starts,
# reports healthy, and has no accounts. The first sign-on says the password is
# wrong. Nothing errors, nothing logs anything alarming — and the next nightly
# backup dutifully overwrites a good snapshot with the empty one.
#
#   sudo ./migrate-db.sh
#   sudo ./migrate-db.sh --dry-run
#   sudo ./migrate-db.sh --service ras --db /var/lib/ras/oscar.sqlite
#
#   --service NAME   systemd unit (asked for, with a guess, if omitted)
#   --db PATH        current database path (asked for, with a guess)
#   --mount PATH     encrypted mountpoint (default /var/lib/benchat-data)
#   --dry-run        show what would happen, change nothing
#   --yes, -y        skip confirmations
#
# Re-runnable. The original database is RENAMED, never deleted, and only after
# the copy has been verified. If the copy is already in place it says so and
# moves on to the guard.

set -euo pipefail

SERVICE="${SERVICE:-}"
DB=""
MOUNT_POINT="${MOUNT_POINT:-/var/lib/benchat-data}"
DRY_RUN=0
ASSUME_YES=0

say()  { printf '\n\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\n\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --service) shift; SERVICE="${1:-}";     [ -n "$SERVICE" ]     || die "--service needs a name" ;;
    --db)      shift; DB="${1:-}";          [ -n "$DB" ]          || die "--db needs a path" ;;
    --mount)   shift; MOUNT_POINT="${1:-}"; [ -n "$MOUNT_POINT" ] || die "--mount needs a path" ;;
    --dry-run) DRY_RUN=1 ;;
    --yes|-y)  ASSUME_YES=1 ;;
    -h|--help) sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)         die "unknown option: $1  (try --help)" ;;
  esac
  shift
done

[ "$(id -u)" -eq 0 ] || die "Run this with sudo:  sudo ./migrate-db.sh"
command -v sqlite3 >/dev/null 2>&1 || die "sqlite3 is not installed.
     It is what makes a consistent copy of a live database and then verifies it.
     Install it (apt-get install sqlite3) and re-run."

ask() { # ask <prompt> <default> -> echoes answer
  local prompt="$1" default="$2" reply
  if [ "$ASSUME_YES" -eq 1 ] || [ ! -t 0 ]; then echo "$default"; return; fi
  printf '%s [%s]: ' "$prompt" "$default" >&2
  read -r reply
  echo "${reply:-$default}"
}

# --- 1. The encrypted volume must actually be mounted ----------------------
say "Checking the encrypted volume"
MOUNT_SRC="$(findmnt -no SOURCE --target "$MOUNT_POINT" 2>/dev/null || true)"
MOUNT_TGT="$(findmnt -no TARGET --target "$MOUNT_POINT" 2>/dev/null || true)"

if [ "$MOUNT_TGT" != "$MOUNT_POINT" ]; then
  die "$MOUNT_POINT is not a mountpoint — it is part of ${MOUNT_TGT:-/}.

     Migrating now would copy the database onto ordinary unencrypted storage
     and then tell BENCoscar that is where it lives, which is worse than not
     doing this at all. Run ./bind-volume.sh first, or mount it:
         mount $MOUNT_POINT"
fi

case "$MOUNT_SRC" in
  /dev/mapper/*) echo "    $MOUNT_POINT <- $MOUNT_SRC  (dm-crypt: good)" ;;
  *)
    warn "$MOUNT_POINT is mounted from $MOUNT_SRC, which is not a /dev/mapper device."
    echo "     That does not look like an encrypted volume. If you know it is"
    echo "     (LVM-on-LUKS, say), carry on; otherwise stop."
    if [ "$ASSUME_YES" -ne 1 ] && [ "$DRY_RUN" -eq 0 ]; then
      printf '     Continue anyway? [y/N] '
      read -r reply
      case "$reply" in y|Y|yes|YES) ;; *) die "cancelled" ;; esac
    fi
    ;;
esac

# --- 2. Which service ------------------------------------------------------
if [ -z "$SERVICE" ]; then
  GUESS=""
  for c in ras open-oscar-server oscar benchat-oscar bencoscar; do
    if systemctl list-unit-files "$c.service" >/dev/null 2>&1 \
       && systemctl list-unit-files "$c.service" 2>/dev/null | grep -q "^$c.service"; then
      GUESS="$c"; break
    fi
  done
  if [ -z "$GUESS" ]; then
    echo
    echo "Could not spot the BENCoscar unit. Units on this machine:"
    systemctl list-unit-files --type=service --no-legend 2>/dev/null \
      | awk '{print "    " $1}' | head -40
    GUESS="ras"
  fi
  SERVICE="$(ask "BENCoscar systemd unit" "$GUESS")"
fi
SERVICE="${SERVICE%.service}"

systemctl list-unit-files "$SERVICE.service" 2>/dev/null | grep -q "^$SERVICE.service" \
  || die "No systemd unit called $SERVICE.service.
     Pass the right one:  sudo ./migrate-db.sh --service <name>"

# The unit's User= decides who must be able to read the database. Getting this
# wrong produces a server that starts and then cannot open its own database.
SVC_USER="$(systemctl show -p User --value "$SERVICE.service" 2>/dev/null || true)"
SVC_GROUP="$(systemctl show -p Group --value "$SERVICE.service" 2>/dev/null || true)"
[ -n "$SVC_USER" ]  || SVC_USER=root
[ -n "$SVC_GROUP" ] || SVC_GROUP="$SVC_USER"

# --- 3. Which database -----------------------------------------------------
if [ -z "$DB" ]; then
  GUESS=""
  # Ask systemd what DB_PATH the unit is actually running with, rather than
  # guessing from a config file that may not be the one in force.
  ENVLINE="$(systemctl show -p Environment --value "$SERVICE.service" 2>/dev/null || true)"
  for tok in $ENVLINE; do
    case "$tok" in DB_PATH=*) GUESS="${tok#DB_PATH=}" ;; esac
  done
  if [ -z "$GUESS" ]; then
    for c in "/var/lib/$SERVICE/oscar.sqlite" /var/lib/ras/oscar.sqlite \
             /opt/open-oscar-server/oscar.sqlite /var/lib/open-oscar-server/oscar.sqlite; do
      [ -f "$c" ] && { GUESS="$c"; break; }
    done
  fi
  [ -n "$GUESS" ] || GUESS="/var/lib/$SERVICE/oscar.sqlite"
  DB="$(ask "Current database path" "$GUESS")"
fi

TARGET="$MOUNT_POINT/oscar.sqlite"
DROPIN_DIR="/etc/systemd/system/$SERVICE.service.d"
DROPIN="$DROPIN_DIR/10-benchat-luks.conf"

ALREADY=0
if [ "$DB" = "$TARGET" ]; then
  ALREADY=1
elif [ ! -f "$DB" ] && [ -f "$TARGET" ]; then
  # A previous run already moved it. Not an error — finish the job.
  ALREADY=1
elif [ ! -f "$DB" ]; then
  die "No database at $DB, and none at $TARGET either.

     If BENCoscar has never run, there is nothing to migrate: point DB_PATH at
     $TARGET yourself and let it create the database there. Otherwise find the
     real path and pass it with --db."
fi

say "Migration plan"
cat <<EOF
    service       : $SERVICE.service  (runs as $SVC_USER:$SVC_GROUP)
    database from : $DB
    database to   : $TARGET
    encrypted vol : $MOUNT_SRC
EOF
if [ "$ALREADY" -eq 1 ]; then
  echo "    copy          : already done — skipping, will (re)install the guard"
else
  SRC_SIZE="$(du -h "$DB" | cut -f1)"
  echo "    copy          : $SRC_SIZE, taken with sqlite3 .backup then verified"
  echo "                    the original is RENAMED, not deleted"
fi
cat <<EOF
    guard         : $DROPIN
                    RequiresMountsFor=$MOUNT_POINT
                    Environment=DB_PATH=$TARGET

    The server will be stopped for the copy and started again afterwards.
EOF

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

# --- 4. Stop, copy, verify -------------------------------------------------
WAS_ACTIVE=0
systemctl is-active --quiet "$SERVICE.service" && WAS_ACTIVE=1

if [ "$WAS_ACTIVE" -eq 1 ]; then
  say "Stopping $SERVICE.service"
  systemctl stop "$SERVICE.service"
fi

if [ "$ALREADY" -eq 0 ]; then
  [ -e "$TARGET" ] && die "$TARGET already exists but $DB does too.
     Two databases, and this script will not guess which one is real. Compare
     them and remove or rename the one you do not want, then re-run:
         sqlite3 $DB     'SELECT COUNT(*) FROM users;'
         sqlite3 $TARGET 'SELECT COUNT(*) FROM users;'"

  say "Copying the database"
  # .backup rather than cp: consistent even if something still has it open, and
  # it produces a file sqlite3 will immediately tell us the truth about.
  sqlite3 "$DB" ".backup '$TARGET'"
  [ -s "$TARGET" ] || die "The copy came out empty. The original at $DB is untouched."

  say "Verifying the copy"
  sqlite3 "$TARGET" "PRAGMA integrity_check;" | grep -qx 'ok' \
    || die "The copy failed its integrity check. Original untouched at $DB.
     Removing the bad copy is safe:  rm $TARGET"

  SRC_USERS="$(sqlite3 "$DB" "SELECT COUNT(*) FROM users;" 2>/dev/null || echo "?")"
  DST_USERS="$(sqlite3 "$TARGET" "SELECT COUNT(*) FROM users;" 2>/dev/null || echo "?")"
  echo "    user accounts: $SRC_USERS in the original, $DST_USERS in the copy"
  [ "$SRC_USERS" = "$DST_USERS" ] || die "The copy has a different number of accounts.
     Original untouched at $DB. Remove the copy and investigate:  rm $TARGET"

  chown "$SVC_USER:$SVC_GROUP" "$TARGET"
  chmod 600 "$TARGET"
  chown "$SVC_USER:$SVC_GROUP" "$MOUNT_POINT"
  chmod 700 "$MOUNT_POINT"

  # Only now, with a verified copy in hand, is the original expendable — and
  # even then it is only renamed. Deleting it here would make a mistake in the
  # next ten lines unrecoverable.
  STAMP="$(date +%Y%m%d-%H%M%S)"
  KEPT="$DB.pre-luks-$STAMP"
  say "Renaming the original to $KEPT"
  mv "$DB" "$KEPT"
  for suffix in -wal -shm; do
    [ -f "$DB$suffix" ] && mv "$DB$suffix" "$KEPT$suffix"
  done
  echo "    it is still there, still readable, still unencrypted."
  echo "    delete it yourself once you are satisfied — this script never will."
else
  say "Database is already at $TARGET — leaving it alone"
  chown "$SVC_USER:$SVC_GROUP" "$TARGET" 2>/dev/null || true
  chmod 600 "$TARGET" 2>/dev/null || true
fi

# --- 5. The guard ----------------------------------------------------------
# A drop-in rather than an edit: the packaged unit stays untouched, an upgrade
# cannot clobber this, and uninstall.sh is one rm.
#
# RequiresMountsFor= pulls in the mount unit for $MOUNT_POINT and makes the
# service Require= and After= it. Combined with nofail in fstab this gives
# exactly the behaviour we want and no other:
#
#   Tang down  -> mount fails -> machine still boots, SSH still works (nofail)
#                             -> $SERVICE refuses to start (RequiresMountsFor)
#
# Drop the guard and nofail turns into a data-loss feature: the box boots, the
# directory is empty, and SQLite makes a new database on it.
#
# Environment= appears after the unit's own assignments, so this DB_PATH wins
# without editing theirs.
say "Installing the mount guard: $DROPIN"
mkdir -p "$DROPIN_DIR"
cat > "$DROPIN" <<EOF
# Installed by scripts/benchat-luks/migrate-db.sh — remove with uninstall.sh.
#
# RequiresMountsFor is the whole point of this file. The database lives on an
# encrypted volume that mounts with nofail, so a Tang outage leaves the machine
# up and reachable but the volume absent. Without this line the service would
# start on an empty mountpoint and SQLite would create a fresh, empty database
# there: healthy-looking server, no accounts, and the next backup overwrites a
# good file with the empty one.
[Unit]
RequiresMountsFor=$MOUNT_POINT
After=network-online.target
Wants=network-online.target

[Service]
Environment="DB_PATH=$TARGET"
EOF

systemctl daemon-reload

EFFECTIVE=""
for tok in $(systemctl show -p Environment --value "$SERVICE.service" 2>/dev/null || true); do
  case "$tok" in DB_PATH=*) EFFECTIVE="${tok#DB_PATH=}" ;; esac
done
if [ -n "$EFFECTIVE" ] && [ "$EFFECTIVE" != "$TARGET" ]; then
  warn "systemd says DB_PATH is still '$EFFECTIVE', not '$TARGET'."
  echo "     Something later in the unit is overriding the drop-in — most likely an"
  echo "     EnvironmentFile= that also sets DB_PATH. Fix that file to point at"
  echo "     $TARGET, or the server will keep using the old, unencrypted database."
fi

# --- 6. Start and check ----------------------------------------------------
say "Starting $SERVICE.service"
if ! systemctl start "$SERVICE.service"; then
  warn "$SERVICE.service did not start. Recent log:"
  journalctl -u "$SERVICE.service" -n 30 --no-pager || true
  die "The database copy is in place at $TARGET and the original is still at
     $DB.pre-luks-*. Nothing is lost. Fix the above and start it yourself."
fi

sleep 2
if ! systemctl is-active --quiet "$SERVICE.service"; then
  warn "$SERVICE.service is not active. Recent log:"
  journalctl -u "$SERVICE.service" -n 30 --no-pager || true
  die "See above. Your data is intact in $TARGET and in $DB.pre-luks-*."
fi

USERS="$(sqlite3 "$TARGET" "SELECT COUNT(*) FROM users;" 2>/dev/null || echo "?")"

cat <<EOF

================================================================
 Done. BENCoscar is running against $TARGET ($USERS accounts).

 THE ONE TEST WORTH DOING — prove the guard works, now, while you are
 paying attention and not at 3am:

   sudo systemctl stop $SERVICE
   sudo umount $MOUNT_POINT
   sudo systemctl start $SERVICE      # must FAIL
   systemctl status $SERVICE          # "Unit ... mount ... not found/failed"

   sudo mount $MOUNT_POINT
   sudo systemctl start $SERVICE      # works again

 If it starts with the volume unmounted, the guard is not in force —
 stop and find out why before trusting any of this.

 Then reboot once and confirm the volume unlocks from Tang on its own.

 Still on unencrypted disk, on purpose, for you to remove when ready:
   $DB.pre-luks-*

 Backups: scripts/backup-db.sh reads whatever path you give it. Update
 its timer if it names the old path —
   systemctl cat benchat-backup.service | grep ExecStart
================================================================
EOF
