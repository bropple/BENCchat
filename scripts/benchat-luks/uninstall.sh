#!/usr/bin/env bash
# uninstall.sh — undo everything this bundle did on the BENCoscar host.
#
# Puts the database back on ordinary unencrypted storage, removes the mount
# guard, unbinds the volume from Tang, unmounts it and takes the crypttab and
# fstab entries back out.
#
# It does NOT wipe the LUKS container. Your data is still in there, and after
# the unbind the only thing that opens it is the recovery passphrase from
# bind-volume.sh. If you want the volume gone, that is a separate deliberate act
# and the last section tells you how.
#
#   sudo ./uninstall.sh
#   sudo ./uninstall.sh --dry-run
#   sudo ./uninstall.sh --service ras --restore-to /var/lib/ras/oscar.sqlite
#
#   --service NAME     systemd unit (asked for, with a guess)
#   --restore-to PATH  where the database goes back to (asked for, with a guess)
#   --mount PATH       encrypted mountpoint (default /var/lib/benchat-data)
#   --name NAME        dm-crypt mapper name (default benchat-data)
#   --keep-db          leave the database on the encrypted volume; only remove
#                      the mount guard and the crypttab/fstab entries
#   --dry-run          show what would happen, change nothing
#   --yes, -y          skip confirmations
#
# The copy back is verified before anything is unmounted, and the copy on the
# encrypted volume is left in place. Nothing here deletes a database.

set -euo pipefail

SERVICE="${SERVICE:-}"
RESTORE_TO=""
MOUNT_POINT="${MOUNT_POINT:-/var/lib/benchat-data}"
MAPPER_NAME="${MAPPER_NAME:-benchat-data}"
KEEP_DB=0
DRY_RUN=0
ASSUME_YES=0

say()  { printf '\n\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\n\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --service)    shift; SERVICE="${1:-}";     [ -n "$SERVICE" ]     || die "--service needs a name" ;;
    --restore-to) shift; RESTORE_TO="${1:-}";  [ -n "$RESTORE_TO" ]  || die "--restore-to needs a path" ;;
    --mount)      shift; MOUNT_POINT="${1:-}"; [ -n "$MOUNT_POINT" ] || die "--mount needs a path" ;;
    --name)       shift; MAPPER_NAME="${1:-}"; [ -n "$MAPPER_NAME" ] || die "--name needs a value" ;;
    --keep-db)    KEEP_DB=1 ;;
    --dry-run)    DRY_RUN=1 ;;
    --yes|-y)     ASSUME_YES=1 ;;
    -h|--help)    sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)            die "unknown option: $1  (try --help)" ;;
  esac
  shift
done

[ "$(id -u)" -eq 0 ] || die "Run this with sudo:  sudo ./uninstall.sh"

ask() {
  local prompt="$1" default="$2" reply
  if [ "$ASSUME_YES" -eq 1 ] || [ ! -t 0 ]; then echo "$default"; return; fi
  printf '%s [%s]: ' "$prompt" "$default" >&2
  read -r reply
  echo "${reply:-$default}"
}

# --- 1. Work out what is actually installed --------------------------------
if [ -z "$SERVICE" ]; then
  GUESS=""
  for d in /etc/systemd/system/*.service.d/10-benchat-luks.conf; do
    [ -e "$d" ] || continue
    GUESS="$(basename "$(dirname "$d")")"
    GUESS="${GUESS%.service.d}"
    break
  done
  [ -n "$GUESS" ] || GUESS="ras"
  SERVICE="$(ask "BENCoscar systemd unit" "$GUESS")"
fi
SERVICE="${SERVICE%.service}"
DROPIN="/etc/systemd/system/$SERVICE.service.d/10-benchat-luks.conf"

SOURCE_DEV="$(awk -v n="$MAPPER_NAME" '$1==n {print $2; exit}' /etc/crypttab 2>/dev/null || true)"
[ -n "$SOURCE_DEV" ] || SOURCE_DEV="$(cryptsetup status "$MAPPER_NAME" 2>/dev/null | awk '/device:/ {print $2; exit}' || true)"

DB_ON_VOL="$MOUNT_POINT/oscar.sqlite"

if [ -z "$RESTORE_TO" ] && [ "$KEEP_DB" -eq 0 ]; then
  GUESS=""
  # migrate-db.sh left the original next to where it came from, so the newest
  # .pre-luks-* file names the path we should restore to.
  for c in /var/lib/*/oscar.sqlite.pre-luks-* /opt/*/oscar.sqlite.pre-luks-*; do
    [ -e "$c" ] || continue
    GUESS="${c%%.pre-luks-*}"
  done
  [ -n "$GUESS" ] || GUESS="/var/lib/$SERVICE/oscar.sqlite"
  RESTORE_TO="$(ask "Restore the database to" "$GUESS")"
fi

say "Uninstall plan"
cat <<EOF
    service       : $SERVICE.service
    mount guard   : ${DROPIN}$([ -e "$DROPIN" ] && echo "" || echo "   (not present)")
    mountpoint    : $MOUNT_POINT
    mapper        : /dev/mapper/$MAPPER_NAME
    LUKS device   : ${SOURCE_DEV:-<unknown — not in crypttab and not open>}
EOF
if [ "$KEEP_DB" -eq 1 ]; then
  echo "    database      : LEFT on the encrypted volume (--keep-db)"
  echo "                    the volume will not be unmounted or closed"
else
  echo "    database      : $DB_ON_VOL  ->  $RESTORE_TO  (copied, then verified)"
  echo "                    the copy on the encrypted volume is left in place"
fi
cat <<EOF

    The LUKS container is NOT wiped. After the unbind, only the recovery
    passphrase opens it.
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

# --- 2. Stop the service ---------------------------------------------------
if systemctl list-unit-files "$SERVICE.service" 2>/dev/null | grep -q "^$SERVICE.service"; then
  say "Stopping $SERVICE.service"
  systemctl stop "$SERVICE.service" || true
else
  warn "No unit called $SERVICE.service — carrying on with the volume."
fi

# --- 3. Restore the database ------------------------------------------------
# Before anything is unmounted or closed, while the data is still reachable.
if [ "$KEEP_DB" -eq 0 ]; then
  if [ ! -f "$DB_ON_VOL" ]; then
    warn "No database at $DB_ON_VOL — nothing to restore."
    echo "     If it was never migrated, that is expected."
  else
    command -v sqlite3 >/dev/null 2>&1 || die "sqlite3 is not installed, so the copy
     back cannot be verified. Install it and re-run; nothing has been undone yet."

    if [ -e "$RESTORE_TO" ]; then
      STAMP="$(date +%Y%m%d-%H%M%S)"
      say "Moving the file already at $RESTORE_TO aside"
      mv "$RESTORE_TO" "$RESTORE_TO.displaced-$STAMP"
      echo "    -> $RESTORE_TO.displaced-$STAMP"
    fi

    say "Copying $DB_ON_VOL -> $RESTORE_TO"
    mkdir -p "$(dirname "$RESTORE_TO")"
    sqlite3 "$DB_ON_VOL" ".backup '$RESTORE_TO'"
    [ -s "$RESTORE_TO" ] || die "The copy came out empty. The encrypted volume is
     still mounted and still holds $DB_ON_VOL — nothing is lost."

    sqlite3 "$RESTORE_TO" "PRAGMA integrity_check;" | grep -qx 'ok' \
      || die "The restored copy failed its integrity check. The original on the
     encrypted volume is untouched and still mounted. Investigate before
     going further."

    SRC_USERS="$(sqlite3 "$DB_ON_VOL" "SELECT COUNT(*) FROM users;" 2>/dev/null || echo "?")"
    DST_USERS="$(sqlite3 "$RESTORE_TO" "SELECT COUNT(*) FROM users;" 2>/dev/null || echo "?")"
    echo "    user accounts: $SRC_USERS on the volume, $DST_USERS restored"
    [ "$SRC_USERS" = "$DST_USERS" ] || die "Account counts differ. Refusing to unmount.
     Everything is still where it was."

    SVC_USER="$(systemctl show -p User --value "$SERVICE.service" 2>/dev/null || true)"
    SVC_GROUP="$(systemctl show -p Group --value "$SERVICE.service" 2>/dev/null || true)"
    [ -n "$SVC_USER" ]  || SVC_USER=root
    [ -n "$SVC_GROUP" ] || SVC_GROUP="$SVC_USER"
    chown "$SVC_USER:$SVC_GROUP" "$RESTORE_TO" || true
    chmod 600 "$RESTORE_TO"
    say "Database restored to unencrypted storage at $RESTORE_TO"
  fi
fi

# --- 4. Remove the mount guard ---------------------------------------------
# This has to go, and it has to go BEFORE the volume does. Leaving it behind
# means the service refuses to start against the restored database, because it
# still requires a mount that is no longer there.
if [ -e "$DROPIN" ]; then
  say "Removing the mount guard $DROPIN"
  rm -f "$DROPIN"
  rmdir "$(dirname "$DROPIN")" 2>/dev/null || true
  systemctl daemon-reload
else
  echo
  echo "    no mount guard to remove"
fi

# --- 5. crypttab / fstab ----------------------------------------------------
say "Removing /etc/crypttab and /etc/fstab entries"
STAMP="$(date +%Y%m%d-%H%M%S)"
if [ -f /etc/crypttab ]; then
  cp -a /etc/crypttab "/etc/crypttab.benchat-luks-uninstall.$STAMP.bak"
  grep -vE "^[[:space:]]*$MAPPER_NAME[[:space:]]" /etc/crypttab \
    | grep -v '^# BENCchat encrypted data volume' > /etc/crypttab.new
  mv /etc/crypttab.new /etc/crypttab
fi
cp -a /etc/fstab "/etc/fstab.benchat-luks-uninstall.$STAMP.bak"
grep -vE "^[^#]*[[:space:]]${MOUNT_POINT//\//\\/}[[:space:]]" /etc/fstab \
  | grep -v '^# BENCchat encrypted data volume' > /etc/fstab.new
mv /etc/fstab.new /etc/fstab
echo "    backups: /etc/crypttab.benchat-luks-uninstall.$STAMP.bak"
echo "             /etc/fstab.benchat-luks-uninstall.$STAMP.bak"
systemctl daemon-reload

# --- 6. Unbind, unmount, close ---------------------------------------------
if [ "$KEEP_DB" -eq 1 ]; then
  warn "--keep-db: the volume stays mounted and stays bound to Tang."
  echo "     The database is still only reachable while it is mounted, but the"
  echo "     guard is gone, so $SERVICE can now start without it and create an"
  echo "     empty database. Do not leave it in this state."
else
  if [ -n "$SOURCE_DEV" ] && command -v clevis >/dev/null 2>&1; then
    say "Unbinding from Tang"
    SLOTS="$(clevis luks list -d "$SOURCE_DEV" 2>/dev/null | awk -F: '{print $1}' || true)"
    if [ -n "$SLOTS" ]; then
      for slot in $SLOTS; do
        echo "    removing clevis binding in slot $slot"
        clevis luks unbind -f -d "$SOURCE_DEV" -s "$slot" || warn "could not unbind slot $slot"
      done
    else
      echo "    no clevis bindings found on $SOURCE_DEV"
    fi
  elif [ -z "$SOURCE_DEV" ]; then
    warn "Could not work out which device backs $MAPPER_NAME, so nothing was unbound."
    echo "     Find it and unbind by hand:"
    echo "         clevis luks list   -d /dev/disk/by-id/..."
    echo "         clevis luks unbind -d /dev/disk/by-id/... -s <slot>"
  fi

  if findmnt -no TARGET "$MOUNT_POINT" >/dev/null 2>&1; then
    say "Unmounting $MOUNT_POINT"
    umount "$MOUNT_POINT" || warn "Could not unmount $MOUNT_POINT — something is using it.
     Find it with:  fuser -vm $MOUNT_POINT"
  fi

  if [ -e "/dev/mapper/$MAPPER_NAME" ]; then
    say "Closing /dev/mapper/$MAPPER_NAME"
    cryptsetup luksClose "$MAPPER_NAME" || warn "Could not close $MAPPER_NAME."
  fi
fi

# --- 7. Restart the service -------------------------------------------------
if systemctl list-unit-files "$SERVICE.service" 2>/dev/null | grep -q "^$SERVICE.service"; then
  say "Starting $SERVICE.service"
  if systemctl start "$SERVICE.service"; then
    sleep 2
    systemctl is-active --quiet "$SERVICE.service" \
      && echo "    running" \
      || { warn "not active — recent log:"; journalctl -u "$SERVICE.service" -n 20 --no-pager || true; }
  else
    warn "Could not start it. Recent log:"
    journalctl -u "$SERVICE.service" -n 20 --no-pager || true
  fi
fi

cat <<EOF

================================================================
 Uninstalled.

 Left in place on purpose:
   ${RESTORE_TO:-<database not restored>}   the database, unencrypted again
   the LUKS container on ${SOURCE_DEV:-the volume} — still holds a copy
   /etc/*.benchat-luks-uninstall.*.bak      crypttab and fstab backups
   Tang itself, on the key host, untouched

 The volume is now openable ONLY with the recovery passphrase printed
 by bind-volume.sh, since the Tang binding is gone:

   sudo cryptsetup luksOpen ${SOURCE_DEV:-<device>} recovered
   sudo mount /dev/mapper/recovered /mnt

 To destroy it for good — irreversible, and it is the copy of your
 database that is at stake:

   sudo cryptsetup luksErase ${SOURCE_DEV:-<device>}
   sudo wipefs -a ${SOURCE_DEV:-<device>}

 If Tang has no other clients, tear it down there too:
   sudo systemctl disable --now tangd.socket
================================================================
EOF
