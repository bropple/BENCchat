#!/usr/bin/env bash
# bind-volume.sh — LUKS-format a NEW, EMPTY volume and bind it to Tang.
#
# Run this on the BENCoscar host, on a freshly attached block volume that holds
# nothing. Nothing is ever encrypted in place: there is no cryptsetup-reencrypt
# here and there never will be. The volume is formatted, which destroys whatever
# is on it, which is why this script goes to some length to make sure the answer
# to "what is on it" is "nothing".
#
# Root stays unencrypted. It holds nothing that matters, and keeping it plain is
# what lets the machine boot unattended, reach the network, and only then unlock
# the data volume — no initramfs work, no console prompt at 3am.
#
#   sudo ./bind-volume.sh
#   sudo ./bind-volume.sh --tang http://10.0.0.5:7500
#   sudo ./bind-volume.sh --dry-run
#
#   --tang URL         Tang server URL (asked for if omitted)
#   --thumbprint THP   trust this key thumbprint without prompting
#   --device DEV       skip the picker and use this device
#   --mount PATH       mountpoint (default /var/lib/benchat-data)
#   --name NAME        dm-crypt mapper name (default benchat-data)
#   --dry-run          show what would happen, change nothing
#   --yes, -y          skip confirmations (still refuses unsafe devices)
#
# AFTERWARDS: run ./migrate-db.sh. Until you do, nothing guards against the
# volume failing to mount, and an unguarded mountpoint is how you end up with
# SQLite silently creating an empty database on top of it. README.md explains.

set -euo pipefail

TANG_URL="${TANG_URL:-}"
THUMBPRINT="${THUMBPRINT:-}"
DEVICE=""
MOUNT_POINT="${MOUNT_POINT:-/var/lib/benchat-data}"
MAPPER_NAME="${MAPPER_NAME:-benchat-data}"
DRY_RUN=0
ASSUME_YES=0

say()  { printf '\n\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\n\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }
run()  { if [ "$DRY_RUN" -eq 1 ]; then printf '    [dry run] %s\n' "$*"; else "$@"; fi; }

while [ $# -gt 0 ]; do
  case "$1" in
    --tang)       shift; TANG_URL="${1:-}";   [ -n "$TANG_URL" ]   || die "--tang needs a URL" ;;
    --thumbprint) shift; THUMBPRINT="${1:-}"; [ -n "$THUMBPRINT" ] || die "--thumbprint needs a value" ;;
    --device)     shift; DEVICE="${1:-}";     [ -n "$DEVICE" ]     || die "--device needs a path" ;;
    --mount)      shift; MOUNT_POINT="${1:-}";[ -n "$MOUNT_POINT" ]|| die "--mount needs a path" ;;
    --name)       shift; MAPPER_NAME="${1:-}";[ -n "$MAPPER_NAME" ]|| die "--name needs a value" ;;
    --dry-run)    DRY_RUN=1 ;;
    --yes|-y)     ASSUME_YES=1 ;;
    -h|--help)    sed -n '2,28p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)            die "unknown option: $1  (try --help)" ;;
  esac
  shift
done

[ "$(id -u)" -eq 0 ] || die "Run this with sudo:  sudo ./bind-volume.sh"

# --- 0. Tools --------------------------------------------------------------
need_pkgs=()
command -v cryptsetup >/dev/null 2>&1 || need_pkgs+=(cryptsetup)
command -v clevis     >/dev/null 2>&1 || need_pkgs+=(clevis clevis-luks)
command -v lsblk      >/dev/null 2>&1 || need_pkgs+=(util-linux)
command -v curl       >/dev/null 2>&1 || need_pkgs+=(curl)

if [ ${#need_pkgs[@]} -gt 0 ]; then
  say "Installing: ${need_pkgs[*]}"
  if command -v apt-get >/dev/null 2>&1; then
    run apt-get update -qq
    # clevis-systemd carries clevis-luks-askpass, which is what actually answers
    # the unlock prompt for a non-root device at boot. Without it the volume
    # formats and binds fine and then never unlocks unattended.
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y cryptsetup clevis clevis-luks clevis-systemd curl jose
  elif command -v dnf >/dev/null 2>&1; then
    run dnf install -y cryptsetup clevis clevis-luks clevis-systemd curl jose
  elif command -v yum >/dev/null 2>&1; then
    run yum install -y cryptsetup clevis clevis-luks clevis-systemd curl jose
  else
    die "No apt/dnf/yum found — install cryptsetup, clevis, clevis-luks and clevis-systemd manually."
  fi
fi

if [ "$DRY_RUN" -eq 0 ]; then
  command -v cryptsetup >/dev/null 2>&1 || die "cryptsetup is still missing after install."
  command -v clevis     >/dev/null 2>&1 || die "clevis is still missing after install."
  # Checked up front: discovering it after luksFormat would leave a formatted,
  # bound, empty container and a half-finished run.
  command -v mkfs.ext4  >/dev/null 2>&1 || die "mkfs.ext4 is missing (package: e2fsprogs)."
  # Not fatal on its own, but it is the difference between "unlocks on reboot"
  # and "unlocks only when you are watching", so say so loudly now rather than
  # discovering it during an outage.
  if ! systemctl list-unit-files 2>/dev/null | grep -q '^clevis-luks-askpass'; then
    warn "clevis-luks-askpass is not installed (package: clevis-systemd)."
    warn "Without it this volume will NOT unlock automatically at boot."
  fi
fi

# --- 1. Tang server --------------------------------------------------------
if [ -z "$TANG_URL" ]; then
  echo
  echo "Tang server URL — the host you ran tang-install.sh on."
  echo "  e.g. http://10.0.0.5:7500  or  http://tang.internal:7500"
  printf 'Tang URL: '
  read -r TANG_URL
fi
[ -n "$TANG_URL" ] || die "No Tang URL given. Run tang-install.sh on the key host first."

case "$TANG_URL" in
  http://*|https://*) ;;
  *) die "Tang URL must start with http:// or https://  (got: $TANG_URL)
     Plain http is correct and expected: the McCallum-Relyea exchange never
     puts secret material on the wire, so Tang needs no TLS." ;;
esac

say "Checking Tang is reachable at $TANG_URL"
if [ "$DRY_RUN" -eq 0 ]; then
  ADV="$(curl -fsS --max-time 10 "$TANG_URL/adv" 2>/dev/null || true)"
  [ -n "$ADV" ] || die "No advertisement from $TANG_URL/adv

     Check, in this order:
       - tangd.socket is running on the key host
       - the key host's firewall allows THIS machine's address
       - if it is over a VPN/Tailscale, the tunnel is up on this machine
     A Tang server that is unreachable now will also be unreachable at boot."
  echo "    got an advertisement ($(printf '%s' "$ADV" | wc -c) bytes)"

  if command -v jose >/dev/null 2>&1; then
    SEEN_THP="$(printf '%s' "$ADV" \
      | jose fmt -j- -Og payload -Sy -Og keys -Af- 2>/dev/null \
      | jose jwk thp -i- 2>/dev/null | head -n1 || true)"
    [ -n "$SEEN_THP" ] && echo "    key thumbprint : $SEEN_THP"
    if [ -n "$THUMBPRINT" ] && [ -n "$SEEN_THP" ] && [ "$THUMBPRINT" != "$SEEN_THP" ]; then
      die "Thumbprint mismatch.
     expected : $THUMBPRINT
     got      : $SEEN_THP
     Something other than your Tang server is answering. Stop and find out what."
    fi
  fi
fi

# --- 2. Survey the machine's block devices ---------------------------------
say "Block devices on this machine"
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS 2>/dev/null \
  || lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT

# Nothing in the chain under / is ever a candidate, no matter what else it looks
# like. lsblk -s walks UP the tree, which is what catches the whole-disk parent
# of an LVM or dm-crypt root — PKNAME alone returns nothing for a dm device and
# would leave the physical disk looking innocent.
ROOT_SRC="$(findmnt -no SOURCE / 2>/dev/null || true)"
ROOT_CHAIN=""
if [ -n "$ROOT_SRC" ] && [ -b "$ROOT_SRC" ]; then
  ROOT_CHAIN="$(lsblk -nsro NAME "$ROOT_SRC" 2>/dev/null | sed 's|^|/dev/|' | tr '\n' ' ' || true)"
fi

# Returns the reason a device is unusable, or "" if it looks empty and free.
# Anything uncertain counts as unusable: this is the one place in the bundle
# where being wrong destroys data.
why_unsafe() {
  local dev="$1" reasons=() sigs mnts kids anc

  [ -b "$dev" ] || { echo "not a block device"; return; }

  for anc in $ROOT_CHAIN; do
    if [ "$(readlink -f "$dev")" = "$(readlink -f "$anc")" ]; then
      reasons+=("in the chain under /")
      break
    fi
  done

  mnts="$(lsblk -nro MOUNTPOINTS "$dev" 2>/dev/null | tr -s ' \n' ' ' | sed 's/^ *//;s/ *$//' || true)"
  [ -z "$mnts" ] && mnts="$(lsblk -nro MOUNTPOINT "$dev" 2>/dev/null | tr -s ' \n' ' ' | sed 's/^ *//;s/ *$//' || true)"
  [ -n "$mnts" ] && reasons+=("mounted at $mnts")

  kids="$(lsblk -nro NAME "$dev" 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')"
  [ "${kids:-0}" -gt 0 ] && reasons+=("has $kids partition(s)/holder(s)")

  # wipefs with no -a only LISTS signatures. It sees partition tables and
  # filesystem magic alike, which is exactly the union we want to refuse on.
  if command -v wipefs >/dev/null 2>&1; then
    sigs="$(wipefs --noheadings --output TYPE "$dev" 2>/dev/null | tr -s ' \n' ',' | sed 's/,$//' || true)"
  else
    sigs="$(blkid -p -o value -s TYPE "$dev" 2>/dev/null || true)"
  fi
  [ -n "$sigs" ] && reasons+=("signature: $sigs")

  if command -v swapon >/dev/null 2>&1 && swapon --show=NAME --noheadings 2>/dev/null | grep -qx "$dev"; then
    reasons+=("in use as swap")
  fi

  if [ ${#reasons[@]} -gt 0 ]; then
    local out="" r
    for r in "${reasons[@]}"; do out="${out:+$out; }$r"; done
    echo "$out"
  fi
}

# Resolve to a path that survives a reboot. Kernel names (/dev/sdb) get
# reassigned when devices are added or the machine is rebuilt, and crypttab
# pointing at the wrong disk is how a good volume gets formatted by something
# else. Everything written to /etc uses the stable path, even though the human
# picked from the friendly list.
stable_path() {
  local dev target link best="" alt=""
  target="$(readlink -f "$dev")"
  for d in /dev/disk/by-id /dev/disk/by-path; do
    [ -d "$d" ] || continue
    for link in "$d"/*; do
      [ -e "$link" ] || continue
      [ "$(readlink -f "$link")" = "$target" ] || continue
      case "$(basename "$link")" in
        wwn-*|nvme-eui.*|*-part[0-9]*) alt="${alt:-$link}" ;;
        *) [ -z "$best" ] && best="$link" ;;
      esac
    done
    [ -n "$best" ] && break
  done
  echo "${best:-${alt:-}}"
}

if [ -z "$DEVICE" ]; then
  say "Candidate volumes"
  echo "    Unusable devices are listed too, with the reason. If you cannot see"
  echo "    the disk you attached at all, it is not visible to the kernel yet."
  echo

  CAND_DEV=()
  CAND_SAFE=()
  n=0
  while read -r name size type; do
    case "$type" in disk|part) ;; *) continue ;; esac
    n=$((n + 1))
    reason="$(why_unsafe "$name")"
    CAND_DEV+=("$name")
    if [ -z "$reason" ]; then
      CAND_SAFE+=("1")
      printf '  %2d) %-14s %8s  empty, no partition table, not mounted   \033[1;32m[selectable]\033[0m\n' \
        "$n" "$name" "$size"
    else
      CAND_SAFE+=("0")
      printf '  %2d) %-14s %8s  \033[1;31m[REFUSED]\033[0m\n      %s\n' \
        "$n" "$name" "$size" "$reason"
    fi
  done < <(lsblk -dpnro NAME,SIZE,TYPE 2>/dev/null | grep -Ev '^/dev/(loop|sr|ram|zram)' || true)

  # -d lists only top-level devices; partitions of an otherwise-empty disk are
  # worth offering too, since some providers hand you a pre-partitioned volume.
  while read -r name size type; do
    [ "$type" = "part" ] || continue
    n=$((n + 1))
    reason="$(why_unsafe "$name")"
    CAND_DEV+=("$name")
    if [ -z "$reason" ]; then
      CAND_SAFE+=("1")
      printf '  %2d) %-14s %8s  empty partition, not mounted             \033[1;32m[selectable]\033[0m\n' \
        "$n" "$name" "$size"
    else
      CAND_SAFE+=("0")
      printf '  %2d) %-14s %8s  \033[1;31m[REFUSED]\033[0m\n      %s\n' "$n" "$name" "$size" "$reason"
    fi
  done < <(lsblk -pnro NAME,SIZE,TYPE 2>/dev/null | grep -Ev '^/dev/(loop|sr|ram|zram)' || true)

  [ "$n" -gt 0 ] || die "No block devices found at all. Attach the volume first."

  SAFE_COUNT=0
  for s in "${CAND_SAFE[@]}"; do [ "$s" = "1" ] && SAFE_COUNT=$((SAFE_COUNT + 1)); done
  if [ "$SAFE_COUNT" -eq 0 ]; then
    die "Nothing here is safe to format.

     Every device above already has a partition table, a filesystem, or is in
     use. This script only ever formats an empty volume — it will not clear one
     for you. If you are certain a device is scratch, wipe it deliberately
     yourself (wipefs -a) and re-run, having read the device name twice."
  fi

  echo
  printf 'Pick a number: '
  read -r choice
  case "$choice" in
    ''|*[!0-9]*) die "not a number: $choice" ;;
  esac
  [ "$choice" -ge 1 ] && [ "$choice" -le "${#CAND_DEV[@]}" ] || die "no such entry: $choice"
  idx=$((choice - 1))
  if [ "${CAND_SAFE[$idx]}" != "1" ]; then
    die "${CAND_DEV[$idx]} was listed as REFUSED and cannot be selected."
  fi
  DEVICE="${CAND_DEV[$idx]}"
fi

# --- 3. Re-check the chosen device -----------------------------------------
# The picker already judged it, but --device skips the picker entirely and a
# device can change under you between listing and choosing.
[ -b "$DEVICE" ] || die "Not a block device: $DEVICE"
REASON="$(why_unsafe "$DEVICE")"
[ -z "$REASON" ] || die "Refusing to format $DEVICE — $REASON

     This script only formats an empty volume. Nothing is ever encrypted in
     place. Attach a new, blank volume instead."

DEV_SIZE="$(lsblk -dnro SIZE "$DEVICE" 2>/dev/null | head -n1 || echo '?')"
DEV_MODEL="$(lsblk -dnro MODEL "$DEVICE" 2>/dev/null | head -n1 || true)"
STABLE="$(stable_path "$DEVICE")"

if [ -z "$STABLE" ]; then
  warn "No /dev/disk/by-id or /dev/disk/by-path link points at $DEVICE."
  echo "     Kernel names are not stable across reboots, so /etc/crypttab would"
  echo "     be pointing at whatever ends up named $DEVICE next time. On a VM"
  echo "     with one extra volume this is usually fine; it is still a real risk."
  if [ "$ASSUME_YES" -ne 1 ] && [ "$DRY_RUN" -eq 0 ]; then
    printf '     Use the unstable name %s anyway? [y/N] ' "$DEVICE"
    read -r reply
    case "$reply" in y|Y|yes|YES) ;; *) die "cancelled" ;; esac
  fi
  STABLE="$DEVICE"
fi

say "About to DESTROY everything on this volume"
cat <<EOF
    device      : $DEVICE${DEV_MODEL:+  ($DEV_MODEL)}
    size        : $DEV_SIZE
    stable path : $STABLE
    becomes     : /dev/mapper/$MAPPER_NAME
    mounted at  : $MOUNT_POINT
    bound to    : $TANG_URL

    The volume will be LUKS2-formatted. Any data on it is gone. This script
    checked and found it empty, but you are the one who knows what you attached.
EOF

if [ "$DRY_RUN" -eq 1 ]; then
  say "[dry run] nothing changed"
  echo "    Re-run without --dry-run to do it."
  exit 0
fi

if [ "$ASSUME_YES" -ne 1 ]; then
  echo
  printf 'Format %s (%s) and erase everything on it? [y/N] ' "$DEVICE" "$DEV_SIZE"
  read -r reply
  case "$reply" in y|Y|yes|YES) ;; *) die "cancelled — nothing was touched" ;; esac
fi

if cryptsetup isLuks "$DEVICE" 2>/dev/null; then
  die "$DEVICE is already a LUKS container.
     Refusing to reformat it — that would destroy whatever it protects.
     If this is a half-finished run, open it and check before deciding:
         cryptsetup luksDump $DEVICE"
fi

# --- 4. Recovery passphrase ------------------------------------------------
# Tang is a single point of failure until there are two of them. When it is
# down, the machine still boots and SSH still works, so the recovery path is a
# human typing this passphrase — which only works if it exists and is written
# down OFF this machine. It is deliberately never saved to disk here.
say "Generating a recovery passphrase"
if command -v openssl >/dev/null 2>&1; then
  RECOVERY="$(openssl rand -base64 33 | tr -d '\n')"
else
  RECOVERY="$(head -c 33 /dev/urandom | base64 | tr -d '\n')"
fi
[ "${#RECOVERY}" -ge 40 ] || die "Failed to generate a recovery passphrase."

KEYFILE="$(mktemp)"
chmod 600 "$KEYFILE"
cleanup() { rm -f "$KEYFILE"; }
trap cleanup EXIT
printf '%s' "$RECOVERY" > "$KEYFILE"

cat <<EOF

    ================================================================
     RECOVERY PASSPHRASE — write this down NOW, somewhere off this
     machine. Treat it exactly like your BENCchat recovery key.

         $RECOVERY

     It is not stored anywhere. This is the only time it is shown.
     Without it, a Tang outage means the database is unreachable until
     Tang comes back — with it, you can unlock by hand over SSH.
    ================================================================
EOF

if [ "$ASSUME_YES" -ne 1 ]; then
  echo
  printf 'Type SAVED once you have written it down: '
  read -r ack
  [ "$ack" = "SAVED" ] || die "cancelled — nothing was touched"
fi

# --- 5. Format, bind, mount ------------------------------------------------
say "LUKS2-formatting $STABLE"
cryptsetup luksFormat --type luks2 --batch-mode --key-file "$KEYFILE" "$STABLE"

say "Opening as /dev/mapper/$MAPPER_NAME"
cryptsetup luksOpen --key-file "$KEYFILE" "$STABLE" "$MAPPER_NAME"

say "Creating the filesystem"
mkfs.ext4 -q -L benchat-data "/dev/mapper/$MAPPER_NAME"

say "Binding to Tang at $TANG_URL"
if [ -n "$THUMBPRINT" ]; then
  CFG="{\"url\":\"$TANG_URL\",\"thp\":\"$THUMBPRINT\"}"
  clevis luks bind -y -d "$STABLE" -k "$KEYFILE" tang "$CFG"
else
  CFG="{\"url\":\"$TANG_URL\"}"
  echo "    clevis will show the server's key thumbprint and ask you to trust it."
  echo "    It should match what tang-install.sh printed on the key host."
  if [ "$ASSUME_YES" -eq 1 ]; then
    clevis luks bind -y -d "$STABLE" -k "$KEYFILE" tang "$CFG"
  else
    clevis luks bind -d "$STABLE" -k "$KEYFILE" tang "$CFG"
  fi
fi

say "Bound key slots"
clevis luks list -d "$STABLE" || true

# --- 6. crypttab and fstab -------------------------------------------------
# _netdev: the unlock needs the network, so systemd must order this after
#   networking rather than treating it as a local disk.
# nofail: a Tang outage must not stop the machine booting. If it did, the box
#   would be unreachable by SSH exactly when you need to fix it.
#
# nofail is only safe BECAUSE migrate-db.sh adds RequiresMountsFor= to the
# BENCoscar unit. That is what turns "boots fine, mount missing" into "boots
# fine, service refuses to start" instead of "boots fine, service starts on an
# empty directory and invents a fresh database". Do not use one without the
# other.
CRYPTTAB_LINE="$MAPPER_NAME $STABLE none _netdev,nofail"
FSTAB_LINE="/dev/mapper/$MAPPER_NAME $MOUNT_POINT ext4 defaults,_netdev,nofail,x-systemd.device-timeout=30 0 2"

say "Writing /etc/crypttab and /etc/fstab entries"
STAMP="$(date +%Y%m%d-%H%M%S)"
touch /etc/crypttab
cp -a /etc/crypttab "/etc/crypttab.benchat-luks.$STAMP.bak"
cp -a /etc/fstab    "/etc/fstab.benchat-luks.$STAMP.bak"
echo "    backups: /etc/crypttab.benchat-luks.$STAMP.bak, /etc/fstab.benchat-luks.$STAMP.bak"

if grep -qE "^[[:space:]]*$MAPPER_NAME[[:space:]]" /etc/crypttab; then
  echo "    crypttab already has an entry for $MAPPER_NAME — replacing it"
  grep -vE "^[[:space:]]*$MAPPER_NAME[[:space:]]" /etc/crypttab > /etc/crypttab.new
  mv /etc/crypttab.new /etc/crypttab
fi
printf '# BENCchat encrypted data volume (scripts/benchat-luks)\n%s\n' "$CRYPTTAB_LINE" >> /etc/crypttab

if grep -qE "^[^#]*[[:space:]]${MOUNT_POINT//\//\\/}[[:space:]]" /etc/fstab; then
  echo "    fstab already has an entry for $MOUNT_POINT — replacing it"
  grep -vE "^[^#]*[[:space:]]${MOUNT_POINT//\//\\/}[[:space:]]" /etc/fstab > /etc/fstab.new
  mv /etc/fstab.new /etc/fstab
fi
printf '# BENCchat encrypted data volume (scripts/benchat-luks)\n%s\n' "$FSTAB_LINE" >> /etc/fstab

mkdir -p "$MOUNT_POINT"
systemctl daemon-reload

# --- 7. Prove the Tang unlock actually works -------------------------------
# Binding succeeding does not prove unlocking works. Close it and let clevis
# open it from scratch, which is the same path the boot will take. Finding out
# here beats finding out after a reboot.
say "Testing the Tang unlock (closing and reopening without the passphrase)"
cryptsetup luksClose "$MAPPER_NAME"
if ! clevis luks unlock -d "$STABLE" -n "$MAPPER_NAME"; then
  warn "clevis could not unlock the volume from Tang."
  echo "     The volume is fine and your recovery passphrase still opens it:"
  echo "         cryptsetup luksOpen $STABLE $MAPPER_NAME"
  echo "     But it will NOT come up on its own. Check Tang's reachability and"
  echo "     firewall from this host, then re-run this script."
  die "Automatic unlock is not working — fix it before migrating the database."
fi
echo "    unlocked from Tang with no passphrase: OK"

say "Mounting $MOUNT_POINT"
mount "$MOUNT_POINT"
findmnt -no TARGET,SOURCE,FSTYPE "$MOUNT_POINT" || die "Mount did not take."
chmod 700 "$MOUNT_POINT"

cat <<EOF

================================================================
 Encrypted volume is up.

   device      : $STABLE
   mapper      : /dev/mapper/$MAPPER_NAME
   mounted at  : $MOUNT_POINT
   unlocked by : $TANG_URL  (no passphrase needed)

 NOT DONE YET. The database is still on unencrypted storage, and
 nothing yet stops BENCoscar starting when this mount is missing.

   sudo ./migrate-db.sh

 That moves the database here AND adds the RequiresMountsFor= guard
 to the BENCoscar unit. Without the guard, a failed mount leaves an
 empty directory, SQLite creates a fresh database on it, the server
 comes up healthy with no accounts, sign-on reports a wrong password,
 and the next backup overwrites a good file with an empty one.

 Reboot once after migrating, and confirm the volume came back on its
 own before you trust it.

 Your recovery passphrase was shown above and is stored nowhere. If
 you did not write it down, start over now: this is the cheapest
 moment to redo it.
================================================================
EOF
