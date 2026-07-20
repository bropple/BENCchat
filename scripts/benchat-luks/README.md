# BENCchat encrypted data volume (LUKS + Tang)

**Optional.** Nothing in BENCchat or BENCoscar requires this. It puts the OSCAR
database on a separate LUKS-encrypted volume that unlocks automatically from a
**Tang** server you run somewhere else, so a leaked block-storage snapshot is not
a readable database.

Read "What this actually protects" before deciding you want it. The prize here
is narrower than "encrypt the database" sounds, and the design document
(`BENCoscar/docs/at-rest-encryption.md`) is blunt that this is the
lowest-value security item on the list.

**These scripts have not been run end to end against a real deployment yet.**
They are written to stop and complain rather than to be clever, every
destructive step has a `--dry-run`, and no step deletes a database. Go slowly
the first time.

## Does BENCoscar need changing?

**No.** The database sits on an encrypted volume and the application never
knows. No code change, no config change beyond one path.

There is exactly one thing this bundle adds to the BENCoscar systemd unit, and
it is not a feature — it is a guard against the failure mode described in the
next section. It goes in a drop-in file, so the packaged unit is never edited
and `uninstall.sh` is one `rm`.

## The single most important thing in this bundle

If the encrypted volume fails to mount, the mountpoint is still there. It is an
empty directory. **SQLite will cheerfully create a brand new database on it.**

What that looks like from the outside:

- the machine boots fine
- BENCoscar starts fine and reports healthy
- there are no accounts, so the first sign-on says the password is wrong
- nothing errors, nothing logs anything alarming
- the next nightly backup **overwrites a good snapshot with the empty one**

That last line is why this matters more than the encryption does. A failed
mount is recoverable; a failed mount plus a backup rotation is not.

So `migrate-db.sh` adds this to the BENCoscar unit:

```ini
[Unit]
RequiresMountsFor=/var/lib/benchat-data
```

which makes the **service** refuse to start when the volume is absent, even
though the **machine** boots perfectly well without it. That distinction is
deliberate and load-bearing:

| | with the guard | without it |
|---|---|---|
| Tang down, machine boots | yes, SSH works | yes, SSH works |
| Volume mounted | no | no |
| BENCoscar starts | **no — refuses** | yes |
| Result | visible outage you can fix | silent empty database |

`prove the guard works` is a step in `migrate-db.sh`'s closing output. Do it.

### Why `nofail` and `_netdev` are safe here

`/etc/crypttab` and `/etc/fstab` both get `_netdev` and `nofail`:

- **`_netdev`** — the unlock needs to reach Tang, so systemd must order the
  device after networking rather than treating it as a local disk.
- **`nofail`** — a Tang outage must not stop the machine booting. If it did, the
  box would be unreachable by SSH at exactly the moment you need to fix it.

`nofail` on a volume holding a database would normally be reckless: it converts
"won't boot" into "boots without the data". It is only safe **because** of
`RequiresMountsFor=` above. Use one without the other and you have built the
silent-empty-database machine on purpose.

## What this actually protects

Be honest about this, because the intuitive version is wrong.

### What it does not do

**A stolen snapshot is not undecryptable.** Anyone holding the snapshot can
decrypt it if they also have network reach to your Tang server — because that is
precisely what the running machine does, unattended, every boot. There is no
version of automatic unlock where this is not true.

And if the VPS reaches Tang over a VPN or Tailscale, **the snapshot contains the
VPN credentials too**. Anything the machine can present without a human present,
the snapshot contains. Restoring the image somewhere else and letting it boot is
a complete attack.

**It does not protect message content.** Message bodies are already end-to-end
encrypted — BENCchat seals them before they are sent, and the server stores
ciphertext it cannot read. Identity backups are already encrypted under the
user's recovery key. Backups are already asymmetric (`scripts/backup-db.sh`),
so the server can create backups it cannot read.

What is left in plaintext, and therefore what this actually covers, is
**metadata**: screen names, buddy lists, profiles, and who exchanged messages
with whom and when. Worth something. Not what most people picture.

**It does not protect against shell access to the running machine.** Explicitly
out of scope. A machine that can unlock itself can be made to hand over what it
unlocked.

### What it does do

Three real properties, none of which a key stored on the disk can give you:

- **Revocability.** Rotate Tang's keys and every volume bound to them stops
  unlocking — including a copy someone else is holding. A leaked snapshot goes
  from "readable forever" to "readable until you notice and revoke". That is the
  whole pitch, and it is a genuinely different thing from what an on-disk key
  offers, which is nothing.
- **Detectability.** Tang logs requests. An unlock from an address that is not
  your server is visible, and is the signal that tells you to revoke.
- **No offline attack.** The disk on its own yields nothing. An attacker who
  grabs a snapshot and no network path has a brick.

Frame the whole thing as **leaked until you notice and revoke**, not **leaked
forever**. If that trade is not worth the operational weight of running a second
machine, do not do this — that is a reasonable conclusion.

## Where to run Tang

Tang has to live somewhere that is **not** the machine it unlocks.

**Do not run Tang on the BENCoscar host.** It would work, and it would protect
nothing at all: the key and the lock would be in the same snapshot. Anyone who
took the disk would have both halves. This is the single mistake that makes the
whole exercise theatre.

That leaves a real problem, and it has no clean answer:

- **Tang at home, port forwarded.** Simple, and means exposing a port on your
  home connection to the internet. Most people setting this up specifically do
  not want that.
- **Tang at home, over a VPN or Tailscale the VPS dials out to.** No inbound
  exposure. But re-read the caveat above: the VPS holds credentials for that
  tunnel unattended, so **the snapshot contains them**. This narrows the attack
  from "anyone on the internet" to "anyone who restores your snapshot and lets it
  boot", which is an improvement and not a solution.
- **A second small VPS.** No home exposure at all, cheap, and different from the
  BENCoscar host in the way that counts as long as it is a **different provider**
  — Tang on a second Oracle instance still leaves Oracle holding both halves.

There is no configuration that removes the fundamental point: unattended unlock
means the machine holds everything needed to unlock. Pick the option whose
failure you would rather explain.

### Two Tang servers, later

One is enough to start. With one, a Tang outage means the volume does not mount
and — thanks to the guard — BENCoscar does not start until you fix it or unlock
by hand.

The fix is a **second** Tang host with an `sss` (Shamir) policy at threshold
`t=1`, so either server can satisfy the unlock. Note what this is: *redundancy*,
not fallback. Clevis does support a passphrase fallback, but it is interactive —
a human at a boot prompt, which is useless on a headless VM at 3am.

Adding the second one later re-binds a key slot and does not re-encrypt
anything:

```bash
clevis luks bind -d /dev/disk/by-id/... sss \
  '{"t":1,"pins":{"tang":[{"url":"http://tang-a:7500"},{"url":"http://tang-b:7500"}]}}'
```

## Install

### 1. On the key host (Pi, home server, second VPS)

```bash
sudo ./tang-install.sh
```

Installs Tang, points `tangd.socket` at port 7500, forces key generation and
prints the **key thumbprint** — write it down, `bind-volume.sh` shows you one to
compare against. It ends with firewall guidance, which is the entire security
boundary for Tang: it has no authentication, so restrict it to the BENCoscar
host's address and nothing else.

### 2. Attach a new, empty block volume to the BENCoscar host

Nothing is ever encrypted in place. There is no `cryptsetup-reencrypt` in this
bundle and there never will be — it is the operation most likely to end a
deployment. A new volume is a few clicks and a fresh start.

Size it for the database plus room to grow; the OSCAR database is small.

### 3. On the BENCoscar host

```bash
sudo ./bind-volume.sh --dry-run     # look first
sudo ./bind-volume.sh
```

It asks for the Tang URL, checks Tang answers **before** touching anything,
shows you `lsblk`, then offers a numbered list of block devices annotated with
what it found on each:

```
   1) /dev/sdb        50G  empty, no partition table, not mounted   [selectable]
   2) /dev/sda       200G  [REFUSED]
        in the chain under /; mounted at /boot /; has 3 partition(s)/holder(s)
```

Devices it judges unsafe stay in the list with the reason, but cannot be picked
— seeing your root disk listed and refused is more reassuring than not seeing it
at all. You pick a number; it resolves that to a stable `/dev/disk/by-id/...`
path internally, because kernel names are not stable across reboots and
`/etc/crypttab` must not be pointing at whatever ends up called `/dev/sdb` next
time.

Then one plain confirmation naming the device and its size, and it:

1. prints a **strong random recovery passphrase** and makes you acknowledge it
2. LUKS2-formats the volume with that passphrase
3. `clevis luks bind`s it to Tang (showing the thumbprint to compare)
4. makes an ext4 filesystem
5. writes the `crypttab` and `fstab` entries
6. **closes the volume and reopens it from Tang with no passphrase** — proving
   the boot-time path works, rather than assuming it
7. mounts it

### 4. Move the database

```bash
sudo ./migrate-db.sh --dry-run
sudo ./migrate-db.sh
```

Stops BENCoscar, copies the database with `sqlite3 .backup` (consistent, and
verifiable), runs `PRAGMA integrity_check`, compares account counts between
original and copy, and **only then** renames the original to
`oscar.sqlite.pre-luks-<timestamp>`. The original is never deleted — delete it
yourself when you are satisfied. Re-running is safe: if the copy is already
there it says so and moves on to the guard.

It then installs the drop-in with `RequiresMountsFor=` and `DB_PATH=`, restarts
the service, and prints the four commands that prove the guard actually works.
Run them.

### 5. Reboot once

Confirm the volume unlocks from Tang on its own and the service comes up. A
setup that has never survived a reboot is not set up.

## Recovery: Tang is down and the volume will not mount

This is the expected failure, not an exotic one, and it is survivable because
**the machine is still up and SSH still works** — that is what `nofail` bought.
BENCoscar is refusing to start, which is the guard doing its job.

Fix Tang if you can. If you cannot, unlock by hand with the recovery passphrase
`bind-volume.sh` printed at setup:

```bash
# preferred — if Tang is reachable again but something else is stuck
sudo clevis luks unlock -d /dev/disk/by-id/... -n benchat-data

# Tang is gone: unlock with the escrowed passphrase
sudo cryptsetup luksOpen /dev/disk/by-id/... benchat-data
sudo mount /var/lib/benchat-data
sudo systemctl start ras            # or whatever your unit is called
```

Diagnosing:

```bash
systemctl status 'systemd-cryptsetup@benchat\x2ddata.service'
journalctl -u clevis-luks-askpass -b
curl -fsS http://your-tang-host:7500/adv | head -c 80   # from the OSCAR host
systemctl status ras                # should say a required mount is missing
```

**Store the recovery passphrase like your BENCchat recovery key** — off the
machine, somewhere you will still have it when the machine is the thing that is
broken. It is printed exactly once and written to disk nowhere, because writing
it to the volume's own host would defeat the point.

Note that Tang *reachable but erroring* is not the same as Tang *unreachable*,
and the second case is the one that is well understood. If unlock fails while
`curl /adv` succeeds, suspect key rotation on the Tang host before anything else.

## Revoking

The property this whole bundle exists for. On the Tang host:

```bash
cd /var/db/tang
# a leading dot makes a key advertised-no-more but still usable for existing
# bindings; MOVING it away is what actually revokes
sudo mv ./ABCdef123.jwk /root/revoked-ABCdef123.jwk
sudo mv ./XYZghi456.jwk /root/revoked-XYZghi456.jwk
sudo systemctl restart tangd.socket
```

Every volume bound to those keys now fails to unlock — including a leaked copy,
which is the point, and including yours, which is why you re-bind immediately:

```bash
# on the BENCoscar host, while the volume is still open
sudo clevis luks unbind -d /dev/disk/by-id/... -s <old-slot>
sudo clevis luks bind   -d /dev/disk/by-id/... tang '{"url":"http://tang:7500"}'
```

Do this while the volume is unlocked and you have the recovery passphrase to
hand. Revoking is a fire drill worth rehearsing once, not first performing
during an actual incident.

## Uninstall

```bash
sudo ./uninstall.sh --dry-run
sudo ./uninstall.sh
```

Copies the database back to unencrypted storage (verified before anything is
unmounted), removes the mount guard, takes out the `crypttab`/`fstab` entries,
unbinds from Tang and closes the volume.

It does **not** wipe the LUKS container — your data is still in there, and after
the unbind only the recovery passphrase opens it. The closing output tells you
how to destroy it deliberately if that is what you want.

## Notes

- **Ubuntu/arm64 on `initramfs-tools` is untested and deliberately irrelevant.**
  This design puts the database on a *data* volume that unlocks after the OS is
  already up, so no initramfs work is needed and the whole "does clevis work
  before root mounts" question never arises. That is the main reason the design
  looks like this.
- **`clevis-systemd` is required**, not optional. It provides
  `clevis-luks-askpass`, which is what actually answers the unlock prompt for a
  non-root device at boot. Without it the volume formats and binds fine and then
  only ever unlocks when you are watching. `bind-volume.sh` warns if it is
  missing.
- **Tang needs no TLS.** In the McCallum-Relyea exchange the client's secret is
  never shared with the server and never crosses the network. Tang is not a key
  escrow — it holds material useless without the client's token, and the client
  holds a token useless without Tang. `http://` is correct here.
- **Update your backup timer** if it names the old database path.
  `scripts/backup-db.sh` reads whatever path you hand it, and a timer installed
  before the migration will still be pointed at the pre-migration file.
- **The mountpoint is not the service's `StateDirectory`.** The default
  `/var/lib/benchat-data` is deliberately separate from anything systemd manages
  for the unit, so `StateDirectory=` and the mount do not fight over the same
  directory.
