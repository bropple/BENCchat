# Live test procedure

Written 2026-07-22, after the server rebuild. Replaces the earlier printed
procedure, which assumed a populated database and pre-existing buddy edges —
both gone.

Run it top to bottom on a blank slate, or pick up at any lettered part. Each
step says what to *observe*, not just what to do: a step with no stated
expectation is a step that can't fail.

---

## 0 · Before you start

- [ ] `LOG_LEVEL=debug` in `/etc/bencoscar/bencoscar.env`, service restarted.
      Put it back to `info` when you're done — debug logs screen names and IPs.
- [ ] `journalctl -u bencoscar -f` in its own pane. The unit is **`bencoscar`**,
      not `ras`.
- [ ] Clients fully quit. **The X button does not quit** — it hides to the tray.
      Use the tray menu's "Quit BENCchat", then confirm the process is gone
      (`Get-Process BENCchat` / `pgrep BENCchat`). Every "the reset didn't work"
      on 22 July was this.
- [ ] Client build stamp noted from the sign-on screen. `dev (unknown)` means an
      unstamped build and you can't tell what's in it — rebuild with
      `scripts/build-desktop.sh`.
- [ ] Windows only: Defender exclusion on the folder holding the exe. A
      mid-session quarantine reads as a crash, not as an AV action.

Blank slate:

```bash
# server
sudo ./reset-db.sh                  # destroys every account
benco_admin user add <name>         # re-provision; DISABLE_AUTH=false
```

```powershell
# client, after the process is confirmed dead
.\reset-local-state.ps1             # or ./reset-local-state.sh
```

---

## A · First-run identity  ✅ verified 22 Jul

Regression check now, not new ground.

1. Sign on with a freshly provisioned account on a freshly reset client.
2. **The recovery key screen appears on the FIRST sign-on** and gates you until
   the key is saved. (Before `f955c6f-dirty` it silently didn't — a routing race
   let the roster overwrite it. If this regresses, that's the bug returning.)
3. Journal shows, in order:
   ```
   BENCOKeyDirGetBackupRequest  ×2
   stored an identity backup
   published a device manifest  counter=1 devices=1
   ```
4. Sign off. Sign back on. Journal shows:
   ```
   issued a device challenge
   re-issued the device challenge at sign-on
   BENCOKeyDirAttestResponse → BENCOKeyDirAttestReply
   ```
   and **neither** of these:
   ```
   session could not prove its device (log mode, admitted anyway)
   session closed without answering its device challenge
   ```
   Success is silent by design; the warnings are the signal.

---

## B · 1:1 messaging  ⬜ not re-verified since the rebuild

Two accounts, two machines.

1. Add each other. **The consent flow runs** — the database is blank, so there
   are no grandfathered buddy edges. Approve from the Requests UI.
2. Safety numbers: compare out of band. Both accounts published fresh
   identities on 22 Jul, so everything starts unverified.
3. Send both directions. Look for **🔒 on every message**. A ⚠ means the peer's
   keys weren't found and the send went in the clear.
4. Sign one side off, send to it, sign back on: the offline message arrives with
   its original send time.
5. Send while the peer is signed off *and* has never been fetched — confirms
   key discovery works for an offline peer.

---

## C · Rooms  ⬜ not re-verified since the rebuild

1. Create an encrypted room. You are the owner (pinned, TOFU).
2. Invite the other account. It carries a **signed roster** — room, owner,
   epoch, members — plus chain material.
3. Both send. Both read. Scrollback opens on both sides.
4. Sign the invitee off, send three messages, sign back on: **catch-up** fills
   them in, and reaches back no further than the join.
5. Remove the invitee (owner only). Confirm:
   - the removed side stops being able to read new messages
   - your chain is marked stale and the next send mints a new one
6. Try removing from the **non-owner** side. It must refuse, naming the owner,
   and must **not** cycle that client's chain.

---

## D · Device lifecycle  ⬜ not re-verified since the rebuild

1. Sign the same account in on a second machine → link with the recovery key.
2. Manifest publishes with `devices=2`, counter incremented.
3. Safety number **does not change** — it derives from the identity, not the
   device set. This is the property cross-signing bought.
4. Remove the second device. Confirm rooms it could read are re-keyed.
5. Device transfer: furnish the second machine from the first, confirm history
   arrives marked as transferred.

---

## E · Flip `BENCO_DEVICE_AUTH=enforce`  ⬜ gated

**Do not flip until A·4 has passed for every account with a published device.**
An account that can't attest is locked out, and there is currently **no
`benco_admin` command to clear a device list** — recovery today is `user rm` or
hand-editing SQLite.

```bash
sudo grep -n BENCO_DEVICE_AUTH /etc/bencoscar/bencoscar.env    # expect nothing
echo 'BENCO_DEVICE_AUTH=enforce' | sudo tee -a /etc/bencoscar/bencoscar.env
sudo systemctl restart bencoscar
```

Sign in with every account immediately. Keep the SSH session open: reverting is
`sed -i s/enforce/log/` and a restart.

---

## Traps, all hit on 22 Jul

- **The X button doesn't quit.** Tray → Quit BENCchat.
- **A successful sign-on logs nothing at `info`.** Silence is not evidence.
- **The System log loses notices emitted before the roster mounts** — it's
  session-scoped, lives inside the roster component, and is destroyed on every
  screen change. Not yet fixed. Client-side evidence is unreliable until it is.
- **`letsencrypt.sh` must be re-run after any teardown** that removed
  `/etc/bencoscar/tls`, or the server refuses to start rather than serving
  cleartext.
- **`install.sh` writes a fresh env file**, so hand-tuned values revert.

---

## When something fails

Capture, in this order, before restarting anything:

1. The journal window around it: `journalctl -u bencoscar --since '<time>'`
2. The client's System log (Copy all) — **before** relaunching; it doesn't
   persist.
3. Client stderr, which needs to have been launched under redirection:
   ```powershell
   .\BENCchat.exe 2> "$env:USERPROFILE\benchat.log"
   ```
4. The build stamp from the sign-on screen.

The single most useful question when the client and server disagree: **did the
client send the request at all?** Grep the journal for the food group. A request
that was never sent and a reply that was never accepted look identical from the
UI and have completely different causes.
