# Live test procedure

Written 2026-07-22, after the server rebuild. Replaces the earlier printed
procedure, which assumed a populated database and pre-existing buddy edges —
both gone.

Run it top to bottom on a blank slate, or pick up at any lettered part. Each
step says what to *observe*, not just what to do: a step with no stated
expectation is a step that can't fail.

---

## Re-test after the 2026-07-23 fixes

A batch of fixes landed after the 23 Jul run — Rooms key distribution, device-
link attestation under enforce, block-evasion B1, the sound backlog, and the
System-log durability that underpins all client-side observation. This is the
targeted pass to confirm them. Run the referenced lettered parts, but watch for
the *new* expected behaviour called out here.

**Deploy the fixes first, or you are testing the old build.** These are
committed, not deployed:
- **Server:** on the VPS, pull BENCoscar and rebuild/redeploy so the commits
  through `d611bae` are running (`fd97919` attestation, `cb74d89` B1,
  `d611bae` devices-clear). Confirm the running binary is the new one before
  starting.
- **Clients:** rebuild with `scripts/build-desktop.sh` so the sign-on screen
  shows a stamp at or past `fd758d4`. `dev (unknown)` means you rebuilt wrong.

**The System log is now durable** (`syslog.ts`) — notices from before the roster
mounts survive, so for the first time the client's own account of a failure is
trustworthy. Use "Copy all" from the System Log freely; it no longer evaporates
on a screen change.

### R1 · Rooms "no key" on join  (was test result C — the priority)

Run **Part C**, but specifically in the order that used to fail:

1. One account creates an encrypted room and **says nothing yet**.
2. It invites the second account **before ever sending a message**.
3. The invitee accepts. **It must be able to read the room** — `RoomSecurityInfo`
   no longer reports "no key" for a chain room, and the invite now carries the
   owner's live chain even though the owner hasn't spoken.
4. The owner sends its first message. The invitee reads it. The invitee must
   **not** be able to read anything from before it joined.
5. Now the reverse-recovery path: have the invitee join a room where the owner's
   chain didn't reach it (or force it — remove/rejoin). A message it can't read
   should trigger a **chain request**, and the sender should re-broadcast so it
   becomes readable rather than staying stuck. There is no more one-shot-and-lost
   broadcast.

If the joiner still reports no key, the durable System log now says *why* — copy
it. Then D4/D5 (room re-key on device removal) unblock.

### R2 · Device-link attestation under enforce  (was the enforce blocker)

This is the fix that lets **Part E** happen at all. Do it with a real second
device.

1. In **log** mode first, run **Part D1**: link a second device with the recovery
   key. It must end up **able to send**, not merely admitted.
2. Then flip to **enforce** (Part E) and link a *third* device, or remove and
   re-link the second. Under enforce the linking device must still get in.
   - Journal shows, briefly, `session has not proven its device; degraded until
     it does` — expected: the device answered before it published its manifest.
   - Then a successful `BENCOKeyDirAttestReply`, and the session **stays up**.
     The old bug disconnected here.
   - The client must **not** show "This device was removed… link again" during
     the linking window. That notice now fires only if the device believes it is
     already enrolled — a genuine problem, not the link in progress.
3. If a device does get stuck degraded, recovery is now tooled:
   `benco_admin user devices clear <name>` (see Part E note) resets it to
   password auth. Confirm that command works end to end while you have enforce on.

### R3 · Block evasion B1  (was test result B1)

From **Part B**, with the deny list in play:

1. Account X blocks account Y (Settings → blocked users, or the block action).
2. Y sends X a **buddy / connection request**.
3. X must **not** receive it. Before the fix the request reached the blocker.
   Y sees nothing that reveals the block (it looks like X is simply offline).

(B2 — a *warn* landing on a blocker — is believed already handled server-side;
if you can, confirm a warn from Y to X is refused too, but it is not the target
of this pass.)

### R4 · Re-observe B5 and B3 with the durable log

These two had their stated causes disproven; the point now is to see what, if
anything, is actually there, with a log that no longer lies.

- **B5:** send to a peer who is signed off. Watch whether the client reports a
  failure (it should, via a notice) and whether the message is **stored and
  delivered when the peer signs back on**. If it errors, capture the journal —
  the likely real cause is the consent gate (the sender not yet authorised),
  not offline storage. Note whether the two accounts had accepted each other
  first.
- **B3:** open a New IM to a **made-up** screen name and send. The failure
  should now be **visible** (a notice), not silent. Whether to also refuse the
  add up front is deferred — the client can't tell an offline real name from a
  fake one — so just confirm the send failure is surfaced.

### R5 · Sound backlog (B6)

1. Sign the second account off.
2. From the first, send it several messages (5+).
3. Sign the second back on. The offline backlog arrives at once, and there must
   be **one** receive chime for the batch, not one per message.
4. Then send a single live message a few seconds later: it chimes on its own —
   the coalescing window is short enough that ordinary conversation is unaffected.

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
An account that can't attest is locked out. Recovery is now
`benco_admin user devices clear <name>`, which resets the account's whole
encryption identity (clears every device and the backup) so it falls back to
password auth and can re-bootstrap — keep an operator with socket access on hand
in case an account can't attest after the flip.

**New since 2026-07-23 — verify the linking fix under enforce before trusting
it.** The link ordering deadlock (a fresh device couldn't publish to enrol, and
was torn down on its first failed attest) is fixed: a failed attest now degrades
rather than closes, publish is allowed while unattested, and the client
re-answers once enrolled. Under enforce, run part **D1** with a real second
device: it must link with the recovery key and end up able to send — not sit
degraded. Watch the journal for `session has not proven its device; degraded
until it does` (expected briefly during the link) followed by a successful
`BENCOKeyDirAttestReply`, and confirm it does **not** disconnect.

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
