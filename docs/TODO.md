# TODO

Living checklist. **Keep it current**: as work lands, tests run, or new problems
surface, update this file in the same change — check items off, add what was
found, re-order when priorities move. A stale TODO is worse than none.

Last updated: 2026-07-23, after the A–D live-test run on build `f955c6f-dirty`.

---

## Blocking / security

- [ ] **Rooms: "no key" on join** (test result C). Top priority — unblocks
      D4/D5. Start with the System-log-durability fix so the client reports
      *why* the key is missing before chasing the distribution path
      (invite → signed roster → per-sender chains).
- [ ] **Device-link attestation ordering.** A freshly-linked device fails its
      first challenge because it is not yet in the manifest when the challenge
      is issued. **Gates the `BENCO_DEVICE_AUTH=enforce` flip** — do not flip
      until this is fixed. Log mode caught it on 2026-07-23.
- [ ] **`benco_admin user devices clear <name>`.** The documented device-loss
      recovery path has no tooling; today it is `user rm` or hand-editing
      SQLite. Wanted before `enforce` regardless.
- [ ] **Block evasion** (test result B1/B2). Server-side: the deny list is not
      consulted on inbound `FeedbagRequestAuthorize` or `ICBMEvilRequest`, so a
      request or a warn reaches someone who blocked you. Fork's permit_deny /
      icbm handlers.

## Client bugs (from 2026-07-23)

- [ ] **B5** — a message to an offline peer errors on the sender
      (`ICBMChannelMsgToHost → ICBMErr`) instead of being stored offline;
      arrives when the peer returns. Likely the E2EE 1:1 send is not setting the
      store-offline TLV.
- [ ] **B3** — the client adds a **nonexistent** screen name (no pending state,
      opens a dead "unencrypted" conversation, sends fail silently). Refuse the
      add, or tell the user the name doesn't exist.
- [ ] **B6** — catch-up plays one notification sound per delivered message
      ("earrape"). Coalesce to a single sound for a batch.
- [ ] **System log durability.** Notices emitted before the roster mounts are
      lost — the log is session-scoped and lives inside the roster component,
      destroyed on every screen change. Hoist the buffer above the component.
      Prerequisite for debugging Rooms.

## Design — decided, not built

- [ ] **Remove unencrypted rooms.** Encryption is not optional elsewhere; rooms
      should not be the exception.
- [ ] **Invite policy as a signed roster field**, tiered
      (owner-only / mods+ / anyone), chosen at room creation. Ship owner-only +
      anyone first; tiers when roles land. See `room-consent-model.md`.
- [ ] **Room roles §7** — owner / senior mod / mod as signed statements.
      Unblocks the tiered invite policy.

## Housekeeping

- [ ] **Refresh the status artifact** — the BENCoscar deploy landed, so its top
      blocking item is stale.
- [ ] **Enable Dependabot + Actions on the BENCoscar fork** (GitHub UI; a fork
      needs both switched on by hand, and Actions is disabled again after 60
      days of inactivity).
- [ ] **Azure Trusted Signing secrets** — clears the Windows Defender
      false-positive at the source. Wiring is already in `build.yml`.

## Deferred — filed, lower priority

- [ ] **Room key retention bound** (`ChainView.Advance`) — makes room forward
      secrecy real; also bounds the unbounded chain-view growth. See
      `SECURITY-FINDINGS.local.md` R8/K4.
- [ ] **1:1 forward secrecy** via rotating X25519 prekeys (no ratchet). Needs
      the device-signs-its-own-rotation delegation step first.
- [ ] **Client-invariant audit** — for each rule the client enforces, does a
      recipient or the server enforce it independently? Anywhere the answer is
      no is where a modified client wins.

## Done (recent)

- [x] Sign-on routing race — first-run key screen no longer lost to the roster
      (`71aaac5`).
- [x] Server rebuild + BENCoscar `d51d966` deployed; both accounts attest.
- [x] `uninstall.sh` for the server (`d51d966`, BENCoscar).
- [x] Server hostname scrubbed from tracked test comments (`f955c6f`).
