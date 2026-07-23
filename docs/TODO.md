# TODO

Living checklist. **Keep it current**: as work lands, tests run, or new problems
surface, update this file in the same change — check items off, add what was
found, re-order when priorities move. A stale TODO is worse than none.

Last updated: 2026-07-22 — System-log durability fixed, block-evasion B1 fixed
(BENCoscar), Rooms "no key" fixed in code (chain-request round-trip + bundle/
readable fixes) pending live re-test, at-rest encryption test filed.

---

## Blocking / security

- [~] **Rooms: "no key" on join** (test result C). **Fixed in code; needs a
      two-client live re-test** (now that the System log is durable, the joiner's
      refusal reason will survive if anything is still off). Uncommitted.
      What landed (all four ranked causes addressed):
      1. **Empty invite bundle** → `ChainBundleFor` now includes our *live*
         outbound chain at its current index, not only chains with a `seen`
         entry, and `CreateEncryptedRoom` mints that chain at creation. An invite
         issued before the owner has spoken now carries a usable key.
         (`internal/client/room_e2ee.go`, `app_room_e2ee.go`.) Tests:
         `TestChainBundleCarriesUnsentOutboundChain` (+ the forward-secrecy
         counterpart `TestChainBundleWithheldPriorMessages`).
      2. **One-shot broadcast** → a **chain-request** round-trip: a joiner holding
         no readable chain (empty bundle, or a message under an unknown chain)
         asks the sender to re-broadcast; the member re-distributes on request.
         New BENCO 1:1 message `\x1bBENCO-CHAINREQ` (client-to-client over ICBM,
         not a server SNAC — no OSCAR wire-format change). Throttled both ways.
      3. **Distribution gate** → `ensureRoomChainDistributed` now broadcasts on
         `!chainShared` rather than "freshly minted", so a chain minted at create
         still goes out on the first send.
      4. **Reporting bug** → `RoomReadable` reflects chain material (`out` or any
         view), not only the dead shared-key flag. Test:
         `TestRoomReadableReflectsChainState`.
      All module tests + `-race` on the room/chain suite pass. **Re-run procedure
      C with two clients to confirm end-to-end; then D4/D5 unblock.**
      Original diagnosis (ranked causes), kept for reference:
      1. **Empty invite bundle.** The chain is minted only on the owner's first
         *send* (`CreateEncryptedRoom`, `app_room_e2ee.go:667-670`: "minted and
         broadcast on the first send"). Create-then-invite — the natural flow, and
         exactly procedure C's order — issues the invite while `rk.views` is
         empty, so `ChainBundleFor` (`internal/client/room_e2ee.go:1181`) returns
         `[]` and the joiner installs no chain (`AcceptRoomInvite`/
         `adoptInviteState`, `app_room_e2ee.go:1169-1171`). This is the most
         likely cause and matches the symptom exactly.
      2. **One-shot broadcast, no retry, no request.** The owner broadcasts the
         chain once (`fresh` gate, `room_e2ee.go:1303-1304`); accept never asks
         for it (`app_room_e2ee.go:1152-1155`). Any miss is permanent — the only
         "recovery" (`RefreshPeerKeys`) fetches identity keys, not chains. There
         is no chain-request message type.
      3. **Ordering/keys gates.** `JoinRoom` runs before `adoptInviteState`
         populates `a.members` (`app_room_e2ee.go:1144` vs `1151`), so a broadcast
         in that window is dropped as "from a non-member" (`room_e2ee.go:1390`);
         owner-side skips a member whose `PeerKeys` it lacks (`room_e2ee.go:1313`).
      4. **Reporting bug (layered on top).** `RoomReadable` returns only
         `rk.hasCurrent` (`room_e2ee.go:191`), which only the *shared-key* path
         sets — chain rooms never set it, so `RoomSecurityInfo.Readable` is false
         for every chain room even once chains are present, and would mis-report
         the owner too. Likely the source of the literal "no key" indicator.
      Fix direction is a **design choice** (mint-at-create vs re-send-on-invite
      vs add a chain-request SNAC) — decide before building. See
      `room-consent-model.md`.
- [ ] **Device-link attestation ordering.** A freshly-linked device fails its
      first challenge because it is not yet in the manifest when the challenge
      is issued. **Gates the `BENCO_DEVICE_AUTH=enforce` flip** — do not flip
      until this is fixed. Log mode caught it on 2026-07-23.
- [ ] **`benco_admin user devices clear <name>`.** The documented device-loss
      recovery path has no tooling; today it is `user rm` or hand-editing
      SQLite. Wanted before `enforce` regardless.
- [~] **Block evasion** (test result B1/B2).
      - **B1 (buddy request) — FIXED** in BENCoscar. `RequestAuthorizeToHost`
        (`foodgroup/feedbag.go`) relayed the request with no deny check, unlike
        `ChannelMsgToHost`/`EvilRequest`. Now gates on
        `relationshipFetcher.Relationship` and silently drops when either party
        blocks the other; covered by two new cases in
        `TestFeedbagService_RequestAuthorizeToHost`. **Uncommitted, undeployed.**
      - **B2 (warn) — likely a non-bug.** `EvilRequest` (`foodgroup/icbm.go:495`)
        has gated warns on `BlocksYou || YouBlock` since Dec 2024 (well before
        the 23 Jul test), and `trackWarn` additionally needs a prior message from
        the target — which a blocker can't send. Re-confirm live: probably the
        warner's optimistic client display, or the block edge wasn't actually set
        on the fresh DB at test time. No code change until reproduced.

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
- [x] **System log durability.** ~~Notices emitted before the roster mounts are
      lost — the log is session-scoped and lives inside the roster component,
      destroyed on every screen change.~~ Hoisted the buffer into a new
      `frontend/src/syslog.ts` module: a single global subscription in `main.ts`
      records server notices regardless of the mounted screen, and the roster
      renders/subscribes rather than owning it. Also fixed the latent
      `state:event` listener leak — the roster re-subscribed on every mount and
      never detached (`Bridge.onStateEvent` now returns an unsubscribe, called in
      `destroy`). Prerequisite for debugging Rooms — **now cleared.**

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
- [ ] **At-rest encryption test.** Verify the on-disk SQLite database is actually
      unreadable from a leaked block-storage snapshot — the whole point of the
      LUKS volume (and the `uninstall.sh` mountpoint guard). A real test, not an
      assertion: take a copy of the raw device/backing file with the volume
      locked and confirm account rows / argon2id material / message blobs don't
      appear in it. Ties into the unattended-unlock research (Clevis+Tang vs OCI
      Vault) — the test is what proves whichever unlock path chosen still leaves
      the data sealed when the VM is off.
- [ ] **PROXY protocol support in BENCoscar, BEFORE any reverse proxy / Cloudflare
      Spectrum goes in front.** `IPRateLimiter` (`server.go:737`) keys on
      `conn.RemoteAddr()`, which is the real client IP *only* because TLS
      terminates in-process with nothing in front today. The moment a stream
      proxy sits in front, every connection's `RemoteAddr()` becomes the proxy's
      IP and the per-IP login-flood guard silently collapses to one shared global
      bucket. Fix: have the proxy (HAProxy / nginx stream, or Spectrum if it
      supports it) send the PROXY protocol header, and parse it in BENCoscar's
      accept path to key the limiter off the carried IP instead of `RemoteAddr()`.
      **Order matters:** ship and verify PROXY support first — two clients from
      different real IPs behind the proxy must get independent buckets — *then*
      deploy the proxy. Doing it after leaves a window where the guard is
      degraded with no signal that it happened. (No proxy is planned today; this
      is a guard against a future one.)
- [ ] **Redact client IPs in BENCoscar's logs** (recommended over a proxy for
      the IP-privacy goal). `WithIP` (`server/oscar/middleware/logger.go:24`)
      stores the raw `RemoteAddr` in context; every log line pulls it, at info
      too — `"user signed on"` / `"user disconnected"` carry `ip=` even with
      debug off. Hash (keyed HMAC) or truncate the `ip` attribute in
      `NewLogger`'s existing `ReplaceAttr` hook — one chokepoint, covers every
      level. The rate limiter reads a *separate* `ip` variable
      (`server.go:206/419`), so this does NOT touch the flood guard. Directly
      closes the log half of `SECURITY-FINDINGS` S3, with no proxy and no
      conflict with the PROXY-protocol item.
- [ ] **If nginx / a stream proxy IS deployed** (for reasons other than log
      privacy — hiding the origin IP from clients, volumetric DDoS): it must be
      `stream`-module PASSTHROUGH, never TLS-terminating (that is the stunnel
      model the project rejected — TLS stays native in BENCoscar). It conflicts
      with the two items above: a passthrough proxy hides IPs from BENCoscar
      (breaking the app rate limiter) OR carries them via PROXY protocol
      (re-exposing them in BENCoscar's logs) — pick one, or move per-IP limiting
      into nginx (`limit_conn`/`limit_req` on `$remote_addr`) and let BENCoscar
      stay IP-blind. **Whatever is chosen, add the nginx setup to the deploy
      script (`scripts/benco-deploy/install.sh`) so it is provisioned with the
      server and cannot be forgotten on a rebuild** — a hand-configured proxy
      that a `reset`/reinstall drops would silently un-harden the deployment.

## Done (recent)

- [x] Sign-on routing race — first-run key screen no longer lost to the roster
      (`71aaac5`).
- [x] Server rebuild + BENCoscar `d51d966` deployed; both accounts attest.
- [x] `uninstall.sh` for the server (`d51d966`, BENCoscar).
- [x] Server hostname scrubbed from tracked test comments (`f955c6f`).
