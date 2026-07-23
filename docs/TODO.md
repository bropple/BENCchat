# TODO

Living checklist. **Keep it current**: as work lands, tests run, or new problems
surface, update this file in the same change — check items off, add what was
found, re-order when priorities move. A stale TODO is worse than none.

Last updated: 2026-07-23 — A–D live-test run on `f955c6f-dirty`, plus the
PROXY-protocol pre-deploy guard.

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
