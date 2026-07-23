# Test results — 2026-07-23 (build f955c6f-dirty)

Fresh server, fresh clients (Windows + Linux), both attesting on the prior build.
Run against the 22 July procedure. Server on `LOG_LEVEL=debug`.

## Pass

- **A** first-run identity + attestation — verified both accounts.
- **B** 1:1 messaging — works, with the bugs below.
- **D1–D3** device lifecycle — link, manifest counter increments, and the
  **safety number stays stable across a device add** (the cross-signing payoff).
- OSCAR denies pending-request spam on its own — no fix needed.

## Blocks the `enforce` flip — DO NOT flip yet

A **newly-linked device fails its first attestation**, in log mode:

```
04:44:47  session could not prove its device (log mode, admitted anyway)  usec
04:46:28  session closed without answering its device challenge           usec
04:48:05  session could not prove its device (log mode, admitted anyway)  usec
```

These fire on the sign-ons where usec is linking / removing a device
(counter=2 devices=2, counter=4 devices=2). The challenge is issued at sign-on,
before the new device publishes itself into the manifest, so it attests as
"not enrolled." Under `enforce` this locks a linking device out. Fix the
ordering — the device's key must be in the manifest before it can be
challenged, or a just-linked device must be exempt from its first challenge —
before enforce is safe. Log mode did exactly its job here.

## Group 1 — block evasion (server-side, BENCoscar permit_deny)

- **B1** a buddy request reaches someone who has blocked you.
- **B2** a warn lands on someone who has blocked you.

The deny list is not consulted on inbound `FeedbagRequestAuthorize` or
`ICBMEvilRequest`. Security-relevant: blocking is a server-enforced guarantee,
and this is a place a normal client defeats it. Fix in the fork's permit_deny /
icbm handlers.

## Group 2 — rooms (FAIL, priority)

- **C** creating an encrypted room works; joining reports "I don't have the
  key." Key distribution (invite → signed roster → per-sender chains) is not
  landing on the joiner, or the GUI is not wiring an encrypted join to the key
  material.
- **D4/D5** blocked behind rooms (room re-key on device removal; 1:1 transferred
  messages also not arriving — see below).

Needs a focused session with both clients live and the System-log-durability fix
in place, so the client-side refusal reason is visible.

Design notes raised during the run, both agreed:
- **Unencrypted rooms should stop being possible.** Encryption is not optional
  elsewhere; rooms are the exception and shouldn't be.
- **Invite policy should be a room-creation choice, assignable to tiers**
  (owner-only / mods+ / anyone). Fold into the roster as a signed field; ship
  owner-only + anyone first, tiers when §7 roles land.

## Group 3 — client bugs

- **B3** phantom buddy: the client adds a **nonexistent** screen name with no
  validation — no pending state, opens a conversation marked "unencrypted,"
  sends fail silently. Log shows `LocateUserInfoQuery → LocateErr` and
  `session not found` for the typed name. The add should be refused (or the user
  told the name doesn't exist) rather than manufacturing a dead conversation.
- **B5** messages to an **offline** peer error on the sender
  (`ICBMChannelMsgToHost → ICBMErr`) rather than being stored offline; they
  arrive when the peer returns. Likely the E2EE 1:1 send is not setting the
  store-offline TLV. (Cross-reference the audit note about the store-message TLV
  on forwarded ICBMs.)
- **B6** "earrape": catch-up delivers the whole offline backlog at once and each
  message plays a notification sound simultaneously. Coalesce — one sound for a
  batch.

## Suggested order next session

1. **Rooms (C).** Highest value; unblocks D4/D5. Start with the
   System-log-durability fix so the client says why the key is missing.
2. **Device-link attestation ordering.** Gate on this before `enforce`.
3. **Block evasion (B1/B2)** in the fork — small, security-relevant.
4. **B5 offline store**, then the cheap client polish (B3 validation, B6 sound
   coalesce).
