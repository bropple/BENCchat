# BENCchat

## What this is

BENCchat is a modern chat client speaking the **OSCAR protocol** (the wire
protocol AIM and ICQ ran on), built against a self-hosted server rather than
AOL's long-dead infrastructure. The goal is a client that's actually pleasant
to use day-to-day — not a compatibility exercise with 2000s-era Windows
binaries — while staying protocol-authentic underneath.

This is a BENCO Holdings project. Brand voice, lore, and character details
(R. Triy, etc.) live in the separate BENCO lore document — consult that for
copy/personality, not this file. This file is scoped to architecture and
protocol implementation only.

## Why OSCAR instead of Matrix

This was a deliberate choice, not a default. Matrix would have meant no app
to build at all (just deploy a homeserver + stock client), or at best an SDK
skin. OSCAR means hand-rolling the FLAP/SNAC framing and session handling —
more foundational, more protocol-level craft, closer to the kind of project
this is meant to be. That tradeoff is the point: less mature tooling to lean
on, more of the actual protocol built by hand.

## Server side — already live, don't rebuild this

The backend is **[open-oscar-server](https://github.com/mk6i/open-oscar-server)**
(mk6i, Go, MIT), already deployed and working. BENCchat is a **client only**
— do not reimplement server-side session/state logic here.

**Live deployment:** the actual hostname, ports and VPS details live in
`DEPLOYMENT.local.md`, which is deliberately NOT in source control — the server
address is a deployment detail and publishing it just invites traffic. Read that
file for specifics. What matters for the code here:

- **TLS only, terminated natively.** BENCoscar terminates TLS in-process
  (`server/oscar/tls.go`) — there is no stunnel sidecar and no plaintext OSCAR
  port. Anything connecting to this deployment must speak TLS, which includes
  test harnesses: a plaintext dial connects and then hangs waiting for a FLAP
  hello that never comes, so the symptom of getting this wrong is an i/o
  timeout, not a refused connection. Period AIM clients cannot connect at all;
  that compatibility was given up deliberately.
- `DISABLE_AUTH=false` — accounts must be provisioned via the Management API
  before they can sign in.
- The Management API is bound to loopback on the VPS and is **not** publicly
  exposed — reach it over an SSH tunnel. Do not build any BENCchat feature that
  assumes this API is reachable directly from a client on the open internet.
- Never hardcode the server address. `config.DefaultAuthHost` is empty by
  design; a build can pre-fill it via `-ldflags` without committing it.

## Protocol reference

OSCAR is layered: **FLAP** (outer framing) wraps **SNAC** (the actual
command layer, organized into "foodgroups" — families of related commands
like buddy list management, instant messaging, locate/profile, etc.).
Most values inside SNACs are encoded as **TLVs** (type-length-value triples).

Canonical reference for this implementation: **open-oscar-server's own Go
source**, since that's the exact dialect the BENCchat server speaks —
prefer it over generic historical OSCAR docs when the two disagree.

Relevant paths in that repo (clone it locally as a reference, don't vendor it):
- `wire/frames.go` — FLAP framing
- `wire/snacs.go` / `wire/snacs_string.go` — SNAC family/subtype constants
- `wire/tlv.go` — TLV encode/decode
- `wire/decode.go`, `wire/encode.go` — core (de)serialization
- `wire/user.go`, `wire/buddy_prefs.go`, `wire/rate_limit.go`, `wire/xtraz.go`
  — supporting structures
- `foodgroup/` — one file per foodgroup, showing exactly which SNAC
  subtypes are implemented server-side and how they behave:
  `oservice.go` (core session mgmt), `auth.go` (the login flow BENCchat needs
  — see the sign-on note below, not the Kerberos/SSL one in `server/kerberos/`),
  `buddy.go`, `feedbag.go` (buddy list storage), `icbm.go` (instant
  messages), `locate.go` (profile/away), `permit_deny.go`, `chat.go` /
  `chat_nav.go`, `icq.go`, `odir.go`, `stats.go`, `admin.go`
- `server/oscar/` — the actual FLAP/SNAC server loop and session handling,
  useful for understanding expected client behavior at each step

For general OSCAR background beyond this specific server, the old
community-maintained OSCAR protocol writeups (the ones GAIM/Pidgin's
original AIM support was built from) are useful historical context, but
treat open-oscar-server's source as the source of truth for anything that
conflicts — it's the actual server BENCchat talks to.

## Architecture guidance

Keep protocol logic and UI cleanly separated. A likely shape:

1. **Transport layer** — raw TCP socket + FLAP framing (length-prefixed
   frames, sequence numbers)
2. **SNAC layer** — encode/decode SNAC headers + TLV payloads per foodgroup;
   ideally generated or table-driven rather than hand-written per command,
   given how many subtypes exist
3. **Session/auth layer** — sign-on (screen name/password → auth cookie →
   connect to BOS) against `foodgroup/auth.go`'s expectations. **Note:** this
   is no longer BUCP. BENCchat sends the password in TLV `0x1339`
   (`LoginTLVTagsPlaintextPassword`) inside TLS, and BENCoscar *refuses* BUCP
   outright — `ValidateHash` always returns false. The server stores argon2id
   (migration `0034`), so there is no password-equivalent at rest, but the
   cleartext password does cross the trust boundary at every login. Authentication
   is deliberately **not** zero-knowledge; see the trust model below.
4. **State layer** — buddy list (feedbag), presence, away status, open
   conversations — protocol-agnostic data model that a UI can bind to
5. **UI layer** — talks only to the state layer, never touches FLAP/SNAC
   directly. This separation is what would let R. Triy or a future Home
   Assistant integration reuse the protocol layer as a headless client later
   without dragging UI code along.

Write the protocol layer to be testable without a live server where
possible (fixture-based encode/decode tests against known-good byte
sequences), since OSCAR bugs are the kind that are miserable to debug by
staring at a hung TCP connection.

## Tech stack

**Proposed default: Go.** Rationale: matches the server (shared mental
model, can literally cross-reference structs), already proven to
cross-compile cleanly for this deployment's arm64 target, good stdlib
support for raw TCP + binary encoding without heavy dependencies, decent
concurrency primitives for a client juggling a socket read loop + UI events.

This is a starting assumption, not a locked decision — revisit if UI
requirements point somewhere else (e.g. a native GUI toolkit story is
weaker in Go than in some alternatives). Flag it for discussion rather than
silently overriding it.

## Conventions

- No code exists yet as of this file's creation — treat the "Architecture
  guidance" section above as the intended shape when scaffolding, but it's
  a starting point, not gospel. Confirm significant deviations before
  committing to them.
- Don't hardcode the server address or port as a client-side constant —
  make the server address configurable from the start, even though there's
  only one server today.
- Treat the OSCAR wire format as unforgiving: get FLAP/SNAC framing right
  before layering features on top. A subtly wrong TLV length will manifest
  as a confusing disconnect, not a helpful error.
- This project prioritizes protocol authenticity over feature creep —
  resist the urge to silently extend the wire format with custom BENCO-only
  fields; if BENCchat needs something OSCAR can't express, that's a real
  design decision to surface, not something to sneak into a TLV.
- **Keep [`docs/TODO.md`](docs/TODO.md) current.** It is the living checklist
  of outstanding work — bugs, blockers, decided-but-unbuilt design, deferred
  items. When work lands, a test runs, or a new problem surfaces, update the
  TODO in the *same* change: check items off, add what was found, re-order when
  priorities move, and note what gates what. Treat a fix that leaves the TODO
  stale as unfinished. It is the first thing to read when picking work back up.

## How the client actually works

[`docs/how-it-works-today.md`](docs/how-it-works-today.md) describes the program
as it exists — layers, sign-on, messaging, rooms, the device/key model, and what
is on disk — with `file:line` citations throughout. **Read this before the trust
model.** It is the only document here that is purely descriptive; if it and the
code disagree, the code wins and the doc is stale.

## Trust model

**Cross-signing is built.** The account is rooted in an Ed25519 identity key
that signs a device *manifest*. Peers verify that manifest over the bytes as
received, bound to the screen name, with a monotonic counter that rejects a
stale or rolled-back list. The identity private key is held only transiently —
unwrapped from a server-side argon2id-encrypted backup using a ten-word
*generated* recovery key, used, then zeroed. Safety numbers derive from the
identity key, so they no longer churn every time a device is added.

[`docs/keydir-v2-proposal.md`](docs/keydir-v2-proposal.md) is the wire-level
design, and it is **substantially implemented** — see `app_keydir.go`,
`internal/trust/`, `internal/e2ee/identity.go`, `internal/e2ee/identitybackup.go`.
Read it as a spec, and check the code before assuming any individual part of it
landed. [`docs/trust-model.md`](docs/trust-model.md) is the argument that led
there; its premise — "the password owns the account outright" — is **no longer
true**. Read it for the reasoning and for the approaches already ruled out, not
as a description of the program.

What cross-signing changed, and what it did not:

- A password-only attacker **cannot** sign a manifest under the existing
  identity, so it cannot quietly insert a device, and it cannot decrypt anything
  sent earlier.
- It **can** still sign in and send and receive as the account. The server
  authenticates a password and cannot tell which *device* is talking —
  `BENCoscar/foodgroup/benco_keydir.go` says so outright, and notes that every
  check in that file is therefore advisory. Device removal is enforced at the
  key-directory layer, never at the session layer.
- So a takeover is **loud** — publishing a fresh identity moves every peer's
  safety number — but it is not prevented, and it destroys the previous identity
  irrecoverably.

**Rooms have forward secrecy; 1:1 does not.** Rooms moved to per-sender
forward-only chains (`internal/e2ee/ratchet.go`), so joining grants a read from
that point on and nothing earlier, and removal is enforced by every member
retiring the chain they send on. Membership itself is a signed roster with an
epoch and a pinned owner (`internal/e2ee/roster.go`); shrinking it requires the
owner, adding it does not.

Still unbuilt: forward secrecy for 1:1, which remains a static-static NaCl box
(`internal/e2ee/e2ee.go`), and everything in
[`docs/room-consent-model.md`](docs/room-consent-model.md) beyond §7's decided
roles.

Note that `trust-model.md`'s central argument — constraining what a malicious
operator can do — is weighted for a threat model this deployment may not have,
since the operator is the person running the server.

## Open questions to resolve early

- UI framework / platform target (desktop-first? which toolkit?)
- Whether to build the SNAC layer by hand or generate it from a schema
- How BENCchat identity/branding (BENCO visual language) integrates with a
  protocol-first client — separate skin layer, presumably
- Long-term: does BENCchat ever want its own extended protocol on top of
  OSCAR (custom foodgroup-adjacent messages between BENCchat clients only,
  degrading gracefully for non-BENCchat OSCAR clients), or does it stay a
  strict OSCAR client indefinitely
