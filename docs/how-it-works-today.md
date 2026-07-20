# How BENCchat works today

**Status: descriptive.** This document says what the code does, as of the commit
that removed device keys from AIM profiles (`d7720e3`). It is not a design, not
a proposal, and not a wish. Where something is ugly, it says so and stops there.

Contrast with [`trust-model.md`](trust-model.md), which is explicitly a
*proposal* and describes a system that does not exist. Reading that one as
though it described the program is a reliable way to become confused about the
program.

Everything here is cited to `file:line`. If a claim and the code disagree, the
code is right and this file is stale — fix it.

---

## 1. The shape

Five layers, bottom to top:

| Layer | Package | Knows about |
|---|---|---|
| Transport | `internal/oscar` (`transport.go`, `tls.go`) | TCP, TLS, FLAP frames |
| Protocol | `internal/oscar`, `internal/wire` | SNACs, foodgroups, TLVs |
| Translation | `internal/client` | **both** protocol and state |
| State | `internal/state` | neither — plain data |
| UI | `main` package + `frontend/` | state only, via Wails |

The load-bearing rule: `internal/state` imports neither `oscar` nor `wire`
(`state.go:1-9`), and `internal/client` is the only package that knows both
(`client.go:1-8`). That is what would let a headless consumer reuse everything
below the UI.

**The rule mostly holds.** `internal/wire` is imported by exactly two packages:
`internal/oscar` and `internal/client`. Nothing in the UI layer touches it.

**Where it leaks:** the `main` package imports `internal/oscar` — but only for
value and error types, never to speak protocol. Specifically `oscar.Transport`
and `oscar.Credentials` when calling `SignOn` (`app.go:175-180`, `app.go:348`),
and `oscar.SignoffError` / `oscar.ErrClosed` / `oscar.LoginError` for
classifying disconnects (`app.go:201-210`). No comment anywhere states this is
an intended exception, so whether it is design or drift is not knowable from the
code.

---

## 2. Signing on

The auth mechanism is **a plaintext password in a FLAP signon frame, sent over
TLS**. Not BUCP. The BUCP structs still exist in `internal/wire/login.go:101-150`
but nothing in the client path references them; the switch was commit `79ab5e4`.

The password rides in TLV `0x1339` (`internal/wire/login.go:24`), alongside the
screen name (`0x01`), a client identity string of `"BENCchat"`
(`internal/oscar/auth.go:15`), and a multi-connection flag (`login.go:99`).

`oscar.Login` (`auth.go:77-105`) dials, sets a 30-second deadline both ways, and
closes the connection when done — the auth connection is never reused
(`auth.go:75-76`). The reply arrives as a FLAP **signoff** frame containing a
bare TLV block, not a SNAC (`auth.go:161-163`). Success is decided by the
*presence of the cookie TLV*, not the absence of an error (`auth.go:170-175`).

The cookie is valid for **60 seconds** (`auth.go:26`), checked before use
(`session.go:91-96`).

`oscar.SignOn` (`session.go:90-162`) then does, in this order:

1. Redirect to the BOS address and dial it (`session.go:98-102`).
2. Handshake (below).
3. **Load the buddy list — before going online.** The comment at
   `session.go:117-128` records why: the `FeedbagUse` inside it fails silently if
   sent after `ClientOnline`, and you sign on to an empty roster.
4. Create the root group and default group if the account is brand new.
5. Advertise capabilities `CapSecureIM` and `CapBENCchat` — best-effort, error
   deliberately discarded (`session.go:146-148`).
6. `ClientOnline`.
7. Retrieve offline messages — also best-effort (`session.go:157-160`).

The handshake itself (`session.go:184-236`): read the server hello, send the
cookie verbatim, wait for `HostOnline` and **record the server's foodgroup list**,
exchange version blocks, then query rate parameters and build a limiter — but
only if the reply decodes. A decode failure is silently non-fatal and leaves the
client unpaced (`session.go:223-234`).

### Where the server address comes from

`config.DefaultAuthHost` is an empty `var` on purpose (`config.go:14-21`); a
build fills it via `-ldflags`. The default port is **5191**, a const
(`config.go:26`), because the deployment terminates TLS and runs no plaintext
listener. Config lives at `os.UserConfigDir()/BENCchat/config.json`, mode `0600`
(`config.go:171-181`).

**Passwords are never in config.** They go to the OS keyring under service name
`"BENCchat"` (`internal/secret/secret.go:15`); config stores only a
"remembered" marker (`config.go:39-43`).

---

## 3. The read loop

`Session.Run` (`session.go:292-322`) reads SNACs in a loop and calls
`s.Handler` **synchronously on the read goroutine**. Handlers must not block
(`session.go:45-46`) — this constraint shows up repeatedly, e.g. buddy-icon
downloads are punted to a goroutine specifically because `Send` can block on
rate pacing (`client.go:554-557`).

`Client.handleSNAC` (`client.go:423-448`) is a flat switch on foodgroup:
OService, Buddy, ICBM, Feedbag, Locate, UserLookup, ODir, Admin, BENCOKeyDir,
BART. **Anything else is dropped silently** (`client.go:446-447`). Chat rooms
run a second dispatcher on their own connections.

Keepalives go out every 60 seconds (`session.go:19`).

### Rate limiting

There is real client-side pacing (`internal/oscar/ratelimit.go`). It models the
server's sliding-window average per rate class, waits out the shortfall before
sending, and caps any single wait at 8 seconds (`ratelimit.go:16`).

Two facts worth knowing:

- The limiter is built **once** from the initial rate-params reply and never
  updated. The client never subscribes to rate changes and never handles
  `RateParamsChange` — zero references outside tests.
- `SendReq` (`service.go:28-32`) bypasses pacing entirely.

Separately, the *server side* imposes limits the client does not model at all:
stunnel allows 30 connections/minute per IP, and the server has its own sign-on
limiter. See `DEPLOYMENT.local.md`.

---

## 4. State, and how the UI sees it

`internal/state.Store` holds self, buddies, group order, conversations, rooms,
and an icon cache (`state.go:299-314`). One `sync.RWMutex`. Every getter returns
**copies**, not references (`state.go:566-595`, `759-763`).

The mutation pattern is uniform: mutate under lock, snapshot, unlock, *then*
emit. `emit` must be called without the lock (`state.go:348-361`).
`DecryptPending` (`state.go:620-698`) explicitly drops the lock around its
callback, with a comment recording that doing otherwise deadlocked the app
because `RWMutex` is not reentrant.

**The UI does not poll.** One subscriber is registered at startup
(`app.go:131-137`) and forwards every `state.Event` to the frontend as a single
Wails event named `"state:event"`. The frontend listens via
`EventsOn("state:event", …)` (`bridge.ts:411`).

The convention is *event as a hint, then re-read via getters* — e.g.
`buddyListChanged` triggers a full `refreshBuddies()` (`roster.ts:1746-1748`).
The one exception is `buddyChanged`, which patches in place to avoid reordering
the list under the user's cursor (`roster.ts:1750-1756`).

Disconnection does **not** travel this path. `EventDisconnected` is declared
(`state.go:206-208`) and never emitted by anything; disconnects reach the UI via
`client.OnDisconnect` → a separate `"session:status"` event
(`app.go:139-151`).

In-memory scrollback is capped at 1000 messages per conversation
(`state.go:295`).

---

## 5. Buddy list, presence, blocking

The feedbag is a **flat list of items server-side**; the group tree is a
client-side reconstruction (`feedbag.go:70-72`). Root is a Group item with ID 0
whose ordering TLV names the groups. A buddy whose group item is missing falls
back to `"Buddies"` (`feedbag.go:141-146`).

Edits are **optimistic**: the local mirror is authoritative and the server's
`FeedbagStatus` reply is observed asynchronously (`feedbag_edit.go:258-259`).
`handleFeedbag` (`client.go:494-512`) only logs — success is silent, and
**nothing from it ever reaches the UI**, including "awaiting authorization".

Presence is a single value — `offline`/`online`/`away`/`idle`
(`state.go:21-26`) — so away and idle cannot both be represented; away wins
(`client.go:823-837`).

Two consequences of how presence is wired, both stated as code behavior:

- `BuddyArrived` always passes an empty away message (`client.go:517-521`), so
  any away text previously fetched is cleared on every arrival re-broadcast.
- Away text is **fetched, never pushed**. The UI triggers the fetch itself when
  the active buddy goes away with no text (`roster.ts:1782-1788`).

We never send our own idle time; there is no sender for it.

**Blocking is entirely feedbag-based** — there is no `PermitDeny` foodgroup
handling. Blocking inserts a deny item and ensures a privacy-mode item exists
(`feedbag_edit.go:162-194`); unblocking deletes the deny item and deliberately
leaves the mode alone (`feedbag_edit.go:196-197`). Blocked state reaches the
Store **only on a full list republish** — there is no per-buddy setter.

---

## 6. Encryption, keys and devices

This is the part that is hardest to hold in your head, so it gets the most room.

### What keys exist

| Key | Type | Scope | Stored |
|---|---|---|---|
| Device encryption key | X25519 | one per machine | OS keyring, `e2ee:<account>` |
| Device signing key | Ed25519 | one per machine | OS keyring, `sign:<account>` (seed only) |
| Room group key | symmetric | one per room | per-account JSON |

**There is no account-level or identity key.** Every key is per-device. This is
the single fact from which most of the complexity below follows.

Private keys never leave the machine. If the keyring read *fails*, encryption is
disabled for the session and a new key is **not** minted
(`app_e2ee.go:38-65`) — the comment explains that minting on failure would give
the device a new identity every time the keyring was slow, change the safety
number for every contact, and fill the 32-device cap with dead keys.

### Where public keys live

Only in the **key directory**, foodgroup `0xBE00` (`internal/wire/keydir.go`).
Since `d7720e3` this is the sole source; the AIM-profile marker path is gone.
Markers are still *stripped* from profile text for display, because accounts
that have not republished still carry one in their bio (`client.go:478-481`).

The directory carries `BENCODevice{BoxKey, SignKey}` and nothing else — no
device name, no timestamp, no signature, no metadata
(`internal/wire/keydir.go:40`). Support is discovered from the `HostOnline`
foodgroup list, because `0xBE00` sits above `wire.MDir` and cannot participate in
version negotiation (`internal/oscar/keydir.go:17-29`).

Verified against the live server: the directory is **account-scoped** — a second
device reads back what the first published, and it answers for devices that are
currently offline (`internal/oscar/live_test.go`, `TestLiveKeyDirIsAccountScoped`
and `TestLiveKeyDirectory`). The offline case is what the profile scheme could
never do.

**Publication is a full replace.** The publish request carries the entire device
list. A device that publishes before reading destroys every other device on the
account. `publishAfterDeviceCheck` reads first for exactly this reason
(`app_e2ee.go:116-118`) — that ordering is load-bearing and nothing enforces it.

### The device lifecycle

On sign-on, `publishAfterDeviceCheck` (`app_e2ee.go:119-245`):

1. Reads the account's currently published devices.
2. If the directory answered, takes it **as-is** — deliberately *not* merged with
   local memory, because merging republishes devices another machine removed, so
   a removal on one device is undone by the next one to sign on
   (`app_e2ee.go:133-147`).
3. If this device is absent from a non-empty list, it is a new machine and marks
   itself as awaiting approval — quietly, so the user gets one explanation rather
   than two contradictory ones (`app_e2ee.go:174-179`).
4. Adds itself, applies the 32-device cap by least-recently-seen
   (`e2ee.PickDevices`), and warns if anything was dropped.
5. Publishes, then announces itself to any other session on the account.

### Device linking

Linking traffic travels as **self-addressed, unencrypted instant messages** —
kinds `announce`, `share`, `deny` (`internal/e2ee/multidevice.go:465-471`). The
server relays a message you send to yourself to all your other sessions.

- **`announce`** — "I exist, here is my key." The server echoes it back to the
  sender, which is ignored explicitly, or a device would approve itself
  (`app_e2ee.go:648-652`).
- **`share`** — an already-linked device sending the full list, which is how a
  newly-approved machine learns its siblings (`app_e2ee.go:690-709`).
- **`deny`** — tells a device it was refused. It signs out and clears its saved
  password. The comment is honest about what this is:
  *"a courtesy, not a boundary — whoever is here still knows the password and
  can sign in again"* (`app_e2ee.go:633-635`).

Approval is deliberately per-session-forgetful: a device declined last time gets
to ask again on the next sign-on (`app_e2ee.go:95-97`).

### The thing to understand about approval

**Publishing is self-service.** The server accepts whatever an authenticated
session sends, and a session authenticates with a password. By the time the
approval dialog appears, the device is already in the directory.

So the approval dialog does not gate anything. It records a local decision and,
if denied, politely asks the other device to leave. This is not a bug in the
dialog; it is a consequence of there being no key above the device keys for the
server or anyone else to check a device against. Every mitigation in this area
runs into the same wall, which is what `trust-model.md` was written to work
through.

### Safety numbers

`SafetyNumberSet` (`internal/e2ee/multidevice.go:241`) concatenates both sides'
deduped, sorted device keys, orders the two blobs against each other so both
parties compute the same string, hashes with SHA-256, and renders six groups of
five digits.

Because it is computed over the **set of device keys**, adding any device on
either side changes it. There is no stable identity underneath to anchor it to.

The UI softens this by distinguishing an addition from a substitution.
`VerificationInfo` (`app_e2ee.go:446-487`) produces five statuses:

| Status | Meaning |
|---|---|
| `unavailable` | we lack our key or theirs |
| `unverified` | never confirmed out of band |
| `verified` | current key set matches what the user confirmed |
| `device-added` | changed, but every previously-seen key is still present |
| `changed` | a key we relied on is gone — what substitution looks like |

`KeysOnlyAdded` (`multidevice.go:270`) is what separates the last two. The trust
record keeps both `Verified` and `Seen` per peer (`internal/trust/trust.go`), so
a key swap is detectable even for a peer the user never verified — which is the
majority case.

### Scale of this subsystem

`app_e2ee.go` alone has **39 functions**, of which roughly fourteen exist purely
to track link-request UI state (`markLinkPrompted`, `setLinkPending`,
`setLinkPendingQuiet`, `claimLinkNotice`, `forgetLinkPrompt`, `clearLinkPending`,
`resetLinkState`, `emitLinkState`, and friends). That is a fair measure of how
much machinery the per-device model costs.

---

## 7. Messaging

### Sending

`Client.SendMessage` (`client.go:211`) encrypts only if **all three** hold:
E2EE is on, we have a keypair, and we have cached keys for that peer
(`internal/client/e2ee.go:98-104`). The peer's advertised capability is *not*
consulted.

**Both paths fail closed.** `sealOutbound` sends plaintext only when we hold no
keys for the peer — the ordinary non-BENCchat case, where the UI shows no lock.
If we hold keys and sealing fails, nothing is sent, matching what
`sealRoomMessage` does for rooms (`room_e2ee.go:277-280`).

The failure branch is not reachable today: `sealFor` guarantees a non-empty
recipient set, which is the only error `SealFor` returns short of the system
random source failing. It exists because the alternative shape — "encrypt, or
quietly don't" — transmits in the clear to someone the UI is showing a lock for,
and anything fallible added to this path later lands exactly there.

Local storage is optimistic: the plaintext is stored after a successful write to
the socket, with no wait for any ack (`client.go:238-245`).

**Delivery acks are requested and ignored.** Every send asks for one
(`oscar/icbm.go:69`), `ICBMHostAck` has no case in `handleICBM`, and the message
cookie is discarded (`client.go:235`).

There is **no size check** on the outbound body, and the server's advertised
limit disagrees with what it enforces. Measured against the live deployment by
`TestLiveICBMSizeCeiling` (`internal/oscar/live_test.go`):

| | Bytes |
|---|---|
| `MaxIncomingICBMLen`, as advertised | 512 |
| Actually accepted and relayed intact | 65,000 |
| FLAP's own ceiling (`wire.FLAPMaxPayload`) | 65,529 |

The advertised value is the AIM-era number and BENCoscar does not enforce it.
Nothing on the client reads it either.

**This is already load-bearing.** A five-device v2 envelope runs slightly over
512 bytes after base64, so ordinary multi-device messages exceed the advertised
limit today and work only because nothing checks. If the server ever starts
honouring what it advertises, multi-device messaging breaks — and with no
client-side check, it breaks silently.

The headroom is otherwise enormous, which matters for one specific future:
post-quantum hybrid key wrapping would add ~1088 bytes per recipient device
(ML-KEM-768 ciphertext), so a five-device account needs roughly 8 KB. That fits
inside the measured ceiling with room to spare, so it would need no transport
change.

### Receiving

`handleICBM` (`client.go:615`) runs an ordered interceptor chain before anything
is stored:

1. **Device-linking traffic** from our own sessions — tested on the *raw* body,
   which is why device messages are never encrypted (`client.go:634-637`).
2. **System senders** (`aolsystemmsg`, `oossystemmsg`) → routed to the notice
   log, never into a conversation (`client.go:642-645`).
3. Decrypt.
4. **Room invites** and **catch-up**, but only if the body decrypted
   (`client.go:650-658`).
5. Otherwise store as a message.

Decryption has three outcomes (`internal/client/e2ee.go:142-158`): not an
envelope → verbatim; envelope but no keys → a placeholder plus a background key
refresh; envelope but nothing opens → a different placeholder plus a refresh.

**"Not addressed to this device" and "authentication failed" are
indistinguishable** at the client layer. `openWithAny` trial-opens every cached
sender key and discards the error (`e2ee.go:130-137`), so `ErrNotForUs` is never
inspected outside tests. Both land on the same "couldn't decrypt" placeholder.

Retained ciphertext is the recovery mechanism: learning a peer's keys later
triggers `DecryptPending`, which retroactively decrypts stored messages
(`e2ee.go:163`, `state.go:620`). But `Cipher` is `json:"-"`, so **a restart
strands an undecrypted message at the placeholder permanently.**

### The envelope

Two formats, both ESC-prefixed so they stay ASCII-clean and cannot collide with
typed text. One recipient uses v1 (`Seal`); two or more use v2
(`multidevice.go:140-147`):

```
prefix + base64(
  [1]  version = 2
  [24] body nonce
  [1]  recipient count
  count × { [24] wrap nonce, [48] box.Seal(msgKey, …, recipientPub) }
  [..] secretbox.Seal(message, bodyNonce, msgKey)
)
```

A fresh 32-byte message key per message; the body is sealed once under it and
the key is wrapped separately per device. **Slots are unlabelled** — deliberately,
so the recipient set does not leak (`multidevice.go:183-185`). The receiver
trial-opens each one.

Typing notifications collapse three states into a bool: `ICBMEventGone` is
defined but never sent, and `Typed` and `Gone` are indistinguishable downstream
(`client.go:398-401`, `state.go:283-291`).

---

## 8. Chat rooms

Rooms run on **separate connections**: BOS, one shared ChatNav opened lazily,
and one session per joined room keyed by cookie (`client.go:45-48`). Joining is
a four-step redirect dance — request the ChatNav service, create/look up the
room to get its real cookie, request a Chat service grant for it, then dial the
granted host with the granted cookie (`internal/client/chat.go:32-121`).

Order matters at the end: the handler is wired and the read loop started
*before* `GoOnline()`, so the roster the server pushes immediately after isn't
missed (`chat.go:102-112`).

The server relays room messages to everyone **except** the sender, so the local
echo is the only copy the sender ever sees (`chat.go:192-201`).

### Room encryption

A **symmetric group key** per room, with a key ID (first 8 bytes of its SHA-256)
carried in the clear on every message so rotation doesn't strand scrollback
(`internal/e2ee/room.go:50,71-78`). Retired keys are kept forever and never
evicted (`room_e2ee.go:63-70`).

Two server behaviours force this shape, both verified against open-oscar-server
and recorded at `room.go:26-35`: custom TLVs are stripped from chat messages, so
the key ID must be in-band; and the server HTML-tokenizes chat text and
regex-rewrites `^//roll`, hence the ESC prefix and base64-only body.

**Rooms fail closed.** Whether a room is encrypted is tracked separately from
whether we hold its key, precisely so a lost key refuses to send rather than
silently reverting to plaintext (`room_e2ee.go:21-25`).

Keys are delivered as invites over the **1:1 E2EE channel** — refused unless we
can already encrypt to that person (`room_e2ee.go:442-450`). An invite for a room
you are already in is treated as a key rotation and applied silently
(`app_room_e2ee.go:227-232`).

Rotation re-invites the **deliberately-invited member list**, not the current
room roster (`app_room_e2ee.go:27-31`). `ReformRoom` exists because there is no
kick: it creates a new room with a random suffix, new key, carries the members
over, and leaves the old one last.

### What the per-sender signature proves

Each room message carries an Ed25519 signature over `room || 0x00 || message`,
placed **inside** the sealed body so the server cannot build a per-device
activity trace (`roomsign.go:29-31,111-135`).

It proves **which device authored the plaintext**, bound to a room name. It
proves **nothing about membership**: the group key is symmetric, so any holder
can seal anything, and there is no signed membership list.

Three outcomes are carefully distinguished (`roomsign.go:170-194`): no known
sender keys → *unknown, not forged*; ID matches and verifies → good; ID matches
a published key but fails, or matches none → `ErrForgedSignature`, shown with a
`⚠ [UNVERIFIED …]` prefix.

Since `publishDevices` can only attach a signing key for *this* device, other
devices appear with none until they republish for themselves
(`app_keydir.go:63-73`) — so unsigned-but-legitimate is a normal state.

**Known gap, stated in the code:** `reverifyRoomMessages` is an explicit no-op
(`room_e2ee.go:336-340`). A message received before the sender's signing key was
known stays unverified until the room is reopened.

### Catch-up

Rooms are relay-only server-side, so scrollback is requested **peer-to-peer**
over the 1:1 E2EE channel (`room.go:255-404`). Responses carry the *original
sealed envelope* so signatures are re-checked by the recipient rather than
trusted; forged entries are dropped on both serve and merge. Only
deliberately-invited members are served or asked. Because `Envelope` is
`json:"-"`, messages surviving a restart cannot be relayed and are skipped.

---

## 9. The UI layer

Wails v2. A single bound object — the `App` value — exposing **76 methods**, and
exactly **five** Go→JS events:

| Event | Payload |
|---|---|
| `state:event` | every `state.Event`, carrying a `kind` discriminator |
| `session:status` | connection state |
| `device:link-request` | a device asking to be approved |
| `device:link-state` | this device's own link status |
| `room:invite` | an incoming room invitation |

The frontend is **vanilla TypeScript with no framework and no runtime
dependencies** — rendering is `innerHTML` assembly plus `querySelector` wiring.

`bridge.ts` is the only file that touches Wails globals, and it deliberately
**re-declares the binding surface by hand** rather than importing the generated
`frontend/wailsjs/` bindings, so the app loads even before they are generated
(`bridge.ts:1-7`).

There are exactly two screens — sign-on and roster (`main.ts:23`). Everything
else is an overlay. `roster.ts` is 81.5K and holds the entire signed-on UI.

Device management lives in Settings → Privacy; the approval prompt itself lives
in `main.ts:74-111`, separate from it.

### Build

CI builds Linux (amd64, `webkit2_41` tag), Windows (amd64, Azure Trusted Signing
when secrets are present, with a verification step that fails the build if the
signature isn't `Valid`) and macOS (universal, **unsigned and un-notarized**).
The `check` job must build the frontend before running Go steps, because the root
package won't compile without `frontend/dist` for `//go:embed`.

Artifacts ship with `config.DefaultAuthHost` empty on purpose, and the workflow
says so explicitly.

---

## 10. Persistence: what is on disk

| What | Where | Protection |
|---|---|---|
| Config | `UserConfigDir/BENCchat/config.json` | mode 0600 |
| Message history | `UserConfigDir/BENCchat/history/<account>.json` | mode 0600, **encrypted** (secretbox) |
| Trust + own device list | `UserConfigDir/BENCchat/trust/<account>.json` | mode 0600 |
| Room keys | per-account JSON | mode 0600 |
| Passwords, device keys | OS keyring | OS-provided |

**History is encrypted at rest.** The file is sealed with NaCl secretbox under a
random per-account key held in the OS keyring as `hist:<account>` — namespaced
separately from the E2EE key, because that one is an identity peers verify and
this is a local file key with a different lifecycle.

Sealed files carry a `BENCHIST1` magic prefix. Plaintext files from before this
change start with `{`, so the two shapes can't be confused, migration needs no
version negotiation, and existing history is re-encrypted on the next save.

Three deliberate refusals, all mirroring what `setupE2EE` does for encryption
keys (`app.go:753`):

- A keyring read that **fails** does not mint a key. Persistence stops for the
  session and the user is told once. Minting would strand every existing file.
- A stored key that **won't decode** is treated the same way — there is a key,
  it just can't be used, and replacing it destroys what it wrote.
- `history.Save` returns an error rather than writing plaintext when it has no
  key, and `persistHistoryNow`'s nil-key guard sits *above* its `Clear` branch:
  deleting history we merely failed to open is worse than a removal that doesn't
  stick.

A failed decrypt is an error, never an empty `Data` — otherwise a wrong key
would read as "no history yet" and the next save would overwrite the real file
with nothing.

Note that ciphertext is *not* persisted — `Envelope` and `Cipher` are `json:"-"`
(`state.go:108,113`) — so an undecrypted message is stranded at its placeholder
across a restart.

Saves are debounced 2 seconds (`app.go:723-736`), with synchronous flushes on
shutdown, sign-off, and explicit removals. `flushHistory` skips empty sets
specifically to survive the sign-off race where `Store.Reset` has already
cleared everything (`app.go:742-759`).

---

## 11. Known dead code and stale comments

Found while writing this. None are urgent; all are the kind of thing that makes
the codebase read as larger and more mysterious than it is.

**Dead:**
- `oscar.Dial` (`internal/oscar/transport.go:79`) — no call sites; everything
  dials through `Transport.dial`.
- `Transport.PinAddress` — implemented and tested, never set by production code.
- `EventDisconnected` (`state.go:206-208`) — declared, never emitted, no handler.
- `containsFold` (`state.go:1048-1056`) — never called.
- `BuddyList.Blocked` — populated in `internal/oscar`, never read outside it, so
  a blocked non-buddy is invisible to the state layer.
- `ICBMEventGone` — defined, never sent.
- `ICBMHostAck` — requested on every send, never handled.
- Bound to JS but absent from `bridge.ts` entirely: `ForgetOtherDevices`,
  `DeviceCount` (whose doc comment says it exists "so the settings panel can
  show it"; the settings panel does not call it).
- In `bridge.ts` but never called by any UI code: `getGroups`,
  `requestAwayMessage`, `setTLS`, `connectionSecure`, `clearCustomSounds`,
  `setE2EEEnabled`. The last three track features that were deliberately made
  non-optional — the Go method and the binding outlived the UI that called them.
- `e2ee.SafetyNumber` (single-key, `e2ee.go:80`) — production uses
  `SafetyNumberSet`.

**Stale:**
- `internal/oscar/transport.go:53-54` says *"The OSCAR server is plain TCP with
  no TLS handshake"* — beside the timeout constant used by both dial paths,
  including the TLS one. The deployment is TLS-only.
- `app_e2ee.go:700` — the `DeviceShare` handler calls `publishProfile()`, which
  used to publish the merged device list via the profile marker and now publishes
  only the bio. Not a live bug (the approving device already publishes the merged
  list at `:933`, and every device republishes itself on sign-on), but the call
  no longer does what it was written to do.

---

## 12. What this document does not cover

- **The trust model.** See [`trust-model.md`](trust-model.md), and read the
  status line at the top of it before believing anything in it is implemented.
- **BENCoscar**, the server fork. It is a separate repository and the authority
  on wire behavior when the two disagree.
- **Forward secrecy and group membership cryptography.** Neither exists. One
  long-term key per device does everything; room membership changes are not
  handled cryptographically.
