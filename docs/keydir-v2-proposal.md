# Key directory v2: cross-signing on the wire

**Status: proposal.** Nothing here is built. It exists to be argued with before
it becomes a server change you have to live with, because `0xBE00` is BENCchat's
own foodgroup and BENCoscar is the only implementation — which makes it easy to
change now and annoying to change once accounts depend on it.

Read [`how-it-works-today.md`](how-it-works-today.md) for what exists.
[`trust-model.md`](trust-model.md) is the argument that led here; this document
supersedes its wire-level sketch in one respect, flagged in §3.

## 1. What was decided

- **Cross-signing**, not one key per account. Chosen for blast radius: a stolen
  laptop should be a stolen laptop, not a stolen identity.
- **The identity-key backup lives server-side**, encrypted, fetched with the
  account password and decrypted with a secret the server never sees.
- **The recovery key is mandatory and generated**, not chosen: ten words from a
  2048-word list, hyphen-separated, ~110 bits. Generated because the blob is
  attackable offline with no rate limiting, and a human-chosen passphrase loses
  that fight. "Write this down" is also less friction than "invent something
  strong."
- **An algorithm identifier on every key and signature**, so a later
  post-quantum migration is a version bump rather than a second flag day.

## 2. What v1 looks like now

`BENCODevice` is `{BoxKey, SignKey}` and nothing else. Publish replaces the
whole list; the server takes the screen name from the session, so an account can
only publish for itself. Revocation is a server-side tombstone that refuses a
key's return, and restore lifts it.

The server is the authority, and that is precisely the problem: it can insert a
device, drop one, or serve a stale list, and no client can tell.

## 3. The change that matters: sign the manifest, not the devices

`trust-model.md` proposed the identity key signing **each device key**. Signing
the **whole list once**, with a counter, is strictly better and no more work.

Per-device signatures stop the server forging a device. They do **not** stop it
*omitting* one, or serving an older set — each signature is individually valid,
so any subset looks legitimate. That is the gap the doc filed under "detecting
staleness needs signed, monotonic device lists — worth considering, not
included."

A signed manifest closes all three at once:

| Attack | Per-device signatures | Signed manifest |
|---|---|---|
| Insert a device | blocked | blocked |
| Omit a device | **undetectable** | blocked (list signed as a whole) |
| Serve an older list | **undetectable** | blocked (counter must not go backwards) |
| Undo a revocation | needs tombstones | blocked (revocation *is* a higher counter) |

Revocation stops being a separate mechanism. Removing a device means publishing
a manifest without it at `counter + 1`. Clients remember the highest counter
seen per peer in the existing trust store and refuse anything lower, so a
rolled-back or malicious server cannot resurrect a removed machine.

**The manifest must travel as opaque bytes.** The server stores and returns
exactly the bytes that were signed — it must not decode and re-encode them, or
any encoding difference breaks every signature. This is the single most
important implementation note in this document.

## 4. Proposed wire format

Payload version becomes `2`. `BENCOKeyDirVersion` bumps; the foodgroup number is
unchanged.

### Keys carry their algorithm

```go
// BENCOKey is a public key plus the algorithm it belongs to. The identifier is
// what makes a post-quantum migration a version bump instead of a flag day.
type BENCOKey struct {
    Alg uint8                          // see the algorithm table
    Key []byte `oscar:"len_prefix=uint16"`
}
```

| Alg | Meaning | Used for |
|---|---|---|
| `0x01` | X25519 | message key agreement |
| `0x02` | Ed25519 | signatures |
| `0x03` | ML-KEM-768 | reserved — post-quantum key agreement |
| `0x04` | ML-DSA-65 | reserved — post-quantum signatures |

Reserved values are not implemented. They exist so that adding them later does
not require renegotiating anything.

### A device

```go
type BENCODeviceV2 struct {
    Box   BENCOKey                        // X25519 today
    Sign  BENCOKey                        // Ed25519 today
    Label string `oscar:"len_prefix=uint8"` // optional, may be empty
}
```

`Label` is new and **optional** — a human name ("desktop", "thinkpad") so the
device list stops being a wall of fingerprints. Note the tradeoff: it is
metadata the server can read, and it tells anyone with the account password what
hardware exists. It is inside the signed manifest, so the server cannot forge
it, but it cannot be hidden from the server either. Reasonable to ship empty by
default and let the user fill it in.

### The manifest

```go
// The signed statement. Encoded once, signed, and thereafter treated as opaque
// bytes by everything that is not verifying it.
type BENCOManifest struct {
    Version    uint16
    ScreenName string   `oscar:"len_prefix=uint8"` // binds the list to an account
    Counter    uint64                              // monotonic, never reused
    Identity   BENCOKey                            // the account identity public key
    Devices    []BENCODeviceV2 `oscar:"count_prefix=uint16"`
}
```

`ScreenName` is inside the signature deliberately: without it, a manifest lifted
from one account could be replayed onto another.

### Publish and query

```go
type SNAC_0xBE00_0x0002_PublishRequestV2 struct {
    Version   uint16
    Manifest  []byte `oscar:"len_prefix=uint16"` // encoded BENCOManifest, verbatim
    SigAlg    uint8
    Signature []byte `oscar:"len_prefix=uint16"` // over Manifest, by Identity
}

type SNAC_0xBE00_0x0003_PublishReplyV2 struct {
    Accepted uint8  // 1 = stored
    Counter  uint64 // what the server now holds, so a client can detect a race
}

type SNAC_0xBE00_0x0005_QueryReplyV2 struct {
    ScreenName string `oscar:"len_prefix=uint8"`
    Present    uint8  // 0 = no manifest published; not an error
    Manifest   []byte `oscar:"len_prefix=uint16"`
    SigAlg     uint8
    Signature  []byte `oscar:"len_prefix=uint16"`
}
```

### Identity backup

Two new subgroups:

```go
BENCOKeyDirPutBackupRequest  uint16 = 0x000A
BENCOKeyDirPutBackupReply    uint16 = 0x000B
BENCOKeyDirGetBackupRequest  uint16 = 0x000C
BENCOKeyDirGetBackupReply    uint16 = 0x000D

type SNAC_0xBE00_0x000A_PutBackupRequest struct {
    Version uint16
    KDF     uint8                            // 0x01 = argon2id
    Params  []byte `oscar:"len_prefix=uint16"` // time, memory, parallelism
    Salt    []byte `oscar:"len_prefix=uint16"`
    Blob    []byte `oscar:"len_prefix=uint16"` // secretbox(identity private key)
}

type SNAC_0xBE00_0x000D_GetBackupReply struct {
    Present uint8 // 0 = none stored
    KDF     uint8
    Params  []byte `oscar:"len_prefix=uint16"`
    Salt    []byte `oscar:"len_prefix=uint16"`
    Blob    []byte `oscar:"len_prefix=uint16"`
}
```

The KDF parameters travel with the blob so they can be raised later without
stranding existing backups.

## 5. The decision I can't make for you

**Who holds the identity private key, and for how long?**

This determines whether cross-signing actually delivers the blast-radius
property you chose it for, and it is not a detail.

The identity key is needed to sign a *new* device. It is not needed to send or
read messages. So there is a real choice:

**(a) Devices keep it after first unlock.** Approving a new device is one click
from any existing device. But every device then holds the identity key, and
compromising any one of them compromises the identity — which is the property
you rejected the account-key model to avoid. This quietly undoes the decision.

**(b) The identity key is transient.** It is fetched from the backup, used to
sign, and discarded. Signing a new device requires the ten-word recovery key,
every time. A stolen laptop yields that device's key and nothing more.
Cost: linking a device means finding where you wrote your recovery key.

**(c) Matrix's split.** A master key that stays in the backup and is almost
never used, plus a self-signing key that devices retain and use to sign new
devices. A compromised device gets the self-signing key — the attacker can add
devices but cannot replace the identity, and the master key can revoke them.
Cost: two keys, two lifecycles, meaningfully more code.

**My recommendation: (b).** Device linking is rare — a handful of times per
device, ever — and it is exactly the moment when friction is appropriate,
because it is the one moment the security decision is real. (a) would hand back
the property you just chose to pay for. (c) is the right answer at Matrix's
scale and more machinery than a deployment this size needs.

If (b) proves annoying in practice, (c) is a clean upgrade later; (a) is not
something you can walk back, because by then the key is on every machine.

## 6. What the server still cannot do

Worth restating, because it is easy to read a signature-bearing protocol as
making the server trustworthy:

- **It still cannot tell which device is talking to it.** A session
  authenticates with a password. Every server-side check remains advisory; the
  signatures are what actually bind anything.
- **It can still refuse service, drop messages, or return nothing.** Signatures
  prove authenticity, not availability.
- **It still sees all metadata** — who talks to whom, when, how many devices
  exist, and their labels if set.
- **Tombstones become redundant.** The manifest counter supersedes them. Keeping
  them is harmless defence in depth, but they are no longer load-bearing and
  should not be treated as a security boundary.

## 7. Migration

A flag day, as `trust-model.md` concluded. At a handful of accounts, carrying
both formats is more risk than the cutover it avoids.

1. BENCoscar learns v2 while still serving v1.
2. Clients update, generate identity keys, and publish v2 manifests.
3. Clients start **ignoring unsigned devices**. This is the flag day.
4. v1 support is removed from the server.

Safety numbers change once, at step 2, for everyone — and that is the last time
they change for a device addition, which is the entire point.

**One thing to get right in step 2:** publishing a v2 manifest requires the
identity key, which requires the recovery key to exist. So recovery-key
generation has to happen at first v2 sign-on, before anything can be published.
That makes it the first thing a user sees after updating, which is the correct
place for it and worth designing rather than bolting on.

## 8. Open questions

- **Counter persistence across an identity reset.** If an account clears its
  identity and bootstraps a new one, does the counter restart? It must, or the
  new identity inherits the old one's numbering — but clients remembering the
  old high-water mark would then reject the new manifest. Probably: the counter
  is scoped to an identity key, and a new identity resets it, with clients
  keying their high-water mark on `(identity, counter)` rather than counter
  alone. Needs to be settled before implementation, not after.
- **Does the label belong on the wire at all?** It is genuinely useful and
  genuinely metadata. An alternative is keeping labels purely local, which costs
  nothing on the wire but means each device names the others separately.
- **Should the manifest carry a timestamp** as well as a counter? A counter
  detects rollback; a timestamp would additionally bound how stale a served
  manifest can be. Cheap to include now, awkward to add later.
- **What happens to a device signed by an identity that is later replaced?**
  Nothing automatic — its signature no longer verifies under the new identity,
  so it simply stops being accepted. Worth confirming that reads as intended
  rather than as a bug.
