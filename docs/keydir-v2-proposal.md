# Key directory v2: cross-signing on the wire

**Status: proposal, fully specified.** Nothing here is built, but every question
it opened has been answered — see §9 for the decisions and the reasoning behind
each. It exists to be argued with before it becomes a server change you have to
live with, because `0xBE00` is BENCchat's own foodgroup and BENCoscar is the only
implementation — which makes it easy to change now and annoying to change once
accounts depend on it.

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
- **The identity key is transient** — fetched from the backup, used to sign a
  device, discarded. Linking a device costs the recovery key every time. See §5.
- **An identity change is always loud**, never silently accepted, and a device
  that has been cut off detects it itself and says so. See §6.
- **The recovery key is shown exactly once**, and that is a consequence of
  transient custody rather than a policy. The backup can be re-keyed later, but
  only while the user is proving they still hold the current key. See §10.
- **First run takes the whole window** and cannot be left until the key has been
  copied or saved. See §12.
- **Possession is never re-confirmed afterwards**, accepting that a lost key may
  go unnoticed for years. See §13.

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
    Counter    uint64                              // monotonic within an identity
    IssuedAt   uint64                              // Unix seconds, UTC
    Identity   BENCOKey                            // the account identity public key
    Devices    []BENCODeviceV2 `oscar:"count_prefix=uint16"`
}
```

`ScreenName` is inside the signature deliberately: without it, a manifest lifted
from one account could be replayed onto another.

**`Counter` and `IssuedAt` do different jobs and only one of them is
authoritative.** The counter orders manifests and is the rollback defence — it
is the only field a client may use to reject a manifest as stale. `IssuedAt` is
advisory: it bounds how old a served manifest can plausibly be and gives the UI
something to show ("this device list is three months old"), but a client must
**never** reject a manifest on timestamp alone. A wrong clock on either side is
far more likely than an attack, and a client that hard-rejects on time would
brick a conversation over a dead CMOS battery. Always UTC seconds; never local
time, never a formatted string.

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

## 5. Identity-key custody

**Who holds the identity private key, and for how long?** **Decided: (b),
transient.** The reasoning is kept in full because this is the decision that
determines whether cross-signing delivers anything, and a future reader
proposing (a) on convenience grounds needs to see why it was refused.

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

## 6. Identity change, and telling a device it is out

Two of the open questions turned out to be the same mechanism, so they are
answered together here.

### The counter is scoped to an identity

A client's high-water mark is keyed on **`(identity key, counter)`**, not on the
counter alone. A new identity starts at `1` without that looking like a
rollback, and a manifest signed by the identity you already know still cannot go
backwards.

### An identity change is loud, and cryptographically ambiguous

When a client fetches a manifest signed by an identity key it does not
recognise, that is one of exactly two things:

- the account holder lost everything and bootstrapped a new identity, or
- someone with the password cleared the identity and installed their own.

**These are indistinguishable, and no amount of protocol design makes them
distinguishable.** That is not a gap — it is the property `trust-model.md`
argued for, stated as a positive: an operator can *destroy* or *replace* an
identity, but cannot *become* someone without everyone finding out.

So the rule is: an unrecognised identity is **never** accepted silently. It is
surfaced to the human, and the copy must not reassure. "This may be normal" is
the wrong message; the honest one names both possibilities and says the only way
to tell them apart is to ask the person out of band.

This is also the one event that moves a safety number now, which is what makes
it worth reacting to.

### A device can tell it has been cut off — and should say so

A device that is no longer accepted can detect it *itself*, from signed data,
by querying its own account. Two distinct cases, deserving different words:

| What the device sees | What happened | What it should say |
|---|---|---|
| Manifest signed by the identity I know, and my device key is **not in it** | Removed by another device | "This device was removed from your account. It can't read new messages. Approve it again from a device that's still linked." |
| Manifest signed by an identity I **don't** know | The account's identity was replaced | "This account's identity was replaced. This device is no longer part of it, and everything it holds is now unreadable to the account." |

This is a real improvement on the existing `DeviceDeny` message, which its own
comment calls "a courtesy, not a boundary" — an unencrypted instant message that
could be dropped, spoofed, or simply missed while offline. Detection here is
derived from a signed manifest the device fetched itself, so it is reliable,
survives being offline, and cannot be forged by the server or by anyone holding
the password.

It remains a courtesy in the sense that nothing *forces* the device to act. But
it changes the failure mode from "messages silently stop being readable and
nobody knows why" to a specific, correct explanation, which is the whole reason
to bother.

**Follow the existing precedent for what happens next**: `DeviceDeny` signs the
device out and clears its saved password, so the next launch does not walk
straight back into the same state. Removal detected this way should do the same.

## 7. What the server still cannot do

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

## 8. Migration

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

## 9. Resolved

The questions this document opened, and how they were settled.

- **Identity-key custody → (b), transient.** Fetched from the backup, used to
  sign, discarded. Linking a device costs the recovery key every time. A stolen
  laptop yields that device's key and nothing more, which is the property
  cross-signing was chosen for; (a) would have handed it back, and (c) is a
  clean upgrade later if the friction proves unreasonable.
- **Counter across an identity reset → scoped to the identity.** High-water mark
  keyed on `(identity, counter)`. See §6.
- **Label on the wire → yes.** Accepting that it is metadata the server can
  read. It is inside the signed manifest so it cannot be forged, and shipping it
  empty by default keeps the choice with the user.
- **Timestamp → yes, alongside the counter, UTC seconds.** The counter stays
  authoritative for ordering and rejection; the timestamp is advisory only. See
  the note in §4.
- **A device signed by a replaced identity → stops being accepted, and is told.**
  It detects this itself from the signed manifest. See §6.

## 10. First run, and re-keying

### Which flow a client is in is answered by the directory

No server-side "has this account ever signed in" flag is needed. An account the
sysadmin created and nobody has used is exactly an account with no identity
backup, and `GetBackup` already reports that:

| `GetBackup` | Meaning | Flow |
|---|---|---|
| `Present = 0` | never bootstrapped | generate an identity, show the recovery key once |
| `Present = 1` | an identity exists | prompt for the recovery key to link this device |
| `Present = 1`, key lost | unrecoverable | admin clears the identity; back to row one |

That third row is the destroy-and-rebootstrap operation `trust-model.md`
identified as the one admin capability worth having, and it is safe precisely
because it destroys rather than restores. Every contact sees the safety number
change, which is correct: cryptographically that is a new person, and nobody can
prove otherwise.

### The recovery key genuinely cannot be shown twice

This is a property of §5's custody decision, not a policy the UI enforces.
Nothing retains the recovery key — it is used to derive a wrapping key and
discarded — so there is nothing to redisplay. The screen should say so plainly
rather than hedging, because a user who suspects it can be recovered later will
not write it down.

Show it once, with copy-to-clipboard, and make continuing require an
acknowledgement that it has been saved somewhere.

### Re-keying the backup: possible, at exactly one moment

Re-encrypting the backup under a **new** recovery key is safe, and it is not the
same thing as a new identity. Distinguishing them matters:

|  | Devices stay signed? | Safety numbers change? |
|---|---|---|
| **Re-key the backup** — same identity, new recovery key | yes | **no** |
| **New identity** — everything re-issued | no | yes, for everyone |

The identity key never leaves; only the passphrase-derived wrapping around it
changes. So a user who thinks their written-down key was seen does **not** need
a new account, and does not disturb anybody.

The catch is when this can happen. Under transient custody the identity private
key exists in memory only while the user has just supplied the current recovery
key — so that is the only safe moment to offer a re-key, and it is a natural
one: *"you've just entered your recovery key. Replace it with a new one?"* It
requires proving possession of the old key, which is exactly the right bar.

It also gives argon2id parameters a place to be raised later, since `PutBackup`
carries them.

**If the recovery key is lost, there is no re-key** — the plaintext identity key
cannot be reached, and the only route is the destroy-and-rebootstrap above. That
is the honest cost of the design, and it is the same reason an operator cannot
quietly take an account over.

### Losing the recovery key while devices still work

Worth stating because it is not obvious: it is a degradation, not an immediate
catastrophe. Existing devices keep working — their keys are already signed and
messages keep flowing. What is lost is the ability to **change** the device list:
no new device can be linked and none can be revoked, because both require
signing a new manifest.

So the failure is slow. It surfaces the day a laptop is replaced, which may be
long after the key went missing. A client should therefore treat "can you still
produce your recovery key?" as worth asking occasionally, rather than assuming
silence means everything is fine.

## 11. Rejected: periodic manifest re-publishing

Considered and dropped, because it is **incompatible with §5**.

The idea was to re-publish the manifest on a schedule so `IssuedAt` stays fresh,
letting a client distinguish a genuinely idle account from a server withholding
updates. It cannot work: re-publishing means signing, signing requires the
identity key, and under transient custody that key is only available while the
user is entering their recovery key. Automatic re-publication would mean
prompting for the recovery key on a timer, which is absurd.

Pre-signing future manifests would dodge that and is worse — it would mean
signed statements sitting around asserting a device list that has not been
checked, which is the opposite of what signing them was for.

**What this gives up:** a client cannot bound how stale a served manifest is. A
malicious server can serve a correctly-signed, correctly-countered, very old
manifest indefinitely, and the only signal is `IssuedAt` looking old — which,
per §4, is advisory and must not by itself cause a rejection.

That is an acceptable loss here. The attack requires a hostile server, gains
only the suppression of device-list *changes* (it cannot forge, insert, or roll
back), and the deployment's operator is the person reading this. Worth
revisiting if that ever stops being true.

## 12. The first-run screen

**Full window, and no way past it until the key has been copied.**

Not a dialog over the roster, not a dismissible panel — the whole window, with
no other affordance. This is the only screen in BENCchat where dismissing it
without reading costs the user something unrecoverable, and it is the one moment
where blocking is proportionate. Sign-on has already happened at this point; the
account is unusable until the identity exists anyway, so nothing is being held
hostage that would otherwise work.

Requirements:

- The key rendered large and unambiguous, as ten hyphen-separated words.
- A copy button. **Continuing is disabled until it has been used.**
- Text stating plainly that it will not be shown again — which is true, not a
  policy (§10), and should be phrased as a fact about the system rather than a
  warning about behaviour.
- No "remind me later", no close button, no escape key.

### Two things the gate does not achieve, worth knowing

**Copied is not saved.** The clipboard is the strongest signal available
client-side, and it is still only proof that a button was pressed. A user can
copy and never paste. The gate forces a deliberate action, which is worth
having, but it should not be described — internally or in the copy — as
confirming the key is safe.

**The clipboard is not a private place.** Clipboard managers keep history, and
some sync it across machines or to a phone. Putting a ~110-bit account secret
there is a real if minor exposure, and on a compromised machine it is a
significant one. This is an accepted cost of making the gate an action the user
can actually perform, but it argues for also offering **save to a file** as an
equally valid way to satisfy the gate: it persists (unlike a clipboard that gets
overwritten), and it skips the clipboard entirely for users who would rather it
did.

### If the clipboard is unavailable

Some environments have no clipboard access at all. A gate that cannot be
satisfied would leave the account permanently unusable, which is a worse outcome
than any it prevents — so the save-to-file path above doubles as the escape
hatch, and at least one of the two must always be available.

## 13. Recovery-key possession is never re-confirmed

**Decided: never.** No periodic prompt, no nag, no "can you still find your
recovery key?" check.

Recording the cost, because it is real and was accepted deliberately rather than
overlooked. Combined with the slow failure in §10 — devices keep working, only
the ability to change the device list is lost — this means a user can lose their
recovery key and not discover it for years. The discovery moment becomes the day
they replace a laptop and cannot link the new one, which is both the worst time
to find out and long past when anything could have been done about it.

The counter-argument for a periodic check is that it converts a silent loss into
a noticed one while re-keying is still possible (§10). The argument against, and
the one that won: a prompt that fires when nothing is wrong is a prompt people
learn to dismiss, and this project has already established — with safety-number
churn — that an alert which fires during normal use is not there when it
matters.
