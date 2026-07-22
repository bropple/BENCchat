# Trust model: where it is, and where it should go

**Status: the argument, not the state of the code. Its conclusion was built.**

The fix this document argues for — an account identity key that cross-signs
device keys — **exists**. See [`keydir-v2-proposal.md`](keydir-v2-proposal.md)
for the wire design that was actually implemented and
[`how-it-works-today.md`](how-it-works-today.md) for current behaviour.

Read this document for the *reasoning*: the table of approaches already ruled
out, and why enforcement has to live in the things holding keys rather than in a
server policy check. That reasoning is still correct and still worth reading
before designing anything here.

The one question it left open — how the server could ever know WHICH DEVICE is
asking — is answered at the end of this document, decided 2026-07-21.

What is now **wrong** is "The problem" immediately below. The password is no
longer the sole root of trust: a password-holder cannot sign a manifest under
the existing identity, cannot insert a device unnoticed, and cannot read
anything sent before it arrived. It *can* still authenticate a session and send
as the account, and it can publish a **new** identity — which is loud, because
every peer's safety number moves, but which also destroys the old identity
permanently. Read the section below as the starting position, not the end one.

## The problem (historical — see status above)

**The password is the root of trust, and everything else is built on sand.**

Anyone holding the account password fully owns the account. They can sign in,
publish a device, read every message sent afterwards, remove the owner's real
devices, and change the password. No amount of client-side policy changes that,
because the client asking the question is the thing being impersonated.

Every attempt to add authority on top of it runs into the same wall:

| Idea | Why it fails |
|---|---|
| Approval dialogs | Advisory only. Publishing is self-service, so the device joins whether or not you approve. |
| A "master" device that others cannot remove | Lose the master and you can never remove it. Recovery needs an admin backdoor, which is the password problem again wearing a hat. |
| Server-enforced vouching | The server cannot tell which device is calling. A session authenticates with a password, not a device key, so any client can claim to be any device. |

That last one is worth dwelling on. Enforcement needs the server to know *which
device* is asking, and it does not. Making it know requires proof of
possession — sign a nonce with the device key — at which point the device key,
not the password, is doing the authenticating. That is the right answer, and
once it is the answer there is a much better place to put it than a server
policy check.

**A secondary problem the same fix addresses:** safety numbers change every time
a device is added, so contacts are asked to re-verify for a routine event. Every
one of those prompts spends attention on something benign and trains people to
click through the alert meant to catch an attacker.

## What correct looks like

**Root the account in a key, not a password.** The password authenticates a
*transport session*. It stops being the thing that owns the account.

### Identity key and cross-signing

Each account has a long-term **identity keypair**. That key signs each device
key. Peers verify a device against the identity key, not against a list the
server hands them.

This collapses most of the machinery we have been building:

- **The server cannot insert a device.** It cannot forge the signature. This is
  the hole the vouching proposal could not close, and it closes for free.
- **No vouching operation, no proof-of-possession handshake, no admin reset.**
  Clients ignore unsigned devices. Policy lives where it can be enforced: in the
  things holding keys.
- **Safety numbers become stable per person.** Verify a *person* once; their
  devices come along under the identity key. Adding a laptop stops being an
  event every contact must adjudicate.
- **Approval becomes a cryptographic act** — signing the new device — rather
  than a UI gesture that records a local boolean.
- **Revocation stops needing a server authority.** It becomes a signed statement
  clients honour. The tombstone machinery exists only because the server had to
  arbitrate; once signatures arbitrate, a malicious or rolled-back server cannot
  undo a revocation.

### What this actually buys, given the operator can still reset the password

A fair objection: if an operator can reset the password, what has been gained?

**Not "the operator cannot get in."** Nobody can promise that — they control the
server and the account. What changes is that they can no longer do it *quietly*.

Today: reset the password, sign in, publish a device, read everything sent from
then on. The account keeps working, so the owner may never notice. Contacts see
a safety number change — but they see one every time the owner adds a laptop, so
the intrusion is camouflaged by a routine event.

After: the same reset gets them a session and nothing else. They cannot sign a
device under an identity key they do not hold, so every client ignores their
device and they receive nothing readable. Their only route is to clear the
identity binding and start a new one, which is immediately visible to the owner —
their devices stop working — and unambiguous to contacts, because safety numbers
no longer change for device additions. An identity change is the only thing that
moves one.

Stated as a property:

> An operator can **destroy** an identity or **replace** it, but cannot
> **become** someone without everyone finding out.

The second-order effect is the more valuable one. Removing routine
safety-number churn is what makes the warning mean anything: an alert that fires
every time someone buys a laptop is an alert people learn to click through, and
then it is not there when it matters.

### Recovery

The identity key is backed up encrypted under a key derived from a **recovery
passphrase** the user keeps. Losing every device is recoverable without an
operator.

Deliberately not an admin reset endpoint: an operator who can restore an account
is an operator who can take one over, which reintroduces exactly the property we
are removing.

### Beyond cross-signing

Two further gaps, listed for completeness. Both are large and neither blocks the
above.

**Forward secrecy.** One long-term key does everything today, so ciphertext
captured now is readable by anyone who later obtains a key. The fix is X3DH plus
a Double Ratchet, which also brings **prekeys** — the proper mechanism for
messaging an offline peer, which the key directory currently approximates.

**Groups.** Rooms use a symmetric key with per-sender Ed25519 signatures.
Membership changes are not handled cryptographically. MLS is the modern answer;
sender keys are the simpler one.

## What survives

Most of the recent work is reusable:

- **The key directory (foodgroup `0xBE00`)** becomes the store for *signed*
  device bundles and, later, prekeys. Wire format, schema and routing all stand.
- **Native TLS, argon2id, the deployment and reset scripts** are unaffected.
- **Device removal and restore** remain as user-facing concepts; their
  enforcement moves from server tombstones to signatures.

What gets discarded is mostly what this week produced: approval-as-policy,
server-side enforcement, and the master/vouching designs that never shipped.

## How this bites

Stated plainly, because the failure modes are the point of writing it down.

1. **It is a trust-model change, not a patch.** Device keys are re-issued under
   the identity key. Safety numbers change once, for everyone, at cutover — and
   that is the last time they change for a device addition.

2. **Lose every device *and* the recovery passphrase and the cryptographic
   identity is gone** — along with any history that existed only on those
   devices.

   The *account* is not gone. An operator can still delete, recreate and
   password-reset it through the management API exactly as today; none of this
   touches that. What cannot be recovered is the identity key, and the recovery
   is to clear the account's identity binding and bootstrap a fresh one. Every
   contact then sees the safety number change, which is correct: cryptographi-
   cally you are a new person, and nobody can prove otherwise.

   That asymmetry is the whole design, stated once: **an operator who can
   restore your identity is an operator who can take it over.** So the operator
   keeps the account and loses the identity, deliberately.

   This does need one admin operation that does not exist yet — clearing an
   account's device keys and identity binding so it can bootstrap again. That is
   a directory operation, not an account one, and it is safe precisely because
   it destroys rather than restores.

3. **The recovery passphrase is a new thing to lose.** It is now the account. A
   weak one is a weak account, and it cannot be rate-limited the way a login can.

4. **A device with no signing key cannot participate.** Older installs, or a
   keyring that failed at the wrong moment. Needs a defined path, not an
   assumption.

5. **Cutover is the risky moment.** Between old clients and new ones, two trust
   models coexist. Either the directory carries both forms for a period, or
   there is a flag day. A flag day is simpler and honest for a deployment this
   size.

6. **It does not defend against a compromised device.** Whoever holds a signed
   device key is that device until it is revoked. Nothing here changes that.

## What it does not solve

- **Metadata.** The server still sees who talks to whom and when. TLS hides that
  from the network, not from the server.
- **A malicious server denying service.** It cannot forge or insert, but it can
  refuse to serve, drop messages, or serve a stale device list. Detecting
  staleness needs signed, monotonic device lists — worth considering, not
  included above.
- **Someone with your unlocked machine.**

## Staging

**Cross-signing alone, first.** It is the smallest change that makes the rest
coherent, and it subsumes the entire master/vouching/enforcement question. Weeks,
not months. Everything else is optional afterwards.

Rough order:

1. Identity keypair, generated on first sign-on, held in the OS keyring.
2. Recovery passphrase, and encrypted backup of the identity key.
3. Device keys signed by the identity key; the directory carries the signature.
4. Clients verify signatures and **ignore unsigned devices**. This is the flag
   day.
5. Safety numbers computed from identity keys rather than device key sets.
6. Revocation as a signed statement.

Only then, if wanted: the Double Ratchet, then MLS.

## Open questions

- **Does the identity key ever rotate?** If it does, every contact re-verifies,
  so it should be rare and deliberate. If it never does, a compromised identity
  key is unrecoverable. Probably: rotation exists, is loud, and is treated as
  "this is a new person" by peers.
- **Is the recovery passphrase mandatory?** Making it optional means most users
  will not have one and will lose their account. Making it mandatory adds
  friction at exactly the moment a new user is least invested.
- **Flag day or dual-format?** Given the deployment is a handful of accounts, a
  flag day is probably right — but it means every client updates together.
- **Do we want signed device lists** (monotonic counter) to detect a server
  serving a stale set? Cheap to add later; awkward to retrofit.


---

## Device authentication: the decision, and how it lands

**Decided 2026-07-21.** This section answers the question the document opens
with — *the server cannot tell which device is asking* — and records the shape
that was chosen, because the rollout has a foot-gun in it that is worth writing
down before somebody meets it.

### The rule

**An account with no devices may sign in with a password alone. An account with
devices must prove it holds one of them.**

That single rule covers bootstrap and enforcement together. A brand-new account —
one an administrator has just provisioned — has published no manifest, so the
password is all there is and the first device can get in to publish itself. From
the moment a manifest exists, a session must demonstrate possession of a device
signing key that appears in it.

It also supplies its own recovery path, which is the part worth noticing. Somebody
who loses every device cannot get in, by design; the fix is for an administrator
to clear the account's device list, which returns it to the zero-device state and
therefore to password auth. That is the same operation as provisioning, not a
special-cased backdoor bolted on afterwards.

### What it fixes, and what it does not

**Fixes:** a removed device that ignores the removal signal. It is no longer in
the manifest, so it cannot answer a challenge, so it does not get a session. Until
now every check in `benco_keydir.go` was advisory precisely because this was not
true.

**Does not fix:** somebody with the password publishing a NEW identity and their
own device, then authenticating as that. `PublishManifest` accepts an unfamiliar
identity and restarts the counter, so a password-holder can still take the account
over. Device auth makes that the *only* route rather than one of two, and it stays
loud — a new identity moves every peer's safety number — but it is not closed.
See K3 in the findings for the archive that makes it recoverable.

### Where the check goes

**Not in the login exchange.** FLAP sign-on is a single request and response, and
a challenge needs a nonce the server chose, so folding it in would mean
restructuring the one path whose failure locks everybody out — including whoever
would fix it.

Instead the server challenges **just after sign-on**, over the BENCO foodgroup,
and closes the connection if the answer does not arrive or does not verify. The
session, not the login, is what gets authenticated. Same effect, and password auth
is left exactly as it is.

The server needs no new storage for this: it already decodes and validates the
device list at publish time (`foodgroup/benco_keydir.go`), and the manifest blob
is kept, so the signing keys can be read back out of it at challenge time. A
denormalised index would be a second copy to keep honest for no gain.

### The rollout, which is the dangerous part

This is an authentication change. Enforced from the first deploy, a bug in it
locks out every account that has a device — which is all of them — and the
management API on its unix socket becomes the only way back in.

So it ships with three modes: **off**, **log** (verify, record the outcome, allow
either way) and **enforce**. First deploy runs in `log` long enough to see real
sessions passing, then flips. "If you do not support the protocol you do not get
to talk" is the right design; it is not a reason to find out in production
whether the implementation agrees.

Client and server must also land together, since a client that cannot answer is
indistinguishable from one that should not be allowed to. `log` mode covers that
window too.
