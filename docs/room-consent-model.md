# Group chat: consent and membership

**Status: proposal, not built — except §7, which records decisions.** The design
for who can be in an encrypted room and how they get there, decided against the
consensual-connections model. Read `how-it-works-today.md` §8 for how rooms work
now, and `SECURITY-FINDINGS.local.md` for the room work already landed (R1–R4,
K6) — the roster now travels with the key, removal exists, and removing a device
re-keys the rooms it could read.

§7 (roles and authority) is **decided but unbuilt**: owner and mod, roles as
signed statements the server stores and enforces. Nothing else here is built.

The organizing idea: **a group invite carries two separate consent questions,
and a single room-type choice answers both.**

---

## 1. The two consent questions

Every add to a group is really two questions, and conflating them is where group
privacy models go wrong:

1. **Does the invitee want in?** (invitee consent)
2. **Do the people already in the room accept the newcomer?** (member consent)

The scenario that forces the distinction: A, B, C are connected and in a room. B
invites D, a stranger to A and C. Question 1 is between B and D and is easily
handled. Question 2 — *A never agreed to be in a room with D* — is the one a
naive "invitee accepts, done" design silently skips.

---

## 2. Invitee consent: a hybrid, by the inviter's relationship

**You can directly invite your own connections; inviting someone you are not
connected to goes through an accept-first channel.**

- **Invite a connection.** Direct. They still get a join prompt (nobody is
  dropped into a room silently), and the room key is delivered on accept.
- **Invite a stranger.** The invite travels as a native OSCAR chat-invitation
  SNAC — which the server CAN see is an invitation, unlike an E2EE message it
  cannot read — so it is exempt from the 1:1 messaging gate but rate-limited and
  declinable. On accept, a one-time key delivery follows (the invitee's device
  keys come from the directory, which is ungated).

This keeps the common case (add a friend) frictionless and the "reach someone I
have no relationship with" case possible but gated and spam-resistant.

**Why the native-invite channel matters, precisely:** the room key rides the 1:1
E2EE path, and the connections gate blocks that path to non-connections. The
server cannot carve out "but allow room invites," because a room invite and a
message are both opaque ciphertext to it — the "this is an invite" marker is
inside the envelope. So a stranger invite has to travel a channel the server can
identify as an invitation. That is the native chat-invite SNAC. Without this, the
gate would silently make it impossible to invite anyone you are not already
connected to.

---

## 3. Member consent: two room types

Question 2 — whether existing members accept a newcomer — is answered by which
of two room types the creator chose.

### Open room (transparent)

Any member may add their own connections. Every member is **notified** ("B added
D"), and anyone who is not comfortable with the new membership can **leave**.
Consent is ongoing — you can always leave — rather than a per-member veto.

This is how most group chats work, and it is the honest default: since a
determined member can expose a room anyway (§5), making membership changes
**visible** is worth more than pretending to prevent them.

### Owner-gated room (controlled)

Only the room owner adds members; other members' clients offer no "add" affordance,
and an add attempt routes to the owner for approval. Higher control, more
friction, for rooms where the membership is meant to be deliberate.

### What the type does NOT change

Both types deliver the same encryption, the same per-sender signatures, the same
catch-up. The difference is entirely in **who the honest flow lets add members**
and how visible it is — not in any cryptographic guarantee (§5). The type is a
social contract the clients honour, chosen once at creation.

---

## 4. The scenario, resolved

A, B, C connected and in a room; B invites D (stranger to A and C):

- **Open room:** B may add D (B and D are connected, so a direct invite; D gets a
  join prompt). A and C see "B added D." If either is unwilling to share the room
  with D, they leave. Nobody was silently exposed; the exposure was announced and
  is escapable.
- **Owner-gated room:** B cannot add D unless B is the owner. If B is not, the
  add routes to the owner, who decides. A and C are only ever in a room with
  people the owner admitted.

Either way the invitee-hybrid (§2) governs how the key reaches D; the room type
governs whether B was allowed to bring D in at all.

---

## 5. The crypto floor — what neither type can promise

Stated plainly because it caps everything above: the room key is **symmetric**.
Once a member holds it, they can read the room, and they can hand the key or the
plaintext to anyone they like. **No room type can cryptographically stop a member
from exposing the room** — owner-gating included, because the owner cannot prevent
an existing member from re-sharing the current key between rotations.

So both room types govern the **honest default**, which is most behaviour. A
malicious member defeats either one identically. This is the sender-keys /
symmetric-key ceiling; MLS is the only thing that would move it, and it is
explicitly out of scope (see the trust model).

The design consequence, and the reason the open room is not the "insecure" one:
since exposure by a determined member is unpreventable, the most honest posture
is to make membership **legible** — every member visible, every add announced —
rather than to imply a privacy the cryptography does not deliver. Owner-gating
adds deliberate control over the honest path; it does not add a cryptographic
boundary.

**A room is only as private as its least trustworthy member.** Both types. Pick
the members, not just the type.

---

## 6. What this needs, over what exists today

Rooms today: symmetric key, invite delivered over the 1:1 E2EE channel,
effectively auto-join on key receipt, catch-up P2P, rotation and reform for
membership changes.

To build this model:

- **Accept-first invites.** An invite becomes a request the invitee accepts or
  declines; the key is delivered on accept, not before. (Better regardless —
  never hand the key to someone who has not said yes.)
- **The native chat-invite channel** for inviting non-connections (§2), exempt
  from the messaging gate, rate-limited, declinable.
- **A room-type flag** at creation (open vs owner-gated), and a room-owner
  notion the client honours.
- **Membership visibility.** "B added D" / "D joined" surfaced to every member;
  a member list that shows who is present, with unverified members marked.
- **Owner-gated add routing** — non-owner add attempts go to the owner for
  approval rather than executing.

None of it touches the encryption; it is all social-layer coordination on top of
the room key that already exists.

---

## 7. Decided: roles, and where authority lives

**Decided 2026-07-21.** This section answers most of §8's questions; what remains
open is flagged there.

### Two roles. Owner and mod. No tiers.

An owner, who may promote and demote mods and transfer ownership. Mods, who may
admit and remove members. Mods cannot touch the owner or each other's role —
that asymmetry is the point, and it is the whole hierarchy.

Granular tiers exist in products with six-figure member counts, where the cost of
a role system is amortised over thousands of moderation decisions a day. Here
every extra tier multiplies the number of statements that need defining, signing,
verifying and displaying, against rooms that will have single-digit membership.
Two levels cover every case this deployment has. Adding a third later is easy;
removing one after people depend on it is not.

### The server is the authority — but it enforces, it does not decide

Roles live in BENCoscar, alongside the room rows it already keeps. This is the
pragmatic answer and it is the right one: the server is already routing every
message in the room, so it already knows the room exists, who is connected and
who is talking. Storing roles there adds nothing to what it *knows*.

It does add something to what it can *do*, and that distinction is worth being
precise about rather than waving through. A server that is merely told the roles
can be asked to enforce them. A server that *owns* the roles can invent them: it
could promote itself, demote the real owner, and eject everyone, and no client
would have grounds to object.

So: **role changes are signed statements the server stores and serves, not rows
it authors.** The owner's identity key signs "X is a mod as of counter N"; the
server keeps the statement and its signature, hands both to clients, and enforces
what they say. Clients verify before believing.

This costs very little, because the machinery already exists — the account
identity key, detached Ed25519 signatures over exact bytes, and monotonic
counters to refuse a rolled-back statement are all built and in use for device
manifests (see `keydir-v2-proposal.md`). It is the same shape applied to a
different object.

What it buys: a compromised or malicious operator can refuse to serve a room, but
cannot forge authority within one. Denial of service instead of takeover. That is
a meaningful difference even here, where the operator is the person running the
server — and it means the design does not need revisiting if BENCO ever hosts a
room for somebody it does not control.

What it does **not** buy, and nobody should imply otherwise: the server still
sees every participant, every message time and every room name. Roles are about
who may moderate, not about what the operator can read. §5 still governs that.

### Kick is enforcement, not confidentiality

Server-side removal — actually ejecting someone from a room and refusing their
rejoin — is worth building, and it is a genuinely different feature from
rotating the key. They are complementary and neither substitutes:

| | Rotation | Kick |
|---|---|---|
| Enforced by | the client, cryptographically | the server |
| Stops them | reading what is said next | being present at all |
| Cannot stop them | sitting in the room, seeing who is here and that people are talking | reading anything they already hold the key for |
| Trusts the server | no | yes, for this |

Rotation is the confidentiality boundary and stays the load-bearing one. A kick
closes the metadata gap rotation cannot: today a removed member keeps watching
the participant list and the typing indicators of a conversation they can no
longer read, and the only escape is `ReformRoom` relocating everyone to a new
name. Note that a kick asks the server to enforce something it *already observes*
— so it extends the server's power, never its knowledge.

### Owner succession, in preference order

The room must not ossify when its owner goes, and the obvious fix is the one
`trust-model.md` already rejected once: an operator who can reassign ownership is
an admin backdoor, "the password problem again wearing a hat".

That rejection was about the **identity key**, though, and the stakes are not the
same. A backdoor into identity undermines confidentiality — it hands over the
ability to impersonate. Room ownership is moderation. An ossified room still
reads, still sends, still rotates; what is lost is the ability to promote and
admit. Nothing leaks. So an operator path here is far more defensible than one
for identity, and it is still the worst of the three options:

1. **Designated succession.** The owner names a successor while they are around,
   signed like any other role change. The normal path, and the only one that
   needs no special case.
2. **Mod inheritance on inactivity.** If the owner has not been seen for a
   defined period, any mod may claim ownership. Loud: recorded, counter-bumped,
   and announced to every member. No operator involvement at all, which is what
   makes it preferable to (3) rather than merely equivalent.
3. **Operator reassignment.** A last resort, run from the server. The abuse
   concern is real and it cannot be *prevented* — an operator with database
   access can already write whatever they like, with or without a command to do
   it. What can be done is make it **visible**: record it, and have every
   member's client say plainly that the operator reassigned this room rather than
   the previous owner handing it over. Same principle that already governs
   identity takeover — not preventable, but never silent.

Build (1) and (2). Keep (3) as an explicitly-logged escape hatch, not a routine
tool, and never as the answer to "the owner is on holiday".

### What this changes elsewhere

Ownership decides who may re-key, which lands directly on work already queued.
Today any member may rotate, and the roster travels with the key on the honour
system — authenticated only as "you are a member", so any member can lie about
who else is in the room. Under this model the roster becomes part of the signed
room state, which closes that hole: verifiable rather than merely plausible.

Settle this before the ratchet work (§8's first question), because who is allowed
to advance or replace a room's key is exactly what that touches.

---

## 8. Open questions

- **Does adding a member rotate the key?** Rotating on join gives the newcomer no
  cryptographic access to pre-join history (they can still be *sent* it via
  catch-up, but only deliberately). Not rotating means the new key equals the old
  and history is readable by default. Leaning: rotate on membership change, so
  history-sharing is an explicit act, not a default.
- ~~**Owner succession.**~~ Answered in §7: designated succession first, mod
  inheritance on inactivity second, operator reassignment as a logged last
  resort.
- **Can an open room be converted to owner-gated, or vice versa?** And who may
  convert it? Cheap to allow the owner; awkward if anyone can. Still open, but
  §7 supplies the actor: it is an owner-signed statement or it does not happen.
- ~~**How is "the owner" recorded and proven**~~ Answered in §7, and the premise
  has changed: the owner IS a cryptographic role now, not a client convention.
  Ownership and role changes are statements signed by the account identity key,
  stored and enforced by the server but authored by the owner — so a server that
  invents a promotion is caught rather than obeyed.
- **How long is "inactive"** for mod inheritance? Long enough that a holiday does
  not transfer a room, short enough that a room does not ossify for a month.
  Probably weeks, and it wants a real answer before it is built.
- **Does a kick imply removal from the member list**, or can somebody be ejected
  from the room while still holding the key? They are separate operations on
  separate layers (§7's table) and conflating them in the UI would misrepresent
  what each one did.
