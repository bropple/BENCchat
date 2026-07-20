# Group chat: consent and membership

**Status: proposal, not built.** The design for who can be in an encrypted room
and how they get there, decided against the consensual-connections model. Read
`how-it-works-today.md` §8 for how rooms work now, and the connections work (in
progress) for the 1:1 authorization model this sits beside.

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

## 7. Open questions

- **Does adding a member rotate the key?** Rotating on join gives the newcomer no
  cryptographic access to pre-join history (they can still be *sent* it via
  catch-up, but only deliberately). Not rotating means the new key equals the old
  and history is readable by default. Leaning: rotate on membership change, so
  history-sharing is an explicit act, not a default.
- **Owner succession.** If the owner of a gated room leaves or loses their
  identity, who can admit members? Needs a defined answer or the room ossifies.
- **Can an open room be converted to owner-gated, or vice versa?** And who may
  convert it? Cheap to allow the owner; awkward if anyone can.
- **How is "the owner" recorded and proven** in a relay-only, symmetric-key room
  where nothing is cryptographically enforced? It is a client convention like the
  rest — worth being explicit that it is not a cryptographic role.
