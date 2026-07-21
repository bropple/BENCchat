# Group chat: consent and membership

**Status: proposal, not built — except §7, which records decisions.** The design
for who can be in an encrypted room and how they get there, decided against the
consensual-connections model. Read `how-it-works-today.md` §8 for how rooms work
now, and `SECURITY-FINDINGS.local.md` for the room work already landed (R1–R4,
K6) — the roster now travels with the key, removal exists, and removing a device
re-keys the rooms it could read.

§7 (roles and authority) is **decided but unbuilt**: owner, senior mod and mod;
roles as signed statements the server stores and enforces. Nothing else is built.

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

### Three roles: owner, senior mod, mod

| | Promote / demote | Ban | Lift a ban | Kick | Removable by |
|---|---|---|---|---|---|
| **Owner** | yes | any duration | any, including a senior mod's | yes | nobody |
| **Senior mod** | no | any duration | any except one the owner set | yes | owner only |
| **Mod** | no | temp only, ≤ 1 hour | only ones set at mod tier | yes | owner only |
| **Member** | no | no | no | no | owner, senior mod, mod |

Duration is where the mod boundary sits rather than kind — see the temp ban
section below for why, and for the ceilings.

Two invariants do all the work here, and they are worth stating separately from
the table because everything else follows from them:

- **Nobody can touch the owner.** Not kicked, not banned, not demoted.
- **Only the owner can touch anyone holding a role.** A senior mod cannot remove
  a mod, and mods cannot remove each other. Roles are granted by the owner and
  revoked by the owner, full stop.

That second one is what stops the hierarchy eating itself. Without it, two mods
can remove each other and the outcome is decided by whoever acts first — a race
condition dressed up as a permission system.

The split between the tiers is a **capability boundary, not a rank**. Ban is the
more permanent act: a kicked member can be re-invited by anyone, while a banned
one needs the ban lifted first. Gating the irreversible operation higher than the
reversible one is a real distinction, which is why this is three tiers rather
than an arbitrary hierarchy.

What is still deliberately refused is granularity for its own sake. Per-room
custom roles, per-capability grants and configurable permission matrices exist in
products with six-figure membership, where the cost amortises over thousands of
moderation decisions a day. Here every extra axis multiplies what has to be
defined, signed, verified and displayed, against rooms with single-digit
membership. Three tiers with fixed capabilities is the ceiling.

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

**Kick removes from the member list. Ban additionally locks the door.**

- **Kick** = drop them from the signed member list, rotate so the key they hold
  is spent, and eject them from the room. The door is not locked: they can rejoin
  by name, hold no key, and are not a member. So a kick alone does not fully
  close the metadata gap — it evicts, and they can walk back in and watch.
- **Ban** = a kick, plus the server refusing their rejoin. This is the only thing
  that actually closes the metadata gap, and it is purely a server-side join
  check on top of everything a kick already did.

**A kick is an event; a ban is state.** That is the whole difference and it is
worth holding onto, because it decides what gets stored where. A kick happens and
is over — its effect is instantaneous and there is nothing left to preserve
afterwards, so it belongs in a log of things that occurred. A ban is a standing
condition the server consults on every join attempt, so it belongs in a list of
things that are currently true.

### Temp bans: a ban with an expiry, not a third mechanism

Wanting somebody gone for an hour rather than forever is a real need, and the
temptation is to build a "timed kick" alongside the other two. Don't: a kick is
instantaneous, so there is no such thing as a kick that lasts an hour. What that
actually describes is **a ban that expires**, and the ban record already carries
who set it, at what tier, and when. Adding *until when* is one nullable column
and a time comparison in the join check that already exists.

So there is one axis, one mechanism, and the tier gates **how long**:

| | Duration | Mod | Senior mod | Owner |
|---|---|---|---|---|
| **Kick** | none — evicted, may return at once | yes | yes | yes |
| **Temp ban** | up to 1 hour | yes | yes | yes |
| **Temp ban** | up to 3 days | no | yes | yes |
| **Perma ban** | until lifted | no | yes | yes |

**Three days is the ceiling for any temp ban.** Past that the honest description
is "banned", and dressing a month-long exclusion up as temporary helps nobody —
least of all the person on the receiving end, who is better served by being told
plainly that they are out until somebody lifts it.

**One hour is the ceiling for a mod.** Long enough to cool a room down mid-
argument, which is what the power is for; short enough that a mod acting badly or
mistakenly costs somebody an afternoon rather than a week. Anything more
consequential wants a tier that can also undo it.

This revises the earlier "mods do not touch bans at all". The rule that replaces
it is the same one as everywhere else — **the more irreversible the act, the
higher the tier** — applied to duration rather than to kind.

**Lifting follows the rule already in place** with no special case: a ban may be
overridden by an equal or higher tier than set it, so a mod-tier temp ban may be
lifted at mod tier, including by the mod who set it after a misfire. Senior mods
and the owner reach everything below them, and nothing reaches the owner.

An expired ban is not a lifted one. It stops blocking joins and stays in the log
with its original author, tier and duration, because "banned for a day last
March" is history somebody may need, and silently vanishing records make a
moderation log worth less than no log at all.

Two operations, and the UI must not blur them: "removed" and "cannot come back"
are different promises, and only one of them is enforceable without the server.

**A ban survives a reform.** `ReformRoom` moves the conversation to a fresh room
with an unguessable name, and it is a continuation of the same group rather than
a new one — so its bans, roles and member list come with it. Anything else means
the act you perform *because* somebody is unwelcome silently unbans them.

This is a real requirement on the implementation, not a default that falls out.
A reformed room is a new row under a new name, so the server cannot tell it
continues the old one unless it is told: the reform has to carry a pointer to its
predecessor and inherit that room's state. Without the pointer, the ban list is
empty by construction.

The unguessable name and the inherited ban list are belt and braces on purpose.
The name stops the person following the conversation; the ban stops them arriving
if they learn it anyway.

Carrying bans over is the **default, not the rule**. A group reforming to draw a
line under an argument may genuinely want to start clean, so dropping the
inherited bans is offered as a choice at reform time — deliberately chosen, never
assumed, and only to whoever could have lifted those bans individually.

### The owner has the last word on bans

Ban state is contested state — two people with the power to set it can undo each
other indefinitely — so it needs a resolution rule rather than last-writer-wins.

**A ban may only be overridden by an equal or higher tier than the one that set
it.** A senior mod may lift another senior mod's ban, or their own. They may not
lift the owner's. The owner may lift anything, and nothing outranks the owner, so
the owner's decision is final by construction rather than by special case.

This is the same shape as the rule that only the owner touches role-holders:
authority flows down and never up. It also means the friction is intentional and
should not be reported as a bug — a senior mod who bans someone the owner then
unbans **cannot simply re-ban them**. They have to take it up with the owner.
That is the point of a final say.

**The tier is recorded when the statement is written, not looked up when it is
read.** If a senior mod is later demoted, the bans they set stay at the level
they had authority to set them at. Resolving the tier live would mean a demotion
retroactively weakened past decisions, which is a strange thing to happen to
records nobody touched.

Like role changes, ban state is a signed statement the server stores and enforces
rather than a row it authors — for the same reason. A server that can invent a
ban can exclude anyone from any room, and having it check a signature instead
costs almost nothing given the machinery already exists.

### An invite cannot quietly undo a ban

Inviting somebody who is banned would otherwise produce the worst of both: a
member holding a valid key who still cannot get through the door, and a ban
lifted by nobody in particular.

So an invite **refuses** when the target is banned. What happens next depends on
whether the inviter could have lifted that ban anyway:

- **A mod is refused outright**, and told why: the person is banned and a mod
  cannot change that. Ask a senior mod. A mod must never be able to route around
  the ban power they do not have by using the invite they do.
- **A senior mod or the owner** — only for bans they are permitted to lift — is
  offered lifting it *and* inviting as one deliberate action. Two things are
  happening and the dialog says both. The ban is properly lifted and recorded,
  never silently bypassed.

### Kicks are recorded, and the person is told

A kick used to leave no trace at all, which made "who keeps throwing me out of
this room?" unanswerable from either side.

**A room keeps a kick log**, server-side, visible to the owner and both mod
tiers: who was kicked, by whom, when, and why. Like role and ban statements it is
signed by whoever performed it, so the log is verifiable rather than the server's
word — otherwise an operator could quietly attribute a kick to a mod who never
made one.

Bounded, unlike the ban list. Bans are authority state and are kept forever; a
kick log is operational history, answering "what has been happening lately"
rather than standing as a permanent record, so it keeps the most recent entries
and lets the rest go.

**The person kicked is told, with an optional reason** written by whoever kicked
them:

> You were kicked from **project-planning**.
> Reason: being an asshole

Two things about that reason worth deciding deliberately rather than discovering:

- **It is not end-to-end encrypted, and the person typing it should be told so.**
  The kick is enforced by the server, the reason travels with it, and unlike room
  messages the operator can read it. That is a small leak, but §5's posture
  applies: be legible about what the cryptography does not cover rather than
  imply a privacy that is not there.
- **It is a message to somebody who is being ejected**, which makes it a channel
  for exactly the behaviour a kick is usually a response to. It should be
  attributable and unmistakably a moderation notice rather than something that
  reads like a DM, and it should respect blocking the same way anything else
  does. Optional, and blank is a perfectly good answer.

**The reason stays with the kick and cannot be withdrawn.** It has already been
delivered, so unsending it was never on the table, and the log entry is the
record of what was actually said. A mod who typed something regrettable has said
it; letting them quietly rewrite the log afterwards would leave the person who
received it holding a message the room's own history denies. An audit trail that
can be edited by the people it audits is not one.

### The room is told too

Only the person on the receiving end learned anything, which sits badly against
§3: the open room is built on membership changes being **visible**, and somebody
vanishing mid-conversation with no explanation is the opposite. So the room sees
it as well:

> **X was kicked**
> **X was banned for 2 hours**
> **X was banned permanently**

Whether the reason is shown to the room as well as to the person is a separate
call — a reason written for one recipient is not automatically fit for an
audience — and it should probably be the moderator's choice at the time.

**This must not be a server-injected message, and that is not a style
preference.** Injecting plaintext into an encrypted room was a real bug, fixed
2026-07-21: a non-envelope body in an encrypted room used to render with the
claimed sender's name, normal styling and no marker at all, and the server picks
the sender name attached to every chat message. Clients now flag exactly that as
`⚠ UNENCRYPTED`, so a server-authored system message would be marked as an
impersonation attempt — correctly, because it is indistinguishable from one.

Building a "legitimate" version of it would be worse than the bug. A blessed
channel for the server to place text in an encrypted room, in nobody's name, is
the capability the fix removed; the operator could then say anything to anyone
and have it render as trustworthy chrome.

**The acting moderator's client posts it**, as an ordinary room message —
encrypted with the room key, signed with their device key, flagged as a
moderation event so the UI can render it as a notice rather than as something
they typed. No new trust, no injection channel, and it verifies exactly like
every other message in the room.

The cost is that the announcement rides on the moderator's client rather than the
server: if it dies between the ban taking effect and the message going out, the
room is not told about an exclusion the server is already enforcing. That gap is
worth accepting. The alternative buys consistency by handing the operator a
megaphone.

For events the server observes but no moderator caused — somebody's connection
dropping, a ban expiring on its own — render a **timeline event** rather than a
message: unattributed, visibly not chat, and never passing through the
message-decryption path where it could be mistaken for something a person said.

### A ban manager, per room

Bans accumulate silently and are otherwise invisible: nobody can audit a list
they cannot see, and "why can't X join?" is unanswerable without one. The room's
security dialog gets a ban list showing who is banned, when, by whom, and at what
tier — visible and actionable to the owner and senior mods, since those are the
tiers that can act on it.

Showing the authoring tier is what makes the override rule legible. A senior mod
looking at a ban they cannot lift should be able to see that the owner set it,
rather than discovering it by trying.

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

**Inactive means three months, measured on the account, not the room.**

Long enough that a sabbatical does not cost somebody their room; short enough
that a room does not sit frozen for a year. Measured on the owner's last sign-on
rather than their last message *in this room*, because the stricter reading would
transfer a room away from someone who is simply quiet in it, and the failure mode
of getting this wrong is taking somebody's room off them. Prefer the forgiving
measure. The server observes sign-on already, so this needs nothing new.

### When there is nobody to inherit

The ladder can run out: an owner goes quiet and appointed no mods. The answer is
that **the claim falls to the most senior surviving tier** — mods if any exist,
otherwise any member — on the same single timeout. One rule, one window, no
second clock to reason about.

An ownerless room is not a broken state and it is worth being clear why: it is
exactly the model BENCchat ships **today**, and what §3 calls an open room. Any
member may invite and rotate. So the degradation path is "falls back to the
behaviour that already exists", not "deadlocks".

It is still a change to the room's properties, so it must be a deliberate act
rather than a silent expiry. After the window, a member *may claim* ownership —
announced, counter-bumped, visible to everyone — rather than the room quietly
becoming uncontrolled on a timer. Somebody who joined a gated room should never
discover it became open while nobody was looking.

**Contested claims need no new mechanism.** Two mods claiming at once is resolved
by the counter rule already built for device manifests: the server accepts the
first statement at counter N+1 and refuses the second as stale. Deterministic,
first-writer-wins, and identical to how a manifest race already resolves.

### The completely stale room

Nobody has been near it in three months — owner, mods, members, all gone. What
happens is: **nothing**, and that is the correct behaviour rather than an
oversight.

There is no timer that fires. The ladder is evaluated **at the moment somebody
claims**, not continuously, so a room with nobody in it to make a claim simply
sits. When the group does come back it resolves itself in seniority order: if the
owner returns first, nothing ever changed and they are still the owner; if a
senior mod returns first and the window has elapsed, they may claim. "May claim"
rather than "inherits automatically" is exactly what makes this safe — a dormant
room does not quietly change hands while everyone is away.

The property that makes staleness harmless is that **the ladder is closed over
the signed member list**. A stranger who wanders into a stale room — and they
can, because OSCAR has no join control and the name is still reserved — can never
claim it, no matter how long it has been abandoned. They hold no key, and they
are not on a list they cannot sign themselves onto. Staleness never converts a
walk-in into an heir.

**No garbage collection.** Rooms, roles and ban lists persist indefinitely. The
rows are small and this deployment has a handful of rooms, whereas the failure
mode of collecting them is a group returning after a year to find its bans
lifted, its roles gone and its owner demoted to nobody. Keeping them is cheap
insurance against the case that would actually hurt.

One consequence worth writing down rather than discovering: because `chatRoom` is
`UNIQUE(exchange, name)` and never collected, **a stale room reserves its name
forever**. A group that abandons "project-planning" has taken that name off the
table for good.

If there are no members either, the room is empty and there is nothing to decide
— no state anyone is contending for, just a reserved name.

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
- ~~**How long is "inactive"**~~ Answered in §7: three months, measured on the
  owner's last sign-on rather than their last message in the room.
- ~~**Does a kick imply removal from the member list**~~ Answered in §7: yes, and
  a kick is distinct from a ban — the first evicts, the second also refuses the
  rejoin.
- ~~**What if there is nobody to inherit?**~~ Answered in §7: the claim falls to
  the most senior surviving tier, and an ownerless room is the open room of §3
  rather than a broken one.
- ~~**Does a ban survive a room being reformed?**~~ Answered in §7: yes. A reform
  continues the same group, so bans, roles and members carry over — which means
  the implementation needs a predecessor pointer, since a reformed room is
  otherwise indistinguishable from a new one.
- ~~**Can a mod ban, or only kick?**~~ Answered in §7: mods kick, senior mods and
  the owner ban.
- ~~**What happens to a completely stale room?**~~ Answered in §7: nothing, by
  design. The ladder is evaluated at claim time, and it is closed over the signed
  member list so a walk-in can never inherit.
- ~~**Is a senior mod's ban reversible by a mod?**~~ Answered in §7: mods do not
  touch bans at all. Senior mods and the owner lift them, and a ban may only be
  overridden by an equal or higher tier than set it — so the owner has the final
  word by construction.
- ~~**Should a reform be able to DROP inherited bans deliberately?**~~ Answered in
  §7: yes, as an explicit choice at reform time. Carrying them over stays the
  default.
- ~~**Does a ban survive the banned person being re-invited?**~~ Answered in §7:
  the invite refuses. A mod is refused outright; a senior mod or the owner is
  offered lifting and inviting as one deliberate act.
- ~~**Is a kick recorded anywhere?**~~ Answered in §7: a bounded, signed kick log
  visible to the owner and both mod tiers, and the person kicked is told with an
  optional reason.
- **Does the kick log survive a reform?** Bans do, because they are authority
  state. A kick log is operational history and the argument is weaker either way.
- ~~**Can a kick reason be edited or withdrawn**~~ Answered in §7: no. The notice
  is delivered and the log keeps what was sent, because an audit trail editable
  by the people it audits is not one.
- ~~**How long may a timed ban run**~~ Answered in §7: temp bans cap at 3 days,
  and at 1 hour for a mod. Past 3 days the honest word is "banned".
- ~~**Is the room told when somebody is kicked or banned?**~~ Answered in §7: yes,
  posted by the acting moderator's client as an encrypted, signed room message —
  never injected by the server, which is the capability the plaintext-injection
  fix removed.
- **Is the kick reason shown to the ROOM, or only to the person kicked?** A reason
  written for one recipient is not automatically fit for an audience. Probably the
  moderator's choice at the time, defaulting to private.
- **What happens to a temp ban when the room is reformed?** Bans carry over, but a
  1-hour ban set before a reform that takes a minute is a different thing from a
  perma ban carried deliberately. Possibly they should simply expire on schedule
  regardless, which needs the reformed room to inherit the clock and not just the
  entry.
