# Attachments, media, and reactions

**Status: proposal, not built.** A design to argue with before any of it exists.
It covers three requested features that split into two very different shapes:

- **Attachments and media** (images, GIFs, video, arbitrary files) — large, needs
  a transport the messaging channel cannot provide.
- **Reactions** — small, rides the channel that already exists, needs one piece
  of groundwork (stable message IDs).

The through-line, and the property worth protecting: **the server stays a dumb
relay and a dumb encrypted store.** It never reads what it moves. Every feature
here is designed so that spending that property is never the price.

---

## 1. The constraint that decides everything

Messages travel through ICBM. Measured against the live server
(`TestLiveICBMSizeCeiling`), the body tops out around 65 KB. Text fits. A
reaction fits. A photo does not, and a video is not remotely close.

So **files need a separate transport from messages.** That is the fork the whole
design hangs on, and once accepted it answers "how, where, how big" almost by
itself. Everything else is consequence.

The second constraint is E2EE. Message *bodies* are end-to-end encrypted; an
attachment path that was not would be a hole straight through the middle of that
promise. So attachments are E2EE too, non-negotiably — which, combined with the
first constraint, forces one specific shape.

---

## 2. The shape: encrypt, upload ciphertext, reference in the message

The client does the work; the server holds bytes it cannot read.

1. **Prepare.** Optionally compress or downscale the file (see §4). Pick a fresh
   random key.
2. **Seal.** Encrypt the file with that key (NaCl secretbox, the construction
   already in use). Compute a content hash of the ciphertext for integrity.
3. **Upload.** PUT the *ciphertext* to the server's blob store; get back a blob
   ID.
4. **Reference.** Send an ordinary E2EE message whose body is small structured
   data:

   ```
   { blobID, fileKey, hash, filename, mime, size }
   ```

   This is a few hundred bytes, so it rides ICBM comfortably, and it is already
   wrapped per-device by the existing envelope — so multi-device works for free.
5. **Receive.** The recipient reads the reference out of the decrypted message,
   fetches the ciphertext by blob ID, checks the hash, decrypts with `fileKey`,
   and renders.

This is what Signal, WhatsApp and Matrix all do, for the same reasons. The blob
is encryption-at-rest **by construction** — the client encrypts before the bytes
ever leave it, so no server-side key exists and the server cannot decrypt even
if compelled to.

**A property that falls out for free:** a fresh random key per upload means the
same file sent twice produces different ciphertext. No cross-user dedup — which
is a privacy feature, not a loss. The server cannot tell that two people sent the
same image.

---

## 3. Storage: what the server holds

A new blob store, separate from the message path:

- **On disk:** encrypted blobs, plus a table `blobID → {path, owner, size,
  created, expires}`. Local filesystem to start; object storage (S3-style) is a
  later swap if scale ever demands it, and nothing above depends on which.
- **What the server sees:** size, owner, timing, and who downloads. That is
  metadata, the same category it already sees for messages — it does **not** see
  filenames (those are inside the encrypted reference), types, or content.
- **What it cannot do:** read a blob, or forge one a client will accept (the hash
  is checked against the key only the recipient holds).

Note what is metadata and lives in the *message* (encrypted: filename, mime,
size-as-shown) versus what the *server* needs in the clear to run the store
(blob ID, ciphertext length, owner, timestamps). Keep the first set out of the
server's reach; it only needs the second.

---

## 4. Compression, done in the right order

"Store them compressed" is right, with one correction that a naive build gets
backwards: **you cannot compress after encryption.** Ciphertext is
indistinguishable from random, so gzip on a sealed blob saves nothing. Any
compression happens client-side, *before* the seal.

And it splits by content type:

- **Already-compressed media** — JPEG, PNG, GIF, MP4, WebM — do not
  byte-compress. Attempting it wastes CPU for ~0% gain. Upload as-is.
- **Compressible files** — text, logs, uncompressed formats — compress before
  sealing. Real savings.
- **Oversized images/video** — the meaningful "compression" here is not gzip, it
  is *re-encoding*: downscale a 12-megapixel phone photo to something sane,
  re-encode video at a lower bitrate. This is a quality tradeoff and must be the
  user's choice or a sensible default with an "send original" escape hatch. It is
  also the single biggest lever on storage and bandwidth, far more than any
  byte-level compression. It only happens client-side, because the server cannot
  touch the plaintext.

So: transcode/downscale (optional, media) → compress (only if compressible) →
encrypt → upload. In that order, or not at all.

---

## 5. Size limits and quota

The 65 KB ICBM ceiling is **irrelevant** here — blobs do not go through ICBM,
only the tiny reference does. Limits are pure server policy:

- Per-file caps by kind (e.g. images a few MB, video tens of MB), configurable.
- A **per-account quota** on total stored bytes, so no one account can fill the
  disk.
- Both enforced at upload; the server rejects an over-limit or over-quota PUT
  before storing.

---

## 6. Lifecycle — the genuinely hard part, named

The question that ambushes every file feature: **when does an encrypted blob get
deleted?** Naming it now so it does not get discovered later.

The tempting answers are traps:

- **Delete after fetch** breaks multi-device: each of a recipient's devices
  fetches, and a laptop that was offline never gets its copy.
- **Reference counting** (delete when no message points at it) is fiddly, and
  message deletion/history pruning makes the count wrong in subtle ways.

The answer that fits this deployment: **TTL plus quota.** A blob expires N days
after upload (30 is a reasonable default), and a background sweep deletes expired
blobs. A message that references an expired blob renders as "attachment expired —
ask the sender to resend," which is honest and bounded. Combined with the
per-account quota from §5, storage can never grow without limit and never
requires a human to go pruning.

Anything cleverer than TTL+quota is premature until there is a reason. Write the
sweep, pick the numbers, move on.

---

## 7. The upload/download channel

One real sub-decision, flagged rather than pretended away.

- **A new OSCAR foodgroup** keeps everything in one protocol, but chunking large
  binary over FLAP framing is awkward and slow, and FLAP was not built for bulk.
- **An HTTPS endpoint** on the server (separate from the loopback-only management
  API — this one clients must reach) is the natural fit for bulk bytes, but needs
  its own authentication.

**Lean: HTTPS, authenticated by a short-lived ticket minted over the OSCAR
session.** A small foodgroup issues an upload/download ticket (the client is
already authenticated on BOS); the client then PUTs/GETs to the HTTPS endpoint
with that ticket. This keeps auth tied to the existing session without a second
login, and keeps the bulk transfer off the FLAP path where it does not belong.
The ticket is scoped (one blob, upload or download, short expiry) so a leaked one
is nearly worthless.

This endpoint sits behind the same TLS as everything else, so the ciphertext is
double-wrapped in transit (TLS around an already-encrypted blob), which is belt
and suspenders but free.

---

## 8. Rendering, and treating every file as hostile

Once the bytes are decrypted this is mostly a frontend job — the webview renders
`<img>` for images and GIFs and plays `<video>` for what the engine supports
(MP4/H.264, WebM). "Native playback for certain formats" is exactly "whatever the
webview plays"; anything exotic would need transcoding, which we do not do.

The part that is not easy, and matters more than the rendering, is that **every
incoming file is hostile until proven otherwise:**

- Validate declared type and size *before* rendering, and check the bytes match
  the claim rather than trusting the `mime` field.
- Enforce the size cap on the *decrypted* size too, not just the upload — a small
  ciphertext can claim to decompress to something huge (a decompression bomb).
- Do not auto-play or auto-fetch unbounded media; require a click for anything
  past a threshold.
- Render in the webview's sandbox; never hand a file to a native handler
  silently.

This discipline is the actual work of the feature. The `<img>` tag is the trivial
part.

---

## 9. Reactions — the small sibling

Reactions share nothing with the above. No blob store, no new transport. A
reaction is a tiny structured message — *react to message X with 👍, or remove
that reaction* — that rides the existing E2EE channel exactly as room invites and
catch-up already do (an escape-prefixed payload inside a normal sealed message).

It needs **one** piece of groundwork that does not exist yet: **stable message
IDs.** A reaction has to point at a specific message, and today messages are
identified only loosely. So:

1. Give every message a stable ID at send time (already partly present as the
   ICBM cookie; needs to be persisted and surfaced).
2. Define a reaction payload: `{ targetID, emoji, add|remove }`, sealed and sent
   like any message.
3. The recipient's client applies it to the referenced message in the UI, and
   reactions aggregate (three 👍 shows as 👍 ×3).

Message IDs are worth doing regardless: **replies, edits, and deletes all need
the same thing.** Reactions are the cheapest feature that forces that groundwork,
which is a good reason to do it first among these.

---

## 10. What none of this changes

- **The server never reads content.** Blobs are client-encrypted; reactions are
  inside the E2EE envelope. The store is dumb by construction.
- **Metadata is still visible to the server** — who sent whom a file, how big,
  when; who reacted to what, when. Same story as messages. TLS hides it from the
  network, not from the server.
- **Key management is unchanged.** Attachments reuse the per-message envelope
  (the file key rides inside it, already wrapped per device); reactions are just
  messages. Neither touches the identity/manifest layer.

---

## 11. Sequencing

1. **Finish consensual connections** (in flight) — the social foundation.
2. **Message IDs, then reactions.** Smallest of these features, self-contained,
   and it builds the ID groundwork that replies/edits/deletes will reuse.
3. **Attachments** as its own deliberate project — new transport, blob store,
   quota, TTL sweep, upload tickets, encryption integration, safe rendering. It
   is genuinely large; it should not be bolted onto anything.

---

## 12. Open decisions

- **Upload channel:** HTTPS-with-ticket (recommended, §7) versus a transfer
  foodgroup. Decide before building attachments.
- **TTL and quota numbers:** 30 days / some-hundreds-of-MB are placeholders. Pick
  real values against the actual disk and usage.
- **Default downscale policy:** re-encode large media by default with a "send
  original" opt-out, or always send original and only offer downscale? A privacy
  and quality tradeoff, not just storage.
- **Do message IDs get exposed cross-client** in a way that leaks anything? They
  are inside the E2EE envelope, so no — but confirm when specifying reactions.
- **Expired-blob UX:** "ask the sender to resend" is the honest fallback; whether
  the client can offer a one-click re-request is a nicety to decide later.
