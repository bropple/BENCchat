# BENCchat generated sounds

WAV renders of BENCchat's built-in, synthesized notification sounds — the exact
audio the app generates at runtime with the Web Audio API (see
`frontend/src/sound.ts`). These are **original**: built from FM synthesis, not
sampled from or modeled on AIM's audio.

Format: 16-bit PCM mono, 44.1 kHz.

One folder per sound pack, each with all 13 events:

- **terminal/** — BENCO Terminal (the default pack)
- **mellow/** — BENCO Mellow (softer voicing)
- **chime/** — BENCO Chime (bell-like voicing)

Events: `imrcv` (message received), `imsend` (message sent), `dooropen` (buddy
signs on), `doorslam` (buddy signs off), `newalert`, `newmail`, `ring`, `phone`,
`talkbeg`, `talkend`, `talkstop`, `cashregister`, `moo`.

The message tones are three-hit FM-bell "stacks of fourths" (received descends
B4·F♯4·C♯4, sent ascends the mirror), and the other events share that bell
timbre — except `moo`, kept as a deliberate novelty.

These are a static snapshot for reference/reuse. To regenerate after tweaking the
recipes, re-run the export step; the app itself always synthesizes live rather
than loading these files. To use your *own* audio instead, import files per event
via **Settings → Sound → Import your own** (that builds the in-app "Custom" pack;
it does not touch this folder).
