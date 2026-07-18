// sound.ts — client-side notification sounds, synthesized with the Web Audio
// API rather than shipped as audio files.
//
// The classic AIM sounds are AOL's assets, so we don't bundle or imitate them.
// Instead every event has an ORIGINAL sound built from oscillators and noise —
// short, distinct cues in our own voice. Sounds are organized into swappable
// "packs" (like the color themes): the same 13 event recipes rendered through a
// pack's voice. A future pack could load real audio files (e.g. legally-obtained
// AIM sounds) without changing any of this — see playFile in the engine notes.
//
// Event keys mirror the classic AIM sound names so the vocabulary is familiar
// and a file-based pack can map onto them 1:1.

/** The catalog of sound events, in the order the settings panel lists them.
 *  `wired` marks the ones BENCchat currently triggers; the rest are defined for
 *  completeness and future features (voice chat, mail), and are previewable. */
export const SOUND_EVENTS = [
  { key: "imrcv", label: "Message received", wired: true },
  { key: "imsend", label: "Message sent", wired: true },
  { key: "dooropen", label: "Buddy signs on", wired: true },
  { key: "doorslam", label: "Buddy signs off", wired: true },
  { key: "newalert", label: "Alert", wired: true },
  { key: "newmail", label: "New mail", wired: false },
  { key: "ring", label: "Ring", wired: false },
  { key: "phone", label: "Incoming call", wired: false },
  { key: "talkbeg", label: "Conversation start", wired: false },
  { key: "talkend", label: "Conversation end", wired: false },
  { key: "talkstop", label: "Conversation paused", wired: false },
  { key: "cashregister", label: "Cash register", wired: false },
  { key: "moo", label: "Moo", wired: false },
] as const;

export type SoundKey = (typeof SOUND_EVENTS)[number]["key"];

// A layer is one voice in a sound: either a pitched tone (optionally gliding
// between two frequencies and/or low-pass filtered) or a filtered noise burst.
type Tone = {
  kind: "tone";
  wave: OscillatorType;
  f0: number;
  f1?: number; // glide target; omit for a steady pitch
  at: number; // start offset, seconds
  dur: number; // seconds
  peak: number; // 0..1 gain at the attack
  glide?: "lin" | "exp";
  lp?: number; // low-pass cutoff Hz (dulls buzzy waves — used for the "moo")
  // fm turns this into an FM "mallet pluck": a sine modulator at ratio×f0 bends
  // the carrier's pitch, with the modulation depth (index, in multiples of f0)
  // decaying over `decay` seconds. High index + fast decay = a metallic, plucky
  // attack that settles to the pure carrier tone — the AIM "doodle-doo" timbre.
  fm?: { ratio: number; index: number; decay: number };
  // trem is amplitude tremolo (a wavering volume): a `rate`-Hz LFO scaling the
  // amp by ±`depth` (0..1). Used for the decaying tremolo tail.
  trem?: { rate: number; depth: number };
  // vibrato wavers the pitch by ±`depth` Hz at `rate` Hz — the "pitch-bend
  // passing tones" in the tail note.
  vibrato?: { rate: number; depth: number };
};
type Noise = {
  kind: "noise";
  at: number;
  dur: number;
  peak: number;
  lp?: number; // low-pass cutoff Hz
  hp?: number; // high-pass cutoff Hz
};
type Layer = Tone | Noise;
type Recipe = Layer[];

// A pack's voice re-colors every recipe: force a waveform, scale loudness, and
// lengthen release tails. This lets two packs share one set of recipes yet sound
// distinctly different (a retro beeper vs. a mellow bell).
type Voice = {
  waveOverride?: OscillatorType;
  gain: number;
  releaseScale: number;
};

export const SOUND_PACKS: Record<string, { label: string; voice: Voice }> = {
  terminal: { label: "BENCO Terminal", voice: { gain: 1.0, releaseScale: 1.0 } },
  mellow: { label: "BENCO Mellow", voice: { waveOverride: "sine", gain: 0.95, releaseScale: 1.5 } },
  chime: { label: "BENCO Chime", voice: { waveOverride: "triangle", gain: 0.9, releaseScale: 1.7 } },
};

export const DEFAULT_PACK = "terminal";

// The original BENCO sound designs — one recipe per event. None are sampled from
// or modeled on AIM's audio; they're built from first principles here.
const RECIPES: Record<SoundKey, Recipe> = {
  // Incoming message: a descending stack of fourths — three discrete FM bell
  // hits (B4 · F#4 · C#4) that ring out on the final, slower-decaying C#4. Our
  // original take on the AIM "doodle-doo", from an analysis of its note contour.
  imrcv: [
    { kind: "tone", wave: "sine", f0: 493.88, at: 0.01, dur: 0.28, peak: 0.16, fm: { ratio: 3, index: 3, decay: 0.05 } },
    { kind: "tone", wave: "sine", f0: 369.99, at: 0.095, dur: 0.28, peak: 0.15, fm: { ratio: 3, index: 2.8, decay: 0.05 } },
    { kind: "tone", wave: "sine", f0: 277.18, at: 0.195, dur: 0.5, peak: 0.15, fm: { ratio: 3, index: 2.6, decay: 0.06 } },
  ],
  // Outgoing message: the exact mirror — an ascending stack of fourths (C#4 ·
  // F#4 · B4) ringing out on the higher B4, so a send is clearly its own gesture.
  imsend: [
    { kind: "tone", wave: "sine", f0: 277.18, at: 0.01, dur: 0.28, peak: 0.15, fm: { ratio: 3, index: 2.6, decay: 0.05 } },
    { kind: "tone", wave: "sine", f0: 369.99, at: 0.095, dur: 0.28, peak: 0.15, fm: { ratio: 3, index: 2.8, decay: 0.05 } },
    { kind: "tone", wave: "sine", f0: 493.88, at: 0.195, dur: 0.5, peak: 0.16, fm: { ratio: 3, index: 3, decay: 0.06 } },
  ],
  // Buddy signs on: two ascending FM bell hits (rising fifth), ringing out high.
  dooropen: [
    { kind: "tone", wave: "sine", f0: 523.25, at: 0, dur: 0.28, peak: 0.15, fm: { ratio: 3, index: 2.8, decay: 0.05 } },
    { kind: "tone", wave: "sine", f0: 783.99, at: 0.1, dur: 0.5, peak: 0.15, fm: { ratio: 3, index: 3, decay: 0.06 } },
  ],
  // Buddy signs off: two descending FM bell hits (falling fifth), ringing out low.
  doorslam: [
    { kind: "tone", wave: "sine", f0: 783.99, at: 0, dur: 0.28, peak: 0.14, fm: { ratio: 3, index: 2.8, decay: 0.05 } },
    { kind: "tone", wave: "sine", f0: 523.25, at: 0.1, dur: 0.5, peak: 0.14, fm: { ratio: 3, index: 2.6, decay: 0.06 } },
  ],
  // Alert: two quick, insistent bell hits on the same high pitch.
  newalert: [
    { kind: "tone", wave: "sine", f0: 1046.5, at: 0, dur: 0.16, peak: 0.14, fm: { ratio: 3, index: 3.2, decay: 0.04 } },
    { kind: "tone", wave: "sine", f0: 1046.5, at: 0.11, dur: 0.3, peak: 0.14, fm: { ratio: 3, index: 3.2, decay: 0.05 } },
  ],
  // New mail: two ascending bell hits (a major third), ringing out.
  newmail: [
    { kind: "tone", wave: "sine", f0: 783.99, at: 0, dur: 0.28, peak: 0.14, fm: { ratio: 3, index: 2.6, decay: 0.05 } },
    { kind: "tone", wave: "sine", f0: 987.77, at: 0.1, dur: 0.5, peak: 0.14, fm: { ratio: 3, index: 2.8, decay: 0.06 } },
  ],
  // Ring: a single sustained FM bell.
  ring: [{ kind: "tone", wave: "sine", f0: 880, at: 0, dur: 0.65, peak: 0.15, fm: { ratio: 3, index: 3, decay: 0.06 } }],
  // Incoming call: two "ring-ring" bursts, each a quick pair of bell hits.
  phone: [
    { kind: "tone", wave: "sine", f0: 659.25, at: 0, dur: 0.2, peak: 0.13, fm: { ratio: 3, index: 2.8, decay: 0.05 } },
    { kind: "tone", wave: "sine", f0: 880, at: 0.09, dur: 0.3, peak: 0.13, fm: { ratio: 3, index: 2.8, decay: 0.05 } },
    { kind: "tone", wave: "sine", f0: 659.25, at: 0.5, dur: 0.2, peak: 0.13, fm: { ratio: 3, index: 2.8, decay: 0.05 } },
    { kind: "tone", wave: "sine", f0: 880, at: 0.59, dur: 0.34, peak: 0.13, fm: { ratio: 3, index: 2.8, decay: 0.05 } },
  ],
  // Conversation start: three ascending bell hits, ringing out on top.
  talkbeg: [
    { kind: "tone", wave: "sine", f0: 523.25, at: 0, dur: 0.24, peak: 0.14, fm: { ratio: 3, index: 2.6, decay: 0.05 } },
    { kind: "tone", wave: "sine", f0: 659.25, at: 0.09, dur: 0.24, peak: 0.14, fm: { ratio: 3, index: 2.8, decay: 0.05 } },
    { kind: "tone", wave: "sine", f0: 783.99, at: 0.18, dur: 0.45, peak: 0.14, fm: { ratio: 3, index: 3, decay: 0.06 } },
  ],
  // Conversation end: the same three bells, descending.
  talkend: [
    { kind: "tone", wave: "sine", f0: 783.99, at: 0, dur: 0.24, peak: 0.14, fm: { ratio: 3, index: 3, decay: 0.05 } },
    { kind: "tone", wave: "sine", f0: 659.25, at: 0.09, dur: 0.24, peak: 0.14, fm: { ratio: 3, index: 2.8, decay: 0.05 } },
    { kind: "tone", wave: "sine", f0: 523.25, at: 0.18, dur: 0.45, peak: 0.14, fm: { ratio: 3, index: 2.6, decay: 0.06 } },
  ],
  // Conversation paused: two neutral bell hits on the same pitch.
  talkstop: [
    { kind: "tone", wave: "sine", f0: 587.33, at: 0, dur: 0.22, peak: 0.12, fm: { ratio: 3, index: 2.6, decay: 0.05 } },
    { kind: "tone", wave: "sine", f0: 587.33, at: 0.12, dur: 0.36, peak: 0.12, fm: { ratio: 3, index: 2.6, decay: 0.06 } },
  ],
  // Cash register: two bright, sparkly bell hits a fifth apart, ringing out.
  cashregister: [
    { kind: "tone", wave: "sine", f0: 1567.98, at: 0, dur: 0.22, peak: 0.13, fm: { ratio: 3, index: 3, decay: 0.05 } },
    { kind: "tone", wave: "sine", f0: 2093, at: 0.09, dur: 0.5, peak: 0.12, fm: { ratio: 3, index: 3.2, decay: 0.06 } },
  ],
  // Moo: kept as a deliberate novelty (a comedic descending glide) — the one
  // sound that intentionally does NOT share the bell timbre.
  moo: [
    { kind: "tone", wave: "sawtooth", f0: 233, f1: 150, at: 0, dur: 0.5, peak: 0.12, glide: "exp", lp: 620 },
    { kind: "tone", wave: "sawtooth", f0: 236, f1: 152, at: 0, dur: 0.5, peak: 0.09, glide: "exp", lp: 620 },
  ],
};

// The special pack name for user-imported audio files.
export const CUSTOM_PACK = "custom";

let enabled = true;
let pack = DEFAULT_PACK;
let ctx: AudioContext | null = null;

// Decoded user-imported sounds, keyed by event. Populated by loadCustomSounds
// and played when the "custom" pack is active (events without an import fall
// back to the default synth pack).
const customBuffers: Partial<Record<SoundKey, AudioBuffer>> = {};

/** Enables or disables all sound playback. */
export function setSoundEnabled(on: boolean): void {
  enabled = on;
}

// Individually silenced events. Independent of `enabled`: the global switch off
// mutes everything, and these mute specific events while the rest still play.
let muted = new Set<SoundKey>();

/** Replaces the set of individually muted events. */
export function setMutedSounds(keys: readonly string[]): void {
  muted = new Set(keys as readonly SoundKey[]);
}

/** Whether a specific event is individually muted (the global switch aside). */
export function isSoundMuted(key: SoundKey): boolean {
  return muted.has(key);
}

/** Mutes or unmutes one event locally. Persisting is the caller's job. */
export function setSoundMuted(key: SoundKey, on: boolean): void {
  if (on) muted.add(key);
  else muted.delete(key);
}

/** Selects the active sound pack. "custom" and any known synth pack are valid;
 *  anything else falls back to the default. */
export function setSoundPack(name: string): void {
  pack = name === CUSTOM_PACK || SOUND_PACKS[name] ? name : DEFAULT_PACK;
}

/** The active pack name. */
export function soundPack(): string {
  return pack;
}

/** Lazily creates the audio context, regardless of the enabled flag (decoding
 *  imported files needs a context even when playback is muted). */
function ensureCtx(): AudioContext | null {
  if (!ctx) {
    try {
      ctx = new (window.AudioContext ||
        (window as unknown as { webkitAudioContext: typeof AudioContext }).webkitAudioContext)();
    } catch {
      return null;
    }
  }
  if (ctx.state === "suspended") void ctx.resume();
  return ctx;
}

/** The playback context, or null when sound is disabled. Browsers only allow
 *  audio after a user gesture; sign-on is one, so by the time sounds fire we're
 *  clear. */
function audio(): AudioContext | null {
  return enabled ? ensureCtx() : null;
}

/** A short white-noise buffer for percussive layers. Created per call so it's
 *  valid in whatever context (live or offline) is rendering. */
function noise(ac: BaseAudioContext): AudioBuffer {
  const n = Math.floor(ac.sampleRate * 0.3);
  const buf = ac.createBuffer(1, n, ac.sampleRate);
  const data = buf.getChannelData(0);
  for (let i = 0; i < n; i++) data[i] = Math.random() * 2 - 1;
  return buf;
}

/** Schedules a soft attack/exponential release envelope so layers don't click. */
function envelope(gain: GainNode, t0: number, dur: number, peak: number): void {
  gain.gain.setValueAtTime(0, t0);
  gain.gain.linearRampToValueAtTime(peak, t0 + 0.012);
  gain.gain.exponentialRampToValueAtTime(0.0001, t0 + dur);
}

function renderTone(ac: BaseAudioContext, l: Tone, voice: Voice): void {
  const osc = ac.createOscillator();
  const gain = ac.createGain();
  osc.type = voice.waveOverride ?? l.wave;
  const t0 = ac.currentTime + l.at;
  const dur = l.dur * voice.releaseScale;

  osc.frequency.setValueAtTime(l.f0, t0);
  if (l.f1 !== undefined) {
    if (l.glide === "exp") osc.frequency.exponentialRampToValueAtTime(Math.max(1, l.f1), t0 + dur);
    else osc.frequency.linearRampToValueAtTime(l.f1, t0 + dur);
  }

  const stopAt = t0 + dur + 0.03;

  // FM: a sine modulator at ratio×f0 drives the carrier's frequency, with its
  // depth decaying fast for a mallet-pluck attack. The modulator + its gain are
  // self-contained; only the carrier reaches the amp envelope below.
  if (l.fm) {
    const mod = ac.createOscillator();
    mod.type = "sine";
    mod.frequency.value = l.f0 * l.fm.ratio;
    const modGain = ac.createGain();
    const peakDev = l.fm.index * l.f0; // peak pitch deviation, Hz
    modGain.gain.setValueAtTime(peakDev, t0);
    modGain.gain.exponentialRampToValueAtTime(Math.max(0.001, peakDev * 0.001), t0 + l.fm.decay);
    mod.connect(modGain).connect(osc.frequency);
    mod.start(t0);
    mod.stop(stopAt);
  }

  // Vibrato: a slow LFO adds a small ±depth-Hz pitch waver (the tail's passing
  // tones). It sums into the carrier frequency alongside FM and any glide.
  if (l.vibrato) {
    const lfo = ac.createOscillator();
    lfo.type = "sine";
    lfo.frequency.value = l.vibrato.rate;
    const lfoGain = ac.createGain();
    lfoGain.gain.value = l.vibrato.depth;
    lfo.connect(lfoGain).connect(osc.frequency);
    lfo.start(t0);
    lfo.stop(stopAt);
  }

  envelope(gain, t0, dur, l.peak * voice.gain);

  let node: AudioNode = osc;
  if (l.lp) {
    const filter = ac.createBiquadFilter();
    filter.type = "lowpass";
    filter.frequency.value = l.lp;
    node.connect(filter);
    node = filter;
  }
  node = node.connect(gain);

  // Tremolo: a post-envelope gain whose value wavers as 1 ± depth·sin(rate),
  // giving the multiplicative "shimmering" amplitude of the decaying tail.
  if (l.trem) {
    const trem = ac.createGain();
    trem.gain.value = 1;
    const lfo = ac.createOscillator();
    lfo.type = "sine";
    lfo.frequency.value = l.trem.rate;
    const depth = ac.createGain();
    depth.gain.value = l.trem.depth;
    lfo.connect(depth).connect(trem.gain);
    lfo.start(t0);
    lfo.stop(stopAt);
    node = node.connect(trem);
  }

  node.connect(ac.destination);
  osc.start(t0);
  osc.stop(stopAt);
}

function renderNoise(ac: BaseAudioContext, l: Noise, voice: Voice): void {
  const src = ac.createBufferSource();
  src.buffer = noise(ac);
  const gain = ac.createGain();
  const t0 = ac.currentTime + l.at;
  const dur = l.dur * voice.releaseScale;
  envelope(gain, t0, dur, l.peak * voice.gain);

  let node: AudioNode = src;
  if (l.hp) {
    const f = ac.createBiquadFilter();
    f.type = "highpass";
    f.frequency.value = l.hp;
    node.connect(f);
    node = f;
  }
  if (l.lp) {
    const f = ac.createBiquadFilter();
    f.type = "lowpass";
    f.frequency.value = l.lp;
    node.connect(f);
    node = f;
  }
  node.connect(gain).connect(ac.destination);
  src.start(t0);
  src.stop(t0 + dur + 0.03);
}

/** Schedules a synth recipe's layers into any audio context (live or offline).
 *  Exported so the WAV exporter can render recipes through an OfflineAudioContext. */
export function scheduleRecipe(ac: BaseAudioContext, key: SoundKey, packName: string): void {
  const recipe = RECIPES[key];
  if (!recipe) return;
  const voice = SOUND_PACKS[packName]?.voice ?? SOUND_PACKS[DEFAULT_PACK].voice;
  for (const layer of recipe) {
    if (layer.kind === "tone") renderTone(ac, layer, voice);
    else renderNoise(ac, layer, voice);
  }
}

/** The total duration of a recipe in a given pack (for sizing an offline render). */
export function recipeDuration(key: SoundKey, packName: string): number {
  const recipe = RECIPES[key];
  if (!recipe) return 0;
  const voice = SOUND_PACKS[packName]?.voice ?? SOUND_PACKS[DEFAULT_PACK].voice;
  let end = 0;
  for (const l of recipe) end = Math.max(end, l.at + l.dur * voice.releaseScale + 0.05);
  return end;
}

/** Plays a decoded custom buffer through the live context. */
function playBuffer(ac: AudioContext, buf: AudioBuffer): void {
  const src = ac.createBufferSource();
  src.buffer = buf;
  const g = ac.createGain();
  g.gain.value = 0.9;
  src.connect(g).connect(ac.destination);
  src.start();
}

/** Plays a sound by event key using the active pack. Silent if disabled or the
 *  browser blocks audio. When the "custom" pack is active and the event has an
 *  imported file, that plays; otherwise it falls back to the default synth pack.
 *  Safe to call for any key, wired or not. */
export function play(key: SoundKey): void {
  if (muted.has(key)) return;
  const ac = audio();
  if (!ac) return;
  if (pack === CUSTOM_PACK && customBuffers[key]) {
    playBuffer(ac, customBuffers[key]!);
    return;
  }
  const synthPack = SOUND_PACKS[pack] ? pack : DEFAULT_PACK;
  scheduleRecipe(ac, key, synthPack);
}

/** Previews a sound in a specific pack without changing the active selection —
 *  used by the settings panel so the user can audition packs and events. */
export function previewSound(key: SoundKey, packName: string): void {
  const prev = pack;
  const wasEnabled = enabled;
  const wasMuted = muted;
  // A preview is an explicit gesture: audition it even when the global switch
  // is off or this specific event is muted.
  enabled = true;
  muted = new Set();
  setSoundPack(packName);
  play(key);
  pack = prev;
  enabled = wasEnabled;
  muted = wasMuted;
}

/** Decodes and installs user-imported sounds (event key → base64 of the file
 *  bytes). Undecodable entries are skipped. Replaces the current custom set. */
export async function loadCustomSounds(map: Record<string, string>): Promise<void> {
  const ac = ensureCtx();
  for (const k of Object.keys(customBuffers)) delete customBuffers[k as SoundKey];
  if (!ac) return;
  await Promise.all(
    Object.entries(map).map(async ([key, b64]) => {
      try {
        const bin = atob(b64);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        customBuffers[key as SoundKey] = await ac.decodeAudioData(bytes.buffer);
      } catch {
        /* skip an undecodable/unsupported file */
      }
    }),
  );
}

/** Whether an event currently has an imported custom sound loaded. */
export function hasCustomSound(key: SoundKey): boolean {
  return !!customBuffers[key];
}

// --- Semantic wrappers kept for existing call sites ---------------------------
export function playMessageIn(): void {
  play("imrcv");
}
export function playMessageOut(): void {
  play("imsend");
}
export function playSignOn(): void {
  play("dooropen");
}
export function playSignOff(): void {
  play("doorslam");
}
export function playAlert(): void {
  play("newalert");
}
