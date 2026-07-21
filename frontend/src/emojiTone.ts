// Shared skin-tone state, so the picker (roster) and the Settings selector agree
// without threading state through either. Persistence is the Go layer's job
// (Bridge.setSkinTone); this just holds the live value and fans out changes.

import { EMOJI_TONES } from "./emoji_data";

let tone = 0; // 0 = neutral yellow default; 1–5 = Fitzpatrick types 1-2…6
const listeners = new Set<() => void>();

/** The current preferred tone (0 = default). */
export function skinTone(): number {
  return tone;
}

/** Set the live tone and notify subscribers. Does NOT persist — the caller
 *  persists via Bridge.setSkinTone. Out-of-range values fall back to default. */
export function setSkinTonePref(t: number): void {
  const n = t >= 0 && t <= 5 ? t : 0;
  if (n === tone) return;
  tone = n;
  for (const fn of listeners) fn();
}

/** Subscribe to tone changes; returns an unsubscribe. */
export function onSkinToneChange(fn: () => void): () => void {
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
}

/** Whether an emoji supports skin tones. */
export function toneable(base: string): boolean {
  return base in EMOJI_TONES;
}

/** A base emoji rendered in the current default tone (itself if untoneable). */
export function applyTone(base: string): string {
  const v = EMOJI_TONES[base];
  return tone > 0 && v ? v[tone - 1] : base;
}

/** All six choices for a base — [default, type1-2 … type6] — for the long-press
 *  palette. Just the base itself when it doesn't support tones. */
export function toneVariants(base: string): string[] {
  const v = EMOJI_TONES[base];
  return v ? [base, ...v] : [base];
}
