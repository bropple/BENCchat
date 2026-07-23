// syslog.ts — the durable system-log buffer.
//
// The system log used to live inside the roster component, as a closure
// variable rebuilt on every mount. That made it lie about two things: notices
// emitted before the roster mounted (during sign-on and the first-run identity
// screen) had nowhere to land, and every screen change destroyed the record of
// what had happened while signed on. Since the log exists precisely to explain
// things the transient toast is too short-lived to convey — why a room key is
// missing, why a send failed — losing exactly the notices that precede the
// roster is losing the ones most worth keeping.
//
// So the buffer lives here, above any screen. It is a process-lifetime
// singleton: a single global subscription (wired in main.ts) feeds server
// notices into it regardless of which screen is up, and the roster, when it is
// mounted, renders from it and subscribes for changes rather than owning it.
// It is still session-scoped in spirit — a record of what happened while the
// app is running, not a persisted audit trail — it simply no longer resets on
// a screen change.

export type NoticeLevel = "info" | "warn" | "error";

export interface LogEntry {
  id: number;
  at: Date;
  level: NoticeLevel;
  text: string;
  /** Set when the server sent this; also means `text` is AIM HTML rather than
   *  plain text, so a renderer must sanitize it. */
  from?: string;
}

/** Oldest entries fall off the end; a chat client left running for days
 *  shouldn't accumulate notices without bound. */
const LOG_MAX = 200;

let entries: LogEntry[] = [];
let seq = 0;
let unseen = 0;
const subscribers = new Set<() => void>();

function notify(): void {
  for (const cb of subscribers) cb();
}

/** File a notice. Newest first, capped, and counted as unseen — a mounted
 *  viewer whose panel is open clears that immediately via markSeen(), so the
 *  count only survives for notices nobody was looking at, including every
 *  notice that arrived while no roster was mounted at all. */
export function record(text: string, level: NoticeLevel, from?: string): void {
  entries.unshift({ id: ++seq, at: new Date(), level, text, from });
  if (entries.length > LOG_MAX) entries.length = LOG_MAX;
  unseen++;
  notify();
}

/** The current entries, newest first. Treat as read-only. */
export function list(): readonly LogEntry[] {
  return entries;
}

export function unseenCount(): number {
  return unseen;
}

/** Mark everything read — called when the panel is opened, or when a notice
 *  arrives while it is already open. */
export function markSeen(): void {
  if (unseen === 0) return;
  unseen = 0;
  notify();
}

export function dismiss(id: number): void {
  const before = entries.length;
  entries = entries.filter((e) => e.id !== id);
  if (entries.length !== before) notify();
}

export function clear(): void {
  if (entries.length === 0) return;
  entries = [];
  notify();
}

/** Subscribe to buffer changes; returns an unsubscribe. The callback fires on
 *  every record/dismiss/clear/markSeen so a mounted panel can re-render. */
export function subscribe(cb: () => void): () => void {
  subscribers.add(cb);
  return () => {
    subscribers.delete(cb);
  };
}
