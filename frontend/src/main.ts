import "./style.css";
import "./signon.css";
import "./roster.css";
import "./settings.css";
import "./dialog.css";
import "./titlebar.css";
import "./identity.css";

import { Bridge, type IdentityState, type SessionStatus } from "./bridge";
import { renderSignOn, showSignOnStatus } from "./signon";
import { renderRoster, type RosterHandle } from "./roster";
import { renderIdentity, type IdentityHandle } from "./identity";
import { loadAndApplyTheme } from "./theme";
import { setSoundEnabled, setSoundPack, setMutedSounds, loadCustomSounds } from "./sound";
import { mountTitlebar } from "./titlebar";

function el<T extends HTMLElement>(id: string): T {
  const node = document.getElementById(id);
  if (!node) throw new Error(`missing element #${id}`);
  return node as T;
}

/** The three screens this app has.
 *
 *  "identity" is a full screen rather than a dialog over the roster because
 *  proposal §12 asks for the whole window on first run: it is the one place
 *  where dismissing something unread costs an account outright. */
type Screen = "signon" | "roster" | "identity";

let current: Screen = "signon";
let roster: RosterHandle | null = null;
let identity: IdentityHandle | null = null;

/** Whether the Go side reports a live session. Half of what decides the screen;
 *  the identity flow is the other half. */
let signedOn = false;
/** Which identity flow the backend last reported, so `show` knows which of the
 *  two identity screens to render. */
let identityFlow: IdentityState["flow"] = "unavailable";
/** The user chose "Not now" on the link screen. Honoured for the rest of the
 *  session and never re-raised: §13 is explicit that nothing nags, and a prompt
 *  people learn to dismiss is not there when it matters. Cleared on sign-off,
 *  since the next sign-on is a fresh decision. */
let linkDeferred = false;
/** First-run setup finished on this session. Only covers the gap between the
 *  user saving the key and the backend reporting "ready": without it, routing
 *  would still read "setup" for those few milliseconds and put the screen
 *  straight back up. Cleared on sign-off with everything else. */
let setupDone = false;

function show(root: HTMLElement, screen: Screen): void {
  // Re-showing the screen we're already on would rebuild it — which for the
  // identity screen means discarding a key the user is part-way through saving.
  // Sign-on is exempt: it re-renders to surface a new error.
  if (screen === current && screen !== "signon") return;
  current = screen;

  roster?.destroy();
  roster = null;
  identity?.destroy();
  identity = null;

  if (screen === "roster") {
    roster = renderRoster(root, () => signOff(root));
  } else if (screen === "identity") {
    identity = renderIdentity(
      root,
      identityFlow === "link" ? "link" : "setup",
      () => {
        setupDone = true;
        linkDeferred = true;
        route(root);
      },
      () => {
        linkDeferred = true;
        route(root);
      },
    );
  } else {
    renderSignOn(root, () => {
      signedOn = true;
      route(root);
    });
  }
}

/** Which screen the current state calls for.
 *
 *  Derived from state rather than driven by whichever event arrived last. Those
 *  events — "session online" and "identity flow" — are produced by two
 *  independent paths on the Go side and their order is not fixed: sign-on emits
 *  the session status while `setupIdentity` is still doing directory round
 *  trips in a goroutine, so on a first run the identity flow can easily land
 *  first. When both handlers simply called show(), the loser was silently
 *  overwritten, and the case that lost was the one that matters — the first-run
 *  key screen replaced by the roster, leaving an account with no identity and
 *  no sign that anything had been skipped.
 *
 *  "setup" takes the window unconditionally: the account cannot send or read
 *  encrypted messages until it has an identity, so nothing is being held back.
 *  "link" offers itself once and accepts being deferred. */
function targetScreen(): Screen {
  if (!signedOn) return "signon";
  if (identityFlow === "setup") return setupDone ? "roster" : "identity";
  if (identityFlow === "link") return linkDeferred ? "roster" : "identity";
  return "roster";
}

function route(root: HTMLElement): void {
  show(root, targetScreen());
}

function applyIdentityState(root: HTMLElement, st: IdentityState): void {
  if (st.flow === "setup" && identityFlow !== "setup") {
    // A fresh demand for first-run setup, which a stale deferral must not eat.
    linkDeferred = false;
    setupDone = false;
  }
  identityFlow = st.flow;
  route(root);
}

/** Back to a signed-off state, with every per-session decision forgotten. */
function signOff(root: HTMLElement): void {
  signedOn = false;
  identityFlow = "unavailable";
  linkDeferred = false;
  setupDone = false;
  route(root);
}

function handleStatus(root: HTMLElement, status: SessionStatus): void {
  switch (status.state) {
    case "online":
      signedOn = true;
      route(root);
      // And then ask, rather than only waiting to be told. The identity flow is
      // pushed as an event, so one emitted before this handler was in place —
      // or before we knew we were online — has already been and gone. The same
      // reason the reload path below asks; the difference is that this one is
      // the ordinary case, not the unusual one.
      void Bridge.getIdentityState()
        .then((st) => applyIdentityState(root, st))
        .catch(() => {});
      break;
    case "offline":
      signOff(root);
      break;
    case "error":
      // A mid-session fault drops us back to sign-on with the reason shown,
      // rather than leaving a dead roster on screen.
      signOff(root);
      showSignOnStatus(status);
      break;
  }
}

window.addEventListener("DOMContentLoaded", () => {
  const root = el<HTMLDivElement>("app");

  Bridge.onSessionStatus((status) => handleStatus(root, status));

  // Which identity flow this device is in is decided by the backend at sign-on
  // and whenever it changes — a first run completing, a link succeeding, the
  // session going away. Approval-from-another-device is gone: a device is no
  // longer let in by someone clicking Approve, but by being signed into the
  // account's manifest with the recovery key.
  Bridge.onIdentityState((st) => applyIdentityState(root, st));

  // Load the sound preferences up front so the first event honors them, and
  // mount the custom titlebar if the frameless window frame is enabled.
  void Bridge.getPreferences()
    .then((p) => {
      setSoundEnabled(p.soundEnabled);
      setSoundPack(p.soundPack);
      setMutedSounds(p.mutedSounds ?? []);
      if (p.customFrame) mountTitlebar();
    })
    .catch(() => {});
  // Decode any imported custom sounds so the "custom" pack is ready to play.
  void Bridge.getCustomSounds()
    .then((m) => loadCustomSounds(m))
    .catch(() => {});

  // Apply the saved theme before first render so there's no flash of the default
  // palette, then restore the right screen. The Go side owns the session, so a
  // webview reload must not strand a live one.
  void loadAndApplyTheme().finally(() => {
    Bridge.signedOn()
      .then((on) => {
        signedOn = on;
        route(root);
        // A webview reload doesn't re-run sign-on, so the identity:state event
        // that routed us the first time has already been and gone. Ask.
        if (on) {
          void Bridge.getIdentityState()
            .then((st) => applyIdentityState(root, st))
            .catch(() => {});
        }
        // If we're not already signed on, try a remembered password. On success
        // the "online" session-status event moves us to the roster; on failure
        // we simply stay on the sign-on screen.
        if (!on) void Bridge.autoSignIn();
      })
      .catch(() => signOff(root));
  });
});
