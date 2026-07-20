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

/** Which identity flow the backend last reported, so `show` knows which of the
 *  two identity screens to render. */
let identityFlow: IdentityState["flow"] = "unavailable";
/** The user chose "Not now" on the link screen. Honoured for the rest of the
 *  session and never re-raised: §13 is explicit that nothing nags, and a prompt
 *  people learn to dismiss is not there when it matters. Cleared on sign-off,
 *  since the next sign-on is a fresh decision. */
let linkDeferred = false;

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
    roster = renderRoster(root, () => show(root, "signon"));
  } else if (screen === "identity") {
    identity = renderIdentity(
      root,
      identityFlow === "link" ? "link" : "setup",
      () => show(root, "roster"),
      () => {
        linkDeferred = true;
        show(root, "roster");
      },
    );
  } else {
    renderSignOn(root, () => show(root, "roster"));
  }
}

/** Routes an identity state to a screen.
 *
 *  "setup" takes the window unconditionally — the account cannot send or read
 *  encrypted messages until it has an identity, so there is nothing being held
 *  back. "link" offers itself once and accepts being deferred. Anything else
 *  means the identity screen has no business being up. */
function applyIdentityState(root: HTMLElement, st: IdentityState): void {
  identityFlow = st.flow;
  if (st.flow === "setup") {
    linkDeferred = false;
    show(root, "identity");
  } else if (st.flow === "link") {
    if (!linkDeferred) show(root, "identity");
  } else if (current === "identity") {
    show(root, "roster");
  }
}

function handleStatus(root: HTMLElement, status: SessionStatus): void {
  switch (status.state) {
    case "online":
      show(root, "roster");
      break;
    case "offline":
      identityFlow = "unavailable";
      linkDeferred = false;
      show(root, "signon");
      break;
    case "error":
      // A mid-session fault drops us back to sign-on with the reason shown,
      // rather than leaving a dead roster on screen.
      identityFlow = "unavailable";
      linkDeferred = false;
      show(root, "signon");
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
        show(root, on ? "roster" : "signon");
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
      .catch(() => show(root, "signon"));
  });
});
