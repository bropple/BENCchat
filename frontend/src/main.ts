import "./style.css";
import "./signon.css";
import "./roster.css";
import "./settings.css";
import "./dialog.css";
import "./titlebar.css";

import { Bridge, type SessionStatus } from "./bridge";
import { renderSignOn, showSignOnStatus } from "./signon";
import { renderRoster, type RosterHandle } from "./roster";
import { loadAndApplyTheme } from "./theme";
import { setSoundEnabled, setSoundPack, setMutedSounds, loadCustomSounds } from "./sound";
import { mountTitlebar } from "./titlebar";
import { alertDialog, confirmDialog } from "./dialog";

function el<T extends HTMLElement>(id: string): T {
  const node = document.getElementById(id);
  if (!node) throw new Error(`missing element #${id}`);
  return node as T;
}

/** The two screens this app has. */
type Screen = "signon" | "roster";

let current: Screen = "signon";
let roster: RosterHandle | null = null;

function show(root: HTMLElement, screen: Screen): void {
  if (screen === current && screen === "roster") return;
  current = screen;

  roster?.destroy();
  roster = null;

  if (screen === "roster") {
    roster = renderRoster(root, () => show(root, "signon"));
  } else {
    renderSignOn(root, () => show(root, "roster"));
  }
}

function handleStatus(root: HTMLElement, status: SessionStatus): void {
  switch (status.state) {
    case "online":
      show(root, "roster");
      break;
    case "offline":
      show(root, "signon");
      break;
    case "error":
      // A mid-session fault drops us back to sign-on with the reason shown,
      // rather than leaving a dead roster on screen.
      show(root, "signon");
      showSignOnStatus(status);
      break;
  }
}

window.addEventListener("DOMContentLoaded", () => {
  const root = el<HTMLDivElement>("app");

  Bridge.onSessionStatus((status) => handleStatus(root, status));

  // A new machine signing in to this account asks to be linked. Approval is
  // deliberately manual: the request only proves whoever sent it knows the
  // account password, which must not by itself grant the ability to read
  // everything encrypted to this account.
  // A device is only ever asked about once. The backend already suppresses a
  // repeat announcement, but a dialog is async: two requests arriving before
  // the first is answered would otherwise stack, and answering both approves
  // the same device twice.
  const askingAbout = new Set<string>();

  Bridge.onDeviceLinkRequest((req) => {
    if (askingAbout.has(req.key)) return;
    askingAbout.add(req.key);
    void (async () => {
      try {
        const ok = await confirmDialog(
          `A new device wants to link to your account.\n\nDevice code:\n${req.fingerprint}\n\n` +
            `Check that this matches the code shown on that device. If it doesn't — or you're ` +
            `not setting up a device right now — decline: approving lets it read your encrypted messages.`,
          { title: "Link a new device?", okLabel: "Approve", cancelLabel: "Decline", danger: true },
        );
        if (!ok) {
          // Tell the backend, so the same device announcing again this session
          // doesn't re-ask something already answered.
          void Bridge.declineDevice(req.key);
          return;
        }
        const err = await Bridge.approveDevice(req.key);
        if (err) void alertDialog(err, { title: "Could not link device" });
      } finally {
        askingAbout.delete(req.key);
      }
    })();
  });

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
        // If we're not already signed on, try a remembered password. On success
        // the "online" session-status event moves us to the roster; on failure
        // we simply stay on the sign-on screen.
        if (!on) void Bridge.autoSignIn();
      })
      .catch(() => show(root, "signon"));
  });
});
