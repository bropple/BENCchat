// signon.ts — the sign-on screen.

import { Bridge, type SessionStatus } from "./bridge";
import { openSettings } from "./settings";
import { setSoundEnabled } from "./sound";
import { serverDialog } from "./dialog";
import bencoLogo from "./assets/benco-logo.png";

// The R. Triy mark (canonical roster triangle + visor) rendered inline so the
// sign-on screen carries BENCO identity without an external asset request.
// Colors are the canonical R. Triy fill/edge pair from the style guide.
const TRIY_MARK = `
<svg class="signon__mark" viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
  <path d="M 100 16 L 179.8 167.2 L 20.2 167.2 Z" fill="#78b946" stroke="#3f5c28" stroke-width="2"/>
  <rect x="53.8" y="95.8" width="92.4" height="28.56" fill="#9a9d94"/>
  <rect x="70.6" y="103.36" width="58.8" height="13.44" fill="#d84a3a"/>
</svg>`;

export function renderSignOn(root: HTMLElement, onSignedOn: () => void): void {
  root.innerHTML = `
    <div class="signon">
      <div class="signon__panel">
        <div class="signon__brand">
          ${TRIY_MARK}
          <div class="signon__wordmark">
            <h1 class="benco-title">BENCchat</h1>
            <span class="signon__sub">BENCO Holdings</span>
          </div>
        </div>

        <hr class="benco-rule" />

        <div class="signon__field">
          <label class="benco-label" for="screenName">Screen Name</label>
          <input class="benco-input" id="screenName" type="text"
                 autocomplete="username" spellcheck="false" />
        </div>

        <div class="signon__field">
          <label class="benco-label" for="password">Password</label>
          <input class="benco-input" id="password" type="password"
                 autocomplete="current-password" />
        </div>

        <label class="signon__remember">
          <input type="checkbox" id="rememberMe" />
          <span class="benco-caption">Stay signed in on this computer</span>
        </label>

        <div class="signon__actions">
          <button class="benco-button" id="signOn">Sign On</button>
        </div>

        <div class="signon__error-wrap">
          <div class="benco-error signon__error" id="error"></div>
          <button class="signon__copy" id="copyError" type="button"
                  title="Copy this message" hidden>Copy</button>
        </div>

        <hr class="benco-rule" />

        <div class="signon__row">
          <div class="signon__server" id="serverToggle" title="Change server">
            <span class="benco-caption">Server:</span>
            <span class="benco-caption signon__server-value" id="serverValue">—</span>
          </div>
          <button class="settings-gear" id="settingsBtn" title="Settings">⚙ Settings</button>
        </div>
      </div>

      <img class="signon__logo" src="${bencoLogo}" alt="BENCO Holdings" aria-hidden="true" />
    </div>`;

  const el = <T extends HTMLElement>(id: string): T => {
    const node = document.getElementById(id);
    if (!node) throw new Error(`missing element #${id}`);
    return node as T;
  };

  const screenName = el<HTMLInputElement>("screenName");
  const password = el<HTMLInputElement>("password");
  const signOn = el<HTMLButtonElement>("signOn");
  const error = el<HTMLDivElement>("error");
  const serverValue = el<HTMLSpanElement>("serverValue");
  const serverToggle = el<HTMLDivElement>("serverToggle");
  const rememberMe = el<HTMLInputElement>("rememberMe");

  const copyError = el<HTMLButtonElement>("copyError");

  const setError = (msg: string) => {
    error.textContent = msg;
    copyError.hidden = msg === "";
    copyError.textContent = "Copy";
  };

  // Sign-on failures are exactly the text someone needs to paste elsewhere to
  // ask what it means, so copying it shouldn't require selecting it by hand.
  // (Selecting still works too — see .signon__error in signon.css.)
  copyError.addEventListener("click", async () => {
    const ok = await Bridge.copyText(error.textContent ?? "");
    copyError.textContent = ok ? "Copied" : "Press Ctrl+C";
    window.setTimeout(() => (copyError.textContent = "Copy"), 2000);
  });

  // Prefill server address + remembered screen name from Go config, and reflect
  // whether a password is already saved for auto-login.
  Bridge.getServerSettings()
    .then((s) => {
      // Show the transport plainly. An encrypted connection is something the
      // user should be able to confirm at a glance, and its absence should be
      // visible rather than implied.
      serverValue.textContent = `${s.host}:${s.port}${
        s.tls ? (s.tlsInsecure ? " 🔓 TLS (unverified)" : " 🔒 TLS") : " (not encrypted)"
      }`;
      // Default "stay signed in" on unless the user previously turned it off by
      // signing off (which clears the remembered flag on an otherwise-fresh run).
      rememberMe.checked = s.remembered || !s.lastScreenName;
      if (s.lastScreenName) {
        screenName.value = s.lastScreenName;
        password.focus();
      } else {
        screenName.focus();
      }
    })
    .catch((e) => setError(String(e)));

  const submit = async () => {
    setError("");
    signOn.disabled = true;
    signOn.textContent = "Signing On…";
    try {
      const err = await Bridge.signIn(screenName.value.trim(), password.value, rememberMe.checked);
      if (err) {
        setError(err);
        return;
      }
      // Never keep the password in a DOM node once it has served its purpose.
      password.value = "";
      onSignedOn();
    } catch (e) {
      setError(String(e));
    } finally {
      signOn.disabled = false;
      signOn.textContent = "Sign On";
    }
  };

  el<HTMLButtonElement>("settingsBtn").addEventListener("click", () => {
    openSettings((on) => setSoundEnabled(on));
  });

  signOn.addEventListener("click", submit);
  password.addEventListener("keydown", (e) => {
    if (e.key === "Enter") submit();
  });
  screenName.addEventListener("keydown", (e) => {
    if (e.key === "Enter") password.focus();
  });

  // Minimal server switcher via prompt() for now — a proper settings panel is
  // a later phase; the point today is that the address is not hardcoded.
  serverToggle.addEventListener("click", async () => {
    // Ask the backend rather than re-parsing serverValue: that element holds a
    // display string with a "🔒 TLS" suffix, and feeding it back in as an
    // editable value is what used to produce a NaN port.
    const s = await Bridge.getServerSettings();
    const next = await serverDialog(s.host, s.port);
    if (!next) return;
    const err = await Bridge.saveServerSettings(next.host, next.port);
    if (err) {
      setError(err);
      return;
    }
    serverValue.textContent = `${next.host}:${next.port}${
      s.tls ? (s.tlsInsecure ? " 🔓 TLS (unverified)" : " 🔒 TLS") : " (not encrypted)"
    }`;
  });
}

/** Shows a sign-on status update in the error slot. */
export function showSignOnStatus(status: SessionStatus): void {
  const error = document.getElementById("error");
  if (error && status.state === "error") {
    error.textContent = status.message;
    // Keep the copy affordance in step with the message it copies.
    const copy = document.getElementById("copyError");
    if (copy) copy.hidden = status.message === "";
  }
}
