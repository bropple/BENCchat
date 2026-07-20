// identity.ts — the account identity screens.
//
// Two flows share this module because they are the same screen with different
// words: first run (proposal §12), where an identity is generated and its
// recovery key shown exactly once, and linking (§10, row two), where an
// identity already exists and this machine has to be signed into it.
//
// This is a top-level screen, not a dialog. §12 asks for the whole window for
// the first-run case: it is the only screen in BENCchat where dismissing
// something without reading it costs the user an account, and sign-on has
// already happened, so nothing that would otherwise work is being withheld.

import { Bridge } from "./bridge";

export interface IdentityHandle {
  destroy(): void;
}

/** Strips the Go package prefix off an error surfaced straight from e2ee.
 *
 *  These reach the UI verbatim because the interesting ones are precise —
 *  "word 7 is not in the recovery wordlist" locates a typo in a handwritten key,
 *  where "wrong recovery key" sends someone to re-check all ten or to conclude
 *  the key is lost over one smudged letter. Only the "e2ee:" prefix is dropped;
 *  the sentence itself is the message. */
function humanError(msg: string): string {
  const s = msg.replace(/^e2ee:\s*/, "").trim();
  if (!s) return "";
  const capped = s.charAt(0).toUpperCase() + s.slice(1);
  return /[.!?]$/.test(capped) ? capped : `${capped}.`;
}

/** Matches app_identity.go's SaveRecoveryKeyCancelled.
 *
 *  A cancelled save dialog is not an error and must not be shown as one — but
 *  it is emphatically not a saved key either, so it must be distinguishable
 *  from success, or the gate below would open on a file picker that was opened
 *  and dismissed. */
const SAVE_CANCELLED = "cancelled";

function el<T extends HTMLElement>(root: HTMLElement, sel: string): T {
  const node = root.querySelector<T>(sel);
  if (!node) throw new Error(`missing element ${sel}`);
  return node;
}

function escapeHTML(s: string): string {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

export function renderIdentity(
  root: HTMLElement,
  flow: "setup" | "link",
  onDone: () => void,
  onSkip: () => void,
): IdentityHandle {
  return flow === "setup" ? renderSetup(root, onDone) : renderLink(root, onDone, onSkip);
}

// --- First run (§12) --------------------------------------------------------

function renderSetup(root: HTMLElement, onDone: () => void): IdentityHandle {
  root.innerHTML = `
    <div class="identity">
      <div class="identity__panel">
        <div class="identity__head">
          <h1 class="benco-title">Recovery Key</h1>
          <p class="identity__lead">
            This account is getting its encryption identity. These words are the
            only key to it. They are what links a new computer to this account,
            and what removes one — nothing else can.
          </p>
        </div>

        <hr class="benco-rule" />

        <div class="identity__key" id="keyWords">
          <p class="benco-caption identity__working">Generating…</p>
        </div>

        <p class="identity__fact" id="keyFact" hidden>
          <strong>This is the only time these words exist.</strong>
          BENCchat does not keep a copy — it uses them and forgets them — so
          there is nothing to show again, on this computer or any other. Put them
          in a password manager, print them, or keep them where you keep a
          passport.
        </p>

        <div class="identity__gate" id="gate" hidden>
          <button class="benco-button" id="copyKey">Copy</button>
          <button class="benco-button benco-button--ghost" id="saveKey">Save to a file…</button>
          <span class="benco-caption identity__gate-state" id="gateState"></span>
        </div>

        <div class="benco-error identity__error" id="idError"></div>

        <div class="identity__actions">
          <button class="benco-button" id="continueBtn" disabled>Continue</button>
          <button class="benco-button benco-button--ghost" id="retryBegin" hidden>Try Again</button>
        </div>
      </div>
    </div>`;

  const keyWords = el<HTMLDivElement>(root, "#keyWords");
  const keyFact = el<HTMLParagraphElement>(root, "#keyFact");
  const gate = el<HTMLDivElement>(root, "#gate");
  const gateState = el<HTMLSpanElement>(root, "#gateState");
  const copyKey = el<HTMLButtonElement>(root, "#copyKey");
  const saveKey = el<HTMLButtonElement>(root, "#saveKey");
  const idError = el<HTMLDivElement>(root, "#idError");
  const continueBtn = el<HTMLButtonElement>(root, "#continueBtn");
  const retryBegin = el<HTMLButtonElement>(root, "#retryBegin");

  // The gate. It is opened in exactly two places — a copy the clipboard
  // confirmed, and a save the Go side reported as written — and nothing else
  // in this file assigns to it. Neither proves the key is somewhere safe (§12
  // is explicit that "copied" is not "saved"); what they prove is that a
  // deliberate action was taken, which is the strongest signal available here.
  let gateOpen = false;
  // Set before onDone() so destroy() doesn't zero a key that was just sealed.
  let confirmed = false;
  // Whether a key is currently on screen and therefore pending in Go.
  let pending = false;

  const openGate = (msg: string): void => {
    gateOpen = true;
    continueBtn.disabled = false;
    gateState.textContent = msg;
  };

  const begin = async (): Promise<void> => {
    idError.textContent = "";
    retryBegin.hidden = true;
    keyWords.innerHTML = `<p class="benco-caption identity__working">Generating…</p>`;
    let info;
    try {
      info = await Bridge.beginIdentitySetup();
    } catch (e) {
      info = { recoveryKey: "", error: String(e) };
    }
    if (info.error || !info.recoveryKey) {
      keyWords.innerHTML = "";
      keyFact.hidden = true;
      gate.hidden = true;
      idError.textContent = humanError(info.error || "No recovery key was generated.");
      retryBegin.hidden = false;
      return;
    }
    pending = true;
    // Numbered cells: a key read off the screen and typed into another machine
    // is read one word at a time, and the position is what an error names.
    keyWords.innerHTML = info.recoveryKey
      .split("-")
      .map(
        (w, i) => `
        <div class="identity__word">
          <span class="identity__word-n">${i + 1}</span>
          <span class="identity__word-t">${escapeHTML(w)}</span>
        </div>`,
      )
      .join("");
    keyFact.hidden = false;
    gate.hidden = false;
  };

  copyKey.addEventListener("click", async () => {
    const words = [...keyWords.querySelectorAll<HTMLSpanElement>(".identity__word-t")]
      .map((n) => n.textContent ?? "")
      .join("-");
    if (!words) return;
    const ok = await Bridge.copyText(words);
    if (!ok) {
      // Some environments have no clipboard at all. Say so and point at the
      // other route rather than leaving a button that silently does nothing —
      // a gate with no way through would strand the account permanently.
      gateState.textContent = "";
      idError.textContent =
        "This computer wouldn't let BENCchat use the clipboard. Save the words to a file instead.";
      return;
    }
    idError.textContent = "";
    copyKey.textContent = "Copied";
    window.setTimeout(() => (copyKey.textContent = "Copy"), 2000);
    openGate("Copied to the clipboard.");
  });

  saveKey.addEventListener("click", async () => {
    saveKey.disabled = true;
    try {
      const err = await Bridge.saveRecoveryKeyToFile();
      if (err === SAVE_CANCELLED) return; // nothing was written; the gate stays shut
      if (err) {
        idError.textContent = humanError(err);
        return;
      }
      idError.textContent = "";
      openGate("Saved to a file.");
    } catch (e) {
      idError.textContent = String(e);
    } finally {
      saveKey.disabled = false;
    }
  });

  continueBtn.addEventListener("click", async () => {
    if (!gateOpen) return;
    continueBtn.disabled = true;
    continueBtn.textContent = "Saving…";
    idError.textContent = "";
    try {
      const err = await Bridge.confirmIdentitySetup();
      if (err) {
        // Stay put, with the words still on screen and still saveable. §12:
        // dismissing first and failing after is the crash window in miniature.
        idError.textContent = humanError(err);
        continueBtn.textContent = "Try Again";
        continueBtn.disabled = false;
        return;
      }
      confirmed = true;
      pending = false;
      onDone();
    } catch (e) {
      idError.textContent = String(e);
      continueBtn.textContent = "Try Again";
      continueBtn.disabled = false;
    }
  });

  retryBegin.addEventListener("click", () => void begin());

  // §12: no close button, no "remind me later" — and no escape key. Capturing
  // the keydown stops it reaching any handler that would treat it as a dismiss.
  const swallowEscape = (e: KeyboardEvent): void => {
    if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
    }
  };
  document.addEventListener("keydown", swallowEscape, true);

  void begin();

  return {
    destroy(): void {
      document.removeEventListener("keydown", swallowEscape, true);
      // Torn down without confirming — a sign-off, or the session dropping.
      // Nothing was written, so the right move is to zero the generated key
      // rather than leave it sitting in the Go process; the next attempt is a
      // clean first run with a new one.
      if (pending && !confirmed) void Bridge.cancelIdentitySetup();
    },
  };
}

// --- Linking this device (§10, row two) -------------------------------------

function renderLink(
  root: HTMLElement,
  onDone: () => void,
  onSkip: () => void,
): IdentityHandle {
  root.innerHTML = `
    <div class="identity">
      <div class="identity__panel">
        <div class="identity__head">
          <h1 class="benco-title">Link This Device</h1>
          <p class="identity__lead">
            This account already has an encryption identity, and this computer
            isn't part of it yet — so it can't read messages encrypted to you.
            Enter the recovery key you saved when the account was set up.
          </p>
        </div>

        <hr class="benco-rule" />

        <label class="benco-label" for="rkInput">Recovery key</label>
        <textarea class="benco-input identity__rk" id="rkInput" rows="3"
                  spellcheck="false" autocomplete="off"
                  placeholder="word-word-word…"></textarea>
        <p class="benco-caption identity__hint">
          Spaces or hyphens, upper or lower case — all of it is accepted.
        </p>

        <div class="benco-error identity__error" id="idError"></div>

        <div class="identity__actions">
          <button class="benco-button benco-button--ghost" id="skipBtn">Not Now</button>
          <button class="benco-button" id="linkBtn">Link Device</button>
        </div>

        <hr class="benco-rule" />

        <p class="benco-caption identity__hint">
          Linking costs the recovery key every time, and that is the design: no
          computer keeps the account's identity, so a stolen laptop is a stolen
          laptop rather than a stolen account. Without the key, no device can be
          linked or removed until an administrator clears the account's identity
          and you start over.
        </p>
      </div>
    </div>`;

  const rkInput = el<HTMLTextAreaElement>(root, "#rkInput");
  const idError = el<HTMLDivElement>(root, "#idError");
  const linkBtn = el<HTMLButtonElement>(root, "#linkBtn");
  const skipBtn = el<HTMLButtonElement>(root, "#skipBtn");

  const submit = async (): Promise<void> => {
    const key = rkInput.value.trim();
    if (!key) {
      idError.textContent = "Enter your recovery key.";
      return;
    }
    linkBtn.disabled = true;
    linkBtn.textContent = "Linking…";
    idError.textContent = "";
    try {
      const err = await Bridge.linkDevice(key);
      if (err) {
        idError.textContent = humanError(err);
        return;
      }
      // Never leave the key in a DOM node once it has done its work.
      rkInput.value = "";
      onDone();
    } catch (e) {
      idError.textContent = String(e);
    } finally {
      linkBtn.disabled = false;
      linkBtn.textContent = "Link Device";
    }
  };

  linkBtn.addEventListener("click", () => void submit());
  rkInput.addEventListener("keydown", (e) => {
    // Enter submits; Shift+Enter is left alone so a key pasted across lines
    // can still be edited.
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      void submit();
    }
  });
  // Unlike first run, this screen is leaveable: the account is already set up
  // and works, this computer just can't read encrypted messages until it is
  // linked. Blocking the roster over that would withhold the parts that do
  // work. It does not come back on its own afterwards — §13, nothing nags.
  skipBtn.addEventListener("click", () => {
    rkInput.value = "";
    onSkip();
  });

  rkInput.focus();

  return {
    destroy(): void {
      rkInput.value = "";
    },
  };
}
