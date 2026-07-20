// identity.ts — the account identity screens.
//
// Three flows share this module because they are the same screen with different
// words: first run (proposal §12), where an identity is generated and its
// recovery key shown exactly once; linking (§10, row two), where an identity
// already exists and this machine has to be signed into it; and re-keying (§10),
// where the identity is untouched and only the recovery key is replaced.
//
// All three lean on one gate — armRecoveryKeyGate — because all three end with a
// generated secret on screen that exists nowhere else yet.
//
// This is a top-level screen, not a dialog. §12 asks for the whole window for
// the first-run case: it is the only screen in BENCchat where dismissing
// something without reading it costs the user an account, and sign-on has
// already happened, so nothing that would otherwise work is being withheld.

import { Bridge } from "./bridge";
import { confirmDialog } from "./dialog";
import { mountRecoveryKeyInput, wordPositionFromError } from "./recoverykey-input";

// Mirrors e2ee.RecoveryKeyWords. Fixed: the number of words is baked into the
// key's entropy (10 × 11 bits), so it does not change without a protocol change.
const RECOVERY_KEY_WORDS = 10;

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

// --- The gate (§12), shared by first run and re-keying ----------------------

/** The elements a gate drives. Two screens supply these with different markup
 *  and different words; the LOGIC below is the same object in both, which is
 *  the point of the extraction. §12's gate is the only thing standing between a
 *  user and an account they cannot recover, and a second, weaker copy of it
 *  would be worse than not having one at all. */
interface GateElements {
  words: HTMLElement;
  gate: HTMLElement;
  gateState: HTMLElement;
  copyBtn: HTMLButtonElement;
  saveBtn: HTMLButtonElement;
  error: HTMLElement;
  continueBtn: HTMLButtonElement;
  /** The amber "this is the only copy" paragraph, revealed with the key. */
  fact?: HTMLElement;
}

interface Gate {
  /** Lays the key out and reveals the copy/save controls. Continue stays
   *  disabled until one of them reports success. */
  show(recoveryKey: string): void;
  /** Whether the gate has been satisfied. */
  isOpen(): boolean;
}

/** Wires up §12's gate over a set of elements.
 *
 *  It is opened in exactly two places — a copy the clipboard confirmed, and a
 *  save the Go side reported as written — and nothing else assigns to it.
 *  Neither proves the key is somewhere safe (§12 is explicit that "copied" is
 *  not "saved"); what they prove is that a deliberate action was taken, which is
 *  the strongest signal available from here. */
function armRecoveryKeyGate(els: GateElements): Gate {
  let gateOpen = false;

  const openGate = (msg: string): void => {
    gateOpen = true;
    els.continueBtn.disabled = false;
    els.gateState.textContent = msg;
  };

  els.copyBtn.addEventListener("click", async () => {
    const words = [...els.words.querySelectorAll<HTMLSpanElement>(".identity__word-t")]
      .map((n) => n.textContent ?? "")
      .join("-");
    if (!words) return;
    const ok = await Bridge.copyText(words);
    if (!ok) {
      // Some environments have no clipboard at all. Say so and point at the
      // other route rather than leaving a button that silently does nothing —
      // a gate with no way through would strand the account permanently.
      els.gateState.textContent = "";
      els.error.textContent =
        "This computer wouldn't let BENCchat use the clipboard. Save the words to a file instead.";
      return;
    }
    els.error.textContent = "";
    els.copyBtn.textContent = "Copied";
    window.setTimeout(() => (els.copyBtn.textContent = "Copy"), 2000);
    openGate("Copied to the clipboard.");
  });

  els.saveBtn.addEventListener("click", async () => {
    els.saveBtn.disabled = true;
    try {
      const err = await Bridge.saveRecoveryKeyToFile();
      if (err === SAVE_CANCELLED) return; // nothing was written; the gate stays shut
      if (err) {
        els.error.textContent = humanError(err);
        return;
      }
      els.error.textContent = "";
      openGate("Saved to a file.");
    } catch (e) {
      els.error.textContent = String(e);
    } finally {
      els.saveBtn.disabled = false;
    }
  });

  return {
    show(recoveryKey: string): void {
      // Numbered cells: a key read off the screen and typed into another
      // machine is read one word at a time, and the position is what an error
      // names.
      els.words.innerHTML = recoveryKey
        .split("-")
        .map(
          (w, i) => `
        <div class="identity__word">
          <span class="identity__word-n">${i + 1}</span>
          <span class="identity__word-t">${escapeHTML(w)}</span>
        </div>`,
        )
        .join("");
      if (els.fact) els.fact.hidden = false;
      els.gate.hidden = false;
    },
    isOpen: () => gateOpen,
  };
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
  const gateEl = el<HTMLDivElement>(root, "#gate");
  const gateState = el<HTMLSpanElement>(root, "#gateState");
  const copyKey = el<HTMLButtonElement>(root, "#copyKey");
  const saveKey = el<HTMLButtonElement>(root, "#saveKey");
  const idError = el<HTMLDivElement>(root, "#idError");
  const continueBtn = el<HTMLButtonElement>(root, "#continueBtn");
  const retryBegin = el<HTMLButtonElement>(root, "#retryBegin");

  const gate = armRecoveryKeyGate({
    words: keyWords,
    gate: gateEl,
    gateState,
    copyBtn: copyKey,
    saveBtn: saveKey,
    error: idError,
    continueBtn,
    fact: keyFact,
  });

  // Set before onDone() so destroy() doesn't zero a key that was just sealed.
  let confirmed = false;
  // Whether a key is currently on screen and therefore pending in Go.
  let pending = false;

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
      gateEl.hidden = true;
      idError.textContent = humanError(info.error || "No recovery key was generated.");
      retryBegin.hidden = false;
      return;
    }
    pending = true;
    gate.show(info.recoveryKey);
  };

  continueBtn.addEventListener("click", async () => {
    if (!gate.isOpen()) return;
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

        <label class="benco-label">Recovery key</label>
        <div id="rkBoxes"></div>
        <p class="benco-caption identity__hint">
          One word per box. Paste the whole key into any box and it fills the
          rest — case, spaces and hyphens all sort themselves out.
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

  const idError = el<HTMLDivElement>(root, "#idError");
  const linkBtn = el<HTMLButtonElement>(root, "#linkBtn");
  const skipBtn = el<HTMLButtonElement>(root, "#skipBtn");
  const rk = mountRecoveryKeyInput(
    el<HTMLDivElement>(root, "#rkBoxes"),
    RECOVERY_KEY_WORDS,
    () => void submit(),
  );

  const submit = async (): Promise<void> => {
    const key = rk.value();
    // A key with any empty box is incomplete; the join leaves a gap the Go
    // parser would reject less clearly than we can here.
    if (key.split("-").some((w) => w === "")) {
      idError.textContent = "Fill in all the words.";
      return;
    }
    linkBtn.disabled = true;
    linkBtn.textContent = "Linking…";
    idError.textContent = "";
    try {
      const err = await Bridge.linkDevice(key);
      if (err) {
        idError.textContent = humanError(err);
        // If the error names a word, highlight that box — the same locate-the-typo
        // feedback the single field could only put in text.
        const pos = wordPositionFromError(err);
        if (pos) rk.markInvalid(pos);
        return;
      }
      // Never leave the key in a DOM node once it has done its work.
      rk.clear();
      // §10: the user has just proved they hold the current key, which is one of
      // only two moments a re-key is possible. Offered, never imposed — and
      // offered here rather than remembered for later, because "later" is a
      // moment when the identity key is not in memory and the offer would be a
      // lie. Declining leaves everything exactly as it is.
      await offerRecoveryKeyRotation(key);
      onDone();
    } catch (e) {
      idError.textContent = String(e);
    } finally {
      linkBtn.disabled = false;
      linkBtn.textContent = "Link Device";
    }
  };

  linkBtn.addEventListener("click", () => void submit());
  // Enter-to-submit is wired through the box component's onEnter above.
  // Unlike first run, this screen is leaveable: the account is already set up
  // and works, this computer just can't read encrypted messages until it is
  // linked. Blocking the roster over that would withhold the parts that do
  // work. It does not come back on its own afterwards — §13, nothing nags.
  skipBtn.addEventListener("click", () => {
    rk.clear();
    onSkip();
  });

  rk.focus();

  return {
    destroy(): void {
      // A recovery key must not outlive the screen in a DOM node.
      rk.clear();
    },
  };
}

// --- Re-keying (§10) --------------------------------------------------------

/** Asks whether the user wants to replace their recovery key, and runs the
 *  re-key if they do. Resolves once the offer is finished with, either way.
 *
 *  `currentKey` is the key the user has just successfully used, which is why
 *  this can only be called from the two places §10 names: linking a device, and
 *  Verify now. Under transient custody the identity key exists in memory only
 *  during a call that was given the current recovery key, so there is no third
 *  moment and no way to manufacture one.
 *
 *  The offer is a plain question with no urgency attached. Nobody is nudged
 *  towards it: someone who has just linked a laptop has no reason to re-key, and
 *  §13's rule that nothing nags applies to suggestions as much as to alerts. */
export async function offerRecoveryKeyRotation(currentKey: string): Promise<void> {
  const yes = await confirmDialog(
    "Your recovery key can be replaced with a new one now, while you're holding " +
      "the current one. This is worth doing if you think the old one has been " +
      "seen by someone else.\n\n" +
      "It does NOT change your account's identity: your devices stay linked, " +
      "your messages stay readable, and your contacts see no change at all. " +
      "Only the words you'd type to link a device are different.",
    {
      title: "Replace your recovery key?",
      okLabel: "Replace It",
      cancelLabel: "Keep Current Key",
    },
  );
  if (!yes) return;
  await runRecoveryKeyRotation(currentKey);
}

/** The re-key screen: the same shape and the same gate as first run, over
 *  whatever is on screen.
 *
 *  It is an overlay rather than a route because it is reached from two places
 *  that are not screens — a settings panel and the tail of a link — and because
 *  the thing that matters about it is not where it sits but that it cannot be
 *  left by accident while a key is on it. */
async function runRecoveryKeyRotation(currentKey: string): Promise<void> {
  const host = document.createElement("div");
  host.className = "identity identity--overlay";
  host.innerHTML = `
    <div class="identity__panel">
      <div class="identity__head">
        <h1 class="benco-title">New Recovery Key</h1>
        <p class="identity__lead">
          Replacing your recovery key changes the words and nothing else. Your
          account keeps the same identity, every device you've linked stays
          linked, and nobody you talk to sees anything change — this is not the
          same as starting over as a new person.
        </p>
      </div>

      <hr class="benco-rule" />

      <div class="identity__key" id="rkWords">
        <p class="benco-caption identity__working">Checking your current key…</p>
      </div>

      <p class="identity__fact" id="rkFact" hidden>
        <strong>Your old recovery key still works until you press Replace.</strong>
        The moment you do, it stops — these words become the only way to link or
        remove a device. There is no copy of them anywhere else, so save them
        before continuing, and delete the old ones afterwards.
      </p>

      <div class="identity__gate" id="rkGate" hidden>
        <button class="benco-button" id="rkCopy">Copy</button>
        <button class="benco-button benco-button--ghost" id="rkSave">Save to a file…</button>
        <span class="benco-caption identity__gate-state" id="rkGateState"></span>
      </div>

      <div class="benco-error identity__error" id="rkError"></div>

      <div class="identity__actions">
        <button class="benco-button benco-button--ghost" id="rkCancel">Keep Current Key</button>
        <button class="benco-button" id="rkContinue" disabled>Replace</button>
      </div>
    </div>`;
  document.body.appendChild(host);

  const words = el<HTMLDivElement>(host, "#rkWords");
  const fact = el<HTMLParagraphElement>(host, "#rkFact");
  const gateEl = el<HTMLDivElement>(host, "#rkGate");
  const gateState = el<HTMLSpanElement>(host, "#rkGateState");
  const copyBtn = el<HTMLButtonElement>(host, "#rkCopy");
  const saveBtn = el<HTMLButtonElement>(host, "#rkSave");
  const errorEl = el<HTMLDivElement>(host, "#rkError");
  const continueBtn = el<HTMLButtonElement>(host, "#rkContinue");
  const cancelBtn = el<HTMLButtonElement>(host, "#rkCancel");

  // The SAME gate as first run, over different markup and different words. A
  // re-key that let someone through on a weaker check would be the worse of the
  // two failures: first run strands an account that never existed, this one
  // strands an account that does.
  const gate = armRecoveryKeyGate({
    words,
    gate: gateEl,
    gateState,
    copyBtn,
    saveBtn,
    error: errorEl,
    continueBtn,
    fact,
  });

  return new Promise<void>((resolve) => {
    let generated = false;
    let done = false;

    const close = (): void => {
      if (done) return;
      done = true;
      document.removeEventListener("keydown", swallowEscape, true);
      host.remove();
      resolve();
    };

    // No Escape, for the same reason as first run — though the failure here is
    // subtler than an unrecoverable account. Dismissing after saving the new key
    // to a file would leave that file holding words that never became live,
    // sitting next to the ones that still are. Leaving is an explicit button.
    const swallowEscape = (e: KeyboardEvent): void => {
      if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
      }
    };
    document.addEventListener("keydown", swallowEscape, true);

    cancelBtn.addEventListener("click", () => {
      // Nothing has been stored, so this genuinely costs nothing: the server
      // still holds the backup the current key opens.
      if (generated) void Bridge.cancelRecoveryKeyRotation();
      close();
    });

    continueBtn.addEventListener("click", async () => {
      if (!gate.isOpen()) return;
      continueBtn.disabled = true;
      continueBtn.textContent = "Replacing…";
      cancelBtn.disabled = true;
      errorEl.textContent = "";
      try {
        const err = await Bridge.confirmRecoveryKeyRotation();
        if (err) {
          // Stay put with the new words still on screen, exactly as first run
          // does — and the old key is still the live one, so nothing is lost.
          errorEl.textContent = humanError(err);
          continueBtn.textContent = "Try Again";
          continueBtn.disabled = false;
          cancelBtn.disabled = false;
          return;
        }
        generated = false; // stored; there is nothing pending left to cancel
        close();
      } catch (e) {
        errorEl.textContent = String(e);
        continueBtn.textContent = "Try Again";
        continueBtn.disabled = false;
        cancelBtn.disabled = false;
      }
    });

    void (async () => {
      let info;
      try {
        info = await Bridge.beginRecoveryKeyRotation(currentKey);
      } catch (e) {
        info = { recoveryKey: "", error: String(e) };
      }
      if (info.error || !info.recoveryKey) {
        words.innerHTML = "";
        errorEl.textContent = humanError(info.error || "No recovery key was generated.");
        cancelBtn.textContent = "Close";
        return;
      }
      generated = true;
      gate.show(info.recoveryKey);
    })();
  });
}
