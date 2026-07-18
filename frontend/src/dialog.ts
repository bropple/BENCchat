// dialog.ts — themed, in-app modal dialogs that replace the webview's native
// window.alert / confirm / prompt. Those render as unstyled OS/GTK popups (with
// a "JavaScript - wails://…" titlebar); these are plain HTML styled with the
// same BENCO tokens as the rest of the app, so they follow the chosen theme.
//
// alertDialog → void, confirmDialog → boolean, promptDialog → string|null,
// choiceDialog → the chosen value|null. Escape and a backdrop click cancel.

interface DialogOptions {
  title?: string;
  okLabel?: string;
  cancelLabel?: string;
  /** Style the confirm button as destructive (delete/block/remove). */
  danger?: boolean;
}

function escapeHTML(s: string): string {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

// One button in the action row. `value` is what the dialog resolves to when it's
// clicked; the last button renders solid (primary), the rest ghost.
interface Button {
  label: string;
  value: string | boolean | null;
  danger?: boolean;
}

interface CoreConfig {
  title: string;
  message: string;
  input?: { defaultValue: string; placeholder?: string };
  buttons: Button[];
  cancelValue: string | boolean | null;
}

// Shared builder. Resolves with the clicked button's value (or cancelValue on
// Escape/backdrop) plus the input's final text.
function openCore(cfg: CoreConfig): Promise<{ value: string | boolean | null; input: string }> {
  return new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.className = "dialog-overlay";

    const inputHTML = cfg.input
      ? `<input class="benco-input dialog__input" id="dlgInput" spellcheck="false" />`
      : "";
    const buttonsHTML = cfg.buttons
      .map((b, i) => {
        const primary = i === cfg.buttons.length - 1;
        const cls = b.danger ? "dialog__btn--danger" : primary ? "" : "benco-button--ghost";
        return `<button class="benco-button ${cls}" data-i="${i}">${escapeHTML(b.label)}</button>`;
      })
      .join("");

    overlay.innerHTML = `
      <div class="dialog" role="dialog" aria-modal="true" aria-label="${escapeHTML(cfg.title)}">
        <div class="dialog__title benco-label">${escapeHTML(cfg.title)}</div>
        <div class="dialog__msg">${escapeHTML(cfg.message)}</div>
        ${inputHTML}
        <div class="dialog__actions">${buttonsHTML}</div>
      </div>`;

    document.body.appendChild(overlay);

    const inputEl = overlay.querySelector<HTMLInputElement>("#dlgInput");
    if (inputEl && cfg.input) {
      inputEl.value = cfg.input.defaultValue;
      if (cfg.input.placeholder) inputEl.placeholder = cfg.input.placeholder;
    }

    let done = false;
    const finish = (value: string | boolean | null): void => {
      if (done) return;
      done = true;
      document.removeEventListener("keydown", onKey, true);
      overlay.remove();
      resolve({ value, input: inputEl?.value ?? "" });
    };

    const onKey = (e: KeyboardEvent): void => {
      if (e.key === "Escape") {
        e.preventDefault();
        finish(cfg.cancelValue);
      } else if (e.key === "Enter" && (!inputEl || document.activeElement === inputEl)) {
        // Enter triggers the primary (last) button.
        e.preventDefault();
        finish(cfg.buttons[cfg.buttons.length - 1].value);
      }
    };
    document.addEventListener("keydown", onKey, true);

    for (const btn of overlay.querySelectorAll<HTMLButtonElement>(".dialog__actions button")) {
      btn.addEventListener("click", () => finish(cfg.buttons[Number(btn.dataset.i)].value));
    }
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) finish(cfg.cancelValue);
    });

    (inputEl ?? overlay.querySelector<HTMLButtonElement>(".dialog__actions button:last-child"))?.focus();
    inputEl?.select();
  });
}

/** Themed replacement for window.alert. */
export async function alertDialog(message: string, opts: DialogOptions = {}): Promise<void> {
  await openCore({
    title: opts.title ?? "BENCchat",
    message,
    buttons: [{ label: opts.okLabel ?? "OK", value: true }],
    cancelValue: true,
  });
}

/** Themed replacement for window.confirm. Resolves true on OK. */
export async function confirmDialog(message: string, opts: DialogOptions = {}): Promise<boolean> {
  const { value } = await openCore({
    title: opts.title ?? "BENCchat",
    message,
    buttons: [
      { label: opts.cancelLabel ?? "Cancel", value: false },
      { label: opts.okLabel ?? "OK", value: true, danger: opts.danger },
    ],
    cancelValue: false,
  });
  return value === true;
}

/** Themed replacement for window.prompt. Resolves the entered string, or null if
 *  cancelled. */
export async function promptDialog(
  message: string,
  defaultValue = "",
  opts: DialogOptions & { placeholder?: string } = {},
): Promise<string | null> {
  const { value, input } = await openCore({
    title: opts.title ?? "BENCchat",
    message,
    input: { defaultValue, placeholder: opts.placeholder },
    buttons: [
      { label: opts.cancelLabel ?? "Cancel", value: false },
      { label: opts.okLabel ?? "OK", value: true },
    ],
    cancelValue: false,
  });
  return value === true ? input : null;
}

/** A dialog with N labeled choices plus a Cancel. Resolves the chosen value, or
 *  null if cancelled. Choices render left→right with the last one primary. */
export async function choiceDialog(
  message: string,
  choices: { label: string; value: string; danger?: boolean }[],
  opts: DialogOptions = {},
): Promise<string | null> {
  const { value } = await openCore({
    title: opts.title ?? "BENCchat",
    message,
    buttons: [{ label: opts.cancelLabel ?? "Cancel", value: null }, ...choices],
    cancelValue: null,
  });
  return typeof value === "string" ? value : null;
}
