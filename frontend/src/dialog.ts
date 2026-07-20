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

/** One labelled text input. Several can appear in a dialog — a server address
 *  is two separate values, and asking for "host:port" in one box makes the user
 *  do the parsing (and get it wrong). */
interface Field {
  /** Key this field's value appears under in the resolved `inputs`. */
  name: string;
  label?: string;
  defaultValue: string;
  placeholder?: string;
  /** Relative width when fields share a row. Defaults to 1. */
  flex?: number;
  inputMode?: string;
}

interface CoreConfig {
  title: string;
  message: string;
  fields?: Field[];
  buttons: Button[];
  cancelValue: string | boolean | null;
  /** Shown in the dialog's error slot when it opens (used to re-prompt after a
   *  validation failure without losing what was typed). */
  error?: string;
}

// Shared builder. Resolves with the clicked button's value (or cancelValue on
// Escape/backdrop) plus the input's final text.
function openCore(
  cfg: CoreConfig,
): Promise<{ value: string | boolean | null; inputs: Record<string, string> }> {
  return new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.className = "dialog-overlay";

    const fields = cfg.fields ?? [];
    const inputHTML = fields.length
      ? `<div class="dialog__fields">${fields
          .map(
            (f, i) => `
          <label class="dialog__field" style="flex:${f.flex ?? 1}">
            ${f.label ? `<span class="benco-caption">${escapeHTML(f.label)}</span>` : ""}
            <input class="benco-input dialog__input" data-f="${i}" spellcheck="false" />
          </label>`,
          )
          .join("")}</div>`
      : "";
    const errorHTML = `<div class="dialog__error benco-error" id="dlgError"></div>`;
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
        ${errorHTML}
        <div class="dialog__actions">${buttonsHTML}</div>
      </div>`;

    document.body.appendChild(overlay);

    const inputEls = [...overlay.querySelectorAll<HTMLInputElement>(".dialog__input")];
    inputEls.forEach((el, i) => {
      const f = fields[i];
      el.value = f.defaultValue;
      if (f.placeholder) el.placeholder = f.placeholder;
      if (f.inputMode) el.inputMode = f.inputMode;
    });

    const errorEl = overlay.querySelector<HTMLDivElement>("#dlgError")!;
    errorEl.textContent = cfg.error ?? "";

    const inputEl = inputEls[0];
    const collect = (): Record<string, string> =>
      Object.fromEntries(fields.map((f, i) => [f.name, inputEls[i]?.value ?? ""]));

    let done = false;
    const finish = (value: string | boolean | null): void => {
      if (done) return;
      done = true;
      const inputs = collect();
      document.removeEventListener("keydown", onKey, true);
      overlay.remove();
      resolve({ value, inputs });
    };

    const onKey = (e: KeyboardEvent): void => {
      if (e.key === "Escape") {
        e.preventDefault();
        finish(cfg.cancelValue);
      } else if (
        e.key === "Enter" &&
        (!inputEl || inputEls.includes(document.activeElement as HTMLInputElement))
      ) {
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
  const { value, inputs } = await openCore({
    title: opts.title ?? "BENCchat",
    message,
    fields: [{ name: "text", defaultValue, placeholder: opts.placeholder }],
    buttons: [
      { label: opts.cancelLabel ?? "Cancel", value: false },
      { label: opts.okLabel ?? "OK", value: true },
    ],
    cancelValue: false,
  });
  return value === true ? inputs.text : null;
}

/** Asks for a server address as two separate fields.
 *
 *  Previously this was one "host:port" box, which made the user do the parsing:
 *  the field was prefilled with the display string (including its "🔒 TLS"
 *  suffix), so submitting it unedited produced a NaN port and a confusing
 *  error. Two fields make the shape of the answer obvious and the port
 *  mandatory — which matters because a BENCO server terminates TLS itself and
 *  runs no plaintext listener, so the wrong port doesn't degrade, it hangs. */
export async function serverDialog(
  host: string,
  port: number,
): Promise<{ host: string; port: number } | null> {
  let values = { host, port: port ? String(port) : "" };
  let error = "";

  // Re-opens on invalid input rather than discarding what was typed.
  for (;;) {
    const { value, inputs } = await openCore({
      title: "Change server",
      message: "The address of the OSCAR server, and the port it listens on.",
      fields: [
        { name: "host", label: "Server", defaultValue: values.host, placeholder: "chat.example.com", flex: 3 },
        { name: "port", label: "Port", defaultValue: values.port, placeholder: "5191", flex: 1, inputMode: "numeric" },
      ],
      buttons: [
        { label: "Cancel", value: false },
        { label: "Save", value: true },
      ],
      cancelValue: false,
      error,
    });
    if (value !== true) return null;

    values = { host: inputs.host.trim(), port: inputs.port.trim() };

    // Tolerate a pasted "host:port" in the address field rather than rejecting
    // it — it's the obvious thing to paste, and the port box is right there.
    const pasted = /^(.*):(\d+)$/.exec(values.host);
    if (pasted && !values.port) {
      values = { host: pasted[1], port: pasted[2] };
    }

    if (!values.host) {
      error = "Enter the server address.";
      continue;
    }
    const n = Number(values.port);
    if (!values.port || !Number.isInteger(n) || n < 1 || n > 65535) {
      error = "Enter a port between 1 and 65535.";
      continue;
    }
    return { host: values.host, port: n };
  }
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
