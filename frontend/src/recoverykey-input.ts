// A recovery key entered as one box per word, so nobody types hyphens by hand.
//
// The key is ten words. A single field works but makes people either type the
// separators themselves or trust that a pasted blob has the right shape; ten
// boxes make the structure visible and, more importantly, let a pasted key
// distribute itself across them — which is the common case, since the key was
// saved to a file and is pasted, not recalled.
//
// The component owns interaction only. It never validates a word or touches the
// backup; value() hands the assembled string to the Go layer, which is the one
// place that knows the wordlist and does the all-or-nothing decrypt.

export interface RecoveryKeyInput {
  /** The words joined with hyphens, positionally — empty boxes included, so a
   *  "word N is invalid" error from Go maps to box N. Lower-cased and trimmed. */
  value(): string;
  /** Wipe every box. Called once the key has done its work: a recovery key must
   *  not linger in a DOM node. */
  clear(): void;
  focus(): void;
  /** Mark one box (1-based) as the invalid one, e.g. from a "word 7" error, and
   *  put the cursor in it. Out-of-range positions are ignored. */
  markInvalid(position: number): void;
}

// A word is a run of letters; anything else (hyphen, space, comma, newline) is
// a separator. Splitting a paste on separators is what lets one paste of the
// whole key fan out across the boxes.
const SEPARATORS = /[^a-z]+/i;

export function mountRecoveryKeyInput(
  host: HTMLElement,
  count: number,
  onEnter?: () => void,
): RecoveryKeyInput {
  host.classList.add("rk-grid");
  host.innerHTML = "";

  const boxes: HTMLInputElement[] = [];
  for (let i = 0; i < count; i++) {
    const cell = document.createElement("div");
    cell.className = "rk-cell";
    const num = document.createElement("span");
    num.className = "rk-num";
    num.textContent = String(i + 1);
    const box = document.createElement("input");
    box.className = "rk-box";
    box.type = "text";
    box.autocomplete = "off";
    box.spellcheck = false;
    box.setAttribute("autocapitalize", "off");
    box.setAttribute("aria-label", `Recovery word ${i + 1}`);
    cell.append(num, box);
    host.append(cell);
    boxes.push(box);
  }

  const clearInvalid = (): void => {
    for (const b of boxes) b.classList.remove("rk-box--bad");
  };

  // Distribute an array of words across the boxes starting at `start`. This is
  // the paste path and the auto-advance path both, so a key pasted into box 1
  // fills all ten and a stray separator typed mid-word just advances by one.
  const fill = (words: string[], start: number): void => {
    let i = start;
    for (const w of words) {
      if (i >= boxes.length) break;
      boxes[i].value = w.toLowerCase();
      i++;
    }
    // Land the cursor on the first still-empty box, or the last one.
    const next = boxes.findIndex((b, idx) => idx >= start && b.value === "");
    (next === -1 ? boxes[boxes.length - 1] : boxes[next]).focus();
  };

  boxes.forEach((box, i) => {
    box.addEventListener("paste", (e) => {
      const text = e.clipboardData?.getData("text") ?? "";
      const words = text.split(SEPARATORS).filter(Boolean);
      if (words.length <= 1) return; // a single word: let the default paste land in this box
      e.preventDefault();
      clearInvalid();
      fill(words, i);
    });

    box.addEventListener("input", () => {
      clearInvalid();
      // A separator typed inside a box (a hand-typed hyphen or space) means the
      // user finished this word: keep the part before it here, carry any part
      // after it to the next box, and advance.
      if (SEPARATORS.test(box.value)) {
        const parts = box.value.split(SEPARATORS).filter(Boolean);
        box.value = (parts[0] ?? "").toLowerCase();
        if (parts.length > 1) {
          fill(parts.slice(1), i + 1);
        } else if (i + 1 < boxes.length) {
          boxes[i + 1].focus();
        }
      }
    });

    box.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        onEnter?.();
      } else if (e.key === "Backspace" && box.value === "" && i > 0) {
        // Backspacing out of an empty box steps back rather than doing nothing,
        // so a mistyped key can be walked back without reaching for the mouse.
        e.preventDefault();
        boxes[i - 1].focus();
      } else if (e.key === "ArrowLeft" && box.selectionStart === 0 && i > 0) {
        boxes[i - 1].focus();
      } else if (
        e.key === "ArrowRight" &&
        box.selectionStart === box.value.length &&
        i + 1 < boxes.length
      ) {
        boxes[i + 1].focus();
      }
    });
  });

  return {
    value: () => boxes.map((b) => b.value.trim().toLowerCase()).join("-"),
    clear: () => {
      clearInvalid();
      for (const b of boxes) b.value = "";
      boxes[0].focus();
    },
    focus: () => boxes[0].focus(),
    markInvalid: (position: number) => {
      const b = boxes[position - 1];
      if (!b) return;
      clearInvalid();
      b.classList.add("rk-box--bad");
      b.focus();
      b.select();
    },
  };
}

// wordPositionFromError pulls the 1-based position out of a "word N ..." error
// so the offending box can be highlighted. Returns 0 when the message names no
// position (a whole-key failure, where no single box is at fault).
export function wordPositionFromError(msg: string): number {
  const m = /\bword\s+(\d+)\b/i.exec(msg);
  return m ? Number(m[1]) : 0;
}
