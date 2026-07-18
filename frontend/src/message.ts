// message.ts — turns a raw AIM message body into safe display HTML.
//
// Two shapes arrive in Message.text:
//   • Plaintext — BENCchat sends bare UTF-8 with no wrapper.
//   • AIM HTML  — real AIM clients wrap formatted messages in <HTML><BODY>…;
//     open-oscar-server passes that through verbatim (it never strips it), and
//     the Go layer does no escaping either.
//
// So THIS module is the XSS boundary. The rule it never breaks: every run of
// user-supplied text is emitted as a DOM text node (escaped by construction),
// never as markup. For the HTML case we parse with DOMParser and rebuild an
// allowlisted subtree — unknown tags are unwrapped (children kept), unknown
// attributes dropped, and only vetted URLs survive. Emoticons are substituted
// structurally, into text nodes only, so they can never land inside a tag or a
// URL and can never smuggle markup.

/** Classic AIM smileys → Unicode. Longer codes first so ":-)" wins over ":-".
 *  Substituted only within text nodes, never inside links. */
const EMOTICONS: ReadonlyArray<readonly [string, string]> = [
  [":-)", "🙂"], [":)", "🙂"], ["=)", "🙂"],
  [":-(", "🙁"], [":(", "🙁"],
  [";-)", "😉"], [";)", "😉"],
  [":-D", "😄"], [":D", "😄"], ["=D", "😄"],
  [":'(", "😢"],
  [":-P", "😛"], [":P", "😛"], [":-p", "😛"], [":p", "😛"],
  [":-O", "😮"], [":O", "😮"], [":-o", "😮"], [":o", "😮"],
  ["B-)", "😎"], ["8-)", "😎"],
  ["O:-)", "😇"],
  [":-*", "😘"],
  [":-/", "😕"], [":-\\", "😕"],
  [":-|", "😐"],
  [":-X", "🤐"], [":-x", "🤐"],
  [">:(", "😠"],
  ["<3", "❤️"],
];

/** One regex matching any emoticon code, longest-first. */
const EMOTICON_RE = new RegExp(
  [...EMOTICONS]
    .sort((a, b) => b[0].length - a[0].length)
    .map(([code]) => code.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join("|"),
  "g",
);
const EMOTICON_MAP = new Map(EMOTICONS);

/** Tags we keep, with the attributes allowed on each. Everything else is
 *  unwrapped (its children are kept) so wrappers like <HTML>/<BODY> and unknown
 *  tags degrade to their text content rather than vanishing. */
const ALLOWED_TAGS: Record<string, readonly string[]> = {
  B: [], STRONG: [], I: [], EM: [], U: [], S: [], STRIKE: [], DEL: [],
  BR: [], P: [], DIV: [], SPAN: [], PRE: [], CODE: [], BLOCKQUOTE: [],
  BIG: [], SMALL: [], SUB: [], SUP: [], H1: [], H2: [], H3: [],
  FONT: ["color", "size", "face"],
  A: ["href"],
};

/** Tags dropped whole — children discarded too. Unknown tags merely unwrap
 *  (keep their text), but these carry script/markup we never want surfaced,
 *  even as visible text. DOMParser never executes them, but this keeps their
 *  contents out of the bubble entirely. */
const DROP_TAGS = new Set([
  "SCRIPT", "STYLE", "IFRAME", "OBJECT", "EMBED", "NOSCRIPT",
  "TEMPLATE", "LINK", "META", "TITLE", "HEAD", "SVG", "MATH",
]);

/** URL schemes a link may use. Anything else (javascript:, data:, …) is dropped. */
const SAFE_URL = /^(https?:|mailto:|ftp:|aim:)/i;
/** Colors we accept for <font color> — hex, rgb(), or a basic named set. */
const HEX_COLOR = /^#([0-9a-f]{3}|[0-9a-f]{6})$/i;
const RGB_COLOR = /^rgb\(\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}\s*\)$/i;
const NAMED_COLORS = new Set([
  "black", "white", "red", "green", "blue", "yellow", "orange", "purple",
  "pink", "gray", "grey", "cyan", "magenta", "brown", "navy", "teal",
  "maroon", "olive", "lime", "aqua", "silver", "gold",
]);
/** AIM font-size buckets (1–7) → px. */
const AIM_SIZE_PX: Record<string, string> = {
  "1": "10px", "2": "13px", "3": "15px", "4": "18px", "5": "24px",
  "6": "32px", "7": "44px",
};

/** Does this text look like AIM's HTML wire form? We only take the HTML path
 *  when the message is actually wrapped by an AIM client, so a plaintext
 *  message that merely happens to contain "a < b" is never mis-parsed. */
function looksLikeAimHtml(text: string): boolean {
  if (/<\s*(html|body)\b/i.test(text) || /<\/\s*(html|body)\s*>/i.test(text)) {
    return true;
  }
  // Not everything arrives wrapped. The server's own system messages (the
  // offline-message notice, for one) send a bare <a href> with no <html>
  // around it, and treating that as plain text shows the user raw markup.
  //
  // Widening this is safe because the heuristic only chooses a path — the
  // allowlist in sanitizeInto is the actual security boundary, and anything
  // outside it is dropped either way.
  return /<\s*\/?\s*(a|b|i|u|em|strong|font|br)\b[^>]*>/i.test(text);
}

/** Public entry point: raw message text → trusted HTML string for innerHTML. */
export function renderMessageBody(text: string): string {
  const root = document.createElement("div");

  if (looksLikeAimHtml(text)) {
    const doc = new DOMParser().parseFromString(text, "text/html");
    sanitizeInto(doc.body, root);
  } else {
    appendPlainText(root, text);
  }

  applyEmoticons(root);
  return root.innerHTML;
}

/** Copy the allowed subtree of `src` into `dst`, node by node. */
function sanitizeInto(src: Node, dst: HTMLElement): void {
  src.childNodes.forEach((node) => {
    if (node.nodeType === Node.TEXT_NODE) {
      dst.appendChild(document.createTextNode(node.textContent ?? ""));
      return;
    }
    if (node.nodeType !== Node.ELEMENT_NODE) return; // comments, PIs → skip

    const el = node as Element;
    if (DROP_TAGS.has(el.tagName)) return; // drop element and its subtree

    const allowedAttrs = ALLOWED_TAGS[el.tagName];
    if (!allowedAttrs) {
      // Unknown tag: drop the wrapper, keep the (sanitized) children.
      sanitizeInto(el, dst);
      return;
    }

    const clean = document.createElement(el.tagName.toLowerCase());
    for (const attr of allowedAttrs) applySafeAttr(el, clean, attr);
    sanitizeInto(el, clean);
    dst.appendChild(clean);
  });
}

/** Validate and transfer one attribute, translating AIM's <font> attrs to
 *  inline style so nothing attacker-supplied lands in an executable position. */
function applySafeAttr(from: Element, to: HTMLElement, attr: string): void {
  const raw = from.getAttribute(attr);
  if (raw == null) return;
  const val = raw.trim();

  switch (attr) {
    case "href": {
      if (SAFE_URL.test(val)) {
        to.setAttribute("href", val);
        to.setAttribute("rel", "noopener noreferrer");
        to.setAttribute("data-ext", "1"); // roster.ts opens these externally
      }
      return;
    }
    case "color": {
      const c = val.toLowerCase();
      if (HEX_COLOR.test(val) || RGB_COLOR.test(val) || NAMED_COLORS.has(c)) {
        to.style.color = val;
      }
      return;
    }
    case "size": {
      const px = AIM_SIZE_PX[val];
      if (px) to.style.fontSize = px;
      return;
    }
    case "face": {
      // Font-family is low-risk but still user text — keep it to a safe charset.
      const face = val.replace(/[^a-z0-9 ,"'-]/gi, "").slice(0, 120);
      if (face) to.style.fontFamily = face;
      return;
    }
  }
}

/** Plaintext path: text nodes with newlines becoming <br>. No auto-linkify —
 *  plaintext URLs are left as text (only AIM-supplied <a> markup is clickable). */
function appendPlainText(dst: HTMLElement, text: string): void {
  const lines = text.split("\n");
  lines.forEach((line, i) => {
    if (i > 0) dst.appendChild(document.createElement("br"));
    if (line) dst.appendChild(document.createTextNode(line));
  });
}

/** Walk every text node (except inside links) and replace emoticon codes with
 *  <span class="emoticon"> nodes, splitting the text node structurally so the
 *  surrounding user text stays a plain, escaped text node. */
function applyEmoticons(root: HTMLElement): void {
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
    acceptNode(n) {
      // Skip text inside <a>: never rewrite a URL's visible text.
      for (let p = n.parentElement; p && p !== root; p = p.parentElement) {
        if (p.tagName === "A") return NodeFilter.FILTER_REJECT;
      }
      return EMOTICON_RE.test(n.textContent ?? "")
        ? NodeFilter.FILTER_ACCEPT
        : NodeFilter.FILTER_SKIP;
    },
  });

  const targets: Text[] = [];
  for (let n = walker.nextNode(); n; n = walker.nextNode()) targets.push(n as Text);

  for (const textNode of targets) {
    const src = textNode.textContent ?? "";
    const frag = document.createDocumentFragment();
    let last = 0;
    EMOTICON_RE.lastIndex = 0;
    for (let m = EMOTICON_RE.exec(src); m; m = EMOTICON_RE.exec(src)) {
      if (m.index > last) frag.appendChild(document.createTextNode(src.slice(last, m.index)));
      const span = document.createElement("span");
      span.className = "emoticon";
      span.title = m[0];
      span.textContent = EMOTICON_MAP.get(m[0]) ?? m[0];
      frag.appendChild(span);
      last = m.index + m[0].length;
    }
    if (last < src.length) frag.appendChild(document.createTextNode(src.slice(last)));
    textNode.replaceWith(frag);
  }
}
