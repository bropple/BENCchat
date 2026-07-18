// theme.ts — the appearance engine.
//
// A theme is a flat map of design tokens (token key -> CSS value). The keys are
// the CSS custom-property names used throughout the stylesheets, minus the
// leading "--", so applying a theme is just setting those variables on :root.
// The set of tokens and the built-in presets live here, in the frontend; the Go
// side only persists the user's choice.

import { Bridge } from "./bridge";

/** The kind of value a token holds, so the editor can show the right control. */
export type TokenType = "color" | "font" | "size";

/** One themeable token: its CSS variable, a human label, and how to edit it. */
export interface TokenSpec {
  /** CSS custom property name without the leading "--". */
  key: string;
  label: string;
  type: TokenType;
  group: "Colors" | "Text" | "Structure";
  /** One-line hint shown in the editor. */
  hint?: string;
}

/**
 * The token schema. This is the contract between the stylesheet variables and
 * the editor — every entry here becomes an editable control, and every value a
 * preset or custom theme sets must be a key in here.
 */
export const TOKENS: TokenSpec[] = [
  { key: "benco-green", label: "Accent", type: "color", group: "Colors", hint: "Primary brand / button color" },
  { key: "benco-green-deep", label: "Accent edge", type: "color", group: "Colors", hint: "Borders, pressed states" },
  { key: "benco-phosphor", label: "Text", type: "color", group: "Colors", hint: "Primary readable text" },
  { key: "benco-dim", label: "Secondary text", type: "color", group: "Colors" },
  { key: "benco-dim-2", label: "Tertiary text", type: "color", group: "Colors", hint: "Timestamps, captions" },
  { key: "benco-bg", label: "Background", type: "color", group: "Colors" },
  { key: "benco-bg-deep", label: "Deep background", type: "color", group: "Colors", hint: "Sidebar, recesses" },
  { key: "benco-panel", label: "Panel", type: "color", group: "Colors", hint: "Cards, inbound bubbles" },
  { key: "benco-panel-2", label: "Panel (input)", type: "color", group: "Colors", hint: "Input fields, outbound bubbles" },
  { key: "benco-border", label: "Border", type: "color", group: "Colors" },
  { key: "benco-red", label: "Alert", type: "color", group: "Colors", hint: "Errors" },
  { key: "benco-amber", label: "Away / warning", type: "color", group: "Colors" },

  { key: "font-display", label: "Display font", type: "font", group: "Text", hint: "Titles and headings" },
  { key: "font-ui", label: "UI font", type: "font", group: "Text", hint: "Labels, buttons, buddy list" },
  { key: "font-prose", label: "Message font", type: "font", group: "Text", hint: "Chat message text" },

  { key: "benco-radius", label: "Corner radius", type: "size", group: "Structure", hint: "e.g. 3px" },
];

export type ThemeTokens = Record<string, string>;

export interface Preset {
  id: string;
  name: string;
  tokens: ThemeTokens;
}

// The default BENCO tokens. These mirror the values in style.css so that the
// stylesheet still renders correctly with no theme applied (first paint), and
// the editor has a baseline to reset to.
const BENCO_TOKENS: ThemeTokens = {
  "benco-green": "#78b946",
  "benco-green-deep": "#3f5c28",
  "benco-phosphor": "#cdeab0",
  "benco-dim": "#8aa878",
  "benco-dim-2": "#6f8a5c",
  "benco-bg": "#0c1408",
  "benco-bg-deep": "#060a05",
  "benco-panel": "#182010",
  "benco-panel-2": "#11170f",
  "benco-border": "#2a3a1e",
  "benco-red": "#d84a3a",
  "benco-amber": "#e8b23d",
  // var(--cjk-fallback) is defined in style.css :root (not a themeable token);
  // it must stay in these defaults so applying a theme doesn't drop CJK coverage.
  "font-display": '"VT323", "Share Tech Mono", "IBM Plex Mono", var(--cjk-fallback), monospace',
  "font-ui": '"Share Tech Mono", "IBM Plex Mono", "Consolas", var(--cjk-fallback), monospace',
  "font-prose": '"IBM Plex Mono", "Share Tech Mono", var(--cjk-fallback), monospace',
  "benco-radius": "3px",
};

/**
 * Built-in presets. BENCO is first and is the default. The others exist so the
 * app doesn't presume everyone likes the house style — including a light theme,
 * which also proves the token set survives an inverted palette.
 */
export const PRESETS: Preset[] = [
  { id: "benco", name: "BENCO (default)", tokens: BENCO_TOKENS },
  {
    id: "amber",
    name: "Amber Terminal",
    tokens: {
      ...BENCO_TOKENS,
      "benco-green": "#e8b23d",
      "benco-green-deep": "#7a5c14",
      "benco-phosphor": "#f4d79a",
      "benco-dim": "#c69a52",
      "benco-dim-2": "#8a6d3a",
      "benco-bg": "#140f06",
      "benco-bg-deep": "#0a0703",
      "benco-panel": "#201808",
      "benco-panel-2": "#17110a",
      "benco-border": "#3a2e14",
      "benco-red": "#d84a3a",
      "benco-amber": "#78b946",
    },
  },
  {
    id: "midnight",
    name: "Midnight Blue",
    tokens: {
      ...BENCO_TOKENS,
      "benco-green": "#4f8fd8",
      "benco-green-deep": "#274d75",
      "benco-phosphor": "#cfe0f2",
      "benco-dim": "#8aa4c2",
      "benco-dim-2": "#5f7690",
      "benco-bg": "#080c14",
      "benco-bg-deep": "#04060a",
      "benco-panel": "#101725",
      "benco-panel-2": "#0b101a",
      "benco-border": "#1e2a3a",
      "benco-red": "#e0574a",
      "benco-amber": "#e8b23d",
    },
  },
  {
    id: "paperwhite",
    name: "Paperwhite (light)",
    tokens: {
      ...BENCO_TOKENS,
      "benco-green": "#3f7a2a",
      "benco-green-deep": "#2c5620",
      "benco-phosphor": "#1c2416",
      "benco-dim": "#4a5540",
      "benco-dim-2": "#6f7a64",
      "benco-bg": "#eef0e6",
      "benco-bg-deep": "#e2e5d6",
      "benco-panel": "#f6f7f0",
      "benco-panel-2": "#ffffff",
      "benco-border": "#c8ccba",
      "benco-red": "#b83526",
      "benco-amber": "#a5761a",
    },
  },
];

export function presetById(id: string): Preset | undefined {
  return PRESETS.find((p) => p.id === id);
}

/** The default token set, used as the base for custom themes and reset. */
export function defaultTokens(): ThemeTokens {
  return { ...BENCO_TOKENS };
}

/**
 * Resolves a saved theme into the full token map to apply. A preset with no
 * overrides yields that preset; a "custom" theme yields the stored tokens laid
 * over the BENCO base so a partial/older custom theme can't leave a token unset.
 */
export function resolveTokens(saved: {
  name?: string;
  tokens?: ThemeTokens;
}): ThemeTokens {
  const preset = saved.name ? presetById(saved.name) : undefined;
  const base = preset ? preset.tokens : BENCO_TOKENS;
  return { ...BENCO_TOKENS, ...base, ...(saved.tokens ?? {}) };
}

/**
 * Rejects CSS values that could break out of the property they're assigned to
 * or fetch a remote resource. A token like `url(http://evil/)` assigned to a
 * color that's later used in `background: var(--…)` would exfiltrate the user's
 * IP on load. Today theme values only ever come from the user's own local
 * config, so this is defense-in-depth — but it is the guard that keeps a future
 * "import/share a theme" feature from becoming an injection vector. Legitimate
 * color/font/size values never contain any of these.
 */
function safeCssValue(v: string): boolean {
  return !/[;{}<>]|url\(|expression\(|@import|\/\*|javascript:/i.test(v);
}

/**
 * Applies tokens by setting CSS variables on the document root. The phosphor
 * glow is derived from the accent color here rather than stored as its own
 * token, so it always matches whatever accent the user picked.
 */
export function applyTokens(tokens: ThemeTokens): void {
  const root = document.documentElement;
  for (const spec of TOKENS) {
    const val = tokens[spec.key];
    // Skip unsafe values rather than applying them; the token keeps its prior
    // (or stylesheet-default) value.
    if (val != null && safeCssValue(val)) root.style.setProperty(`--${spec.key}`, val);
  }
  const rgb = hexToRgb(tokens["benco-green"]);
  if (rgb) {
    root.style.setProperty("--benco-glow", `0 0 8px rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, 0.4)`);
  }
}

/** Loads the saved theme and applies it. Falls back to BENCO on any error. */
export async function loadAndApplyTheme(): Promise<void> {
  try {
    const prefs = await Bridge.getPreferences();
    applyTokens(resolveTokens(prefs.theme ?? {}));
  } catch {
    applyTokens(BENCO_TOKENS);
  }
}

/** Persists a theme choice. */
export async function saveTheme(
  name: string,
  tokens: ThemeTokens,
): Promise<string> {
  return Bridge.saveTheme(name, tokens);
}

/** Parses a #rrggbb (or #rgb) color into components; null if not a hex color. */
export function hexToRgb(hex: string): { r: number; g: number; b: number } | null {
  if (!hex) return null;
  let h = hex.trim().replace(/^#/, "");
  if (h.length === 3) h = h.split("").map((c) => c + c).join("");
  if (!/^[0-9a-fA-F]{6}$/.test(h)) return null;
  return {
    r: parseInt(h.slice(0, 2), 16),
    g: parseInt(h.slice(2, 4), 16),
    b: parseInt(h.slice(4, 6), 16),
  };
}
