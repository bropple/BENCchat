# BENCO Design Style Guide

Every value in this guide is pulled directly from the actual shipped code — the games, the printer GUI, and the receipt formatter — not reconstructed from memory. If a future piece of work needs a color, font, or spacing decision and it isn't here, the instinct should be "what would already be sitting next to this in Match Filed or the printer app," not "what looks nice."

---

## 1. Brand Voice (the design follows from this, not the other way around)

BENCO's visual identity exists to support one consistent tone: **deadpan, unbothered, quietly retro.** Nothing in the UI should look like it's trying hard. No gradients chasing modern flatness, no excessive animation, no exclamation. A loading screen says "Setting up the model," not "Get ready for an adventure!" The aesthetic is a late-80s/early-90s terminal that has been running, without complaint, for a very long time.

---

## 2. Color Palette

### Core (used everywhere — site, games, apps)

| Name | Hex | Usage |
|---|---|---|
| **Canonical Green** | `#78b946` | The brand color. R. Triy's body color. Primary accent/CTA color everywhere. |
| **Deep Green (edge/shadow)** | `#3f5c28` | Outlines, borders, pressed states, R. Triy's edge stroke. |
| **Phosphor Text** | `#cdeab0` | Primary readable text on dark backgrounds — a warm, slightly desaturated light green, not pure white. This is the "screen glow" color. |
| **Dim Green (secondary text)** | `#6f8a5c` / `#8aa878` | Labels, captions, timestamps, anything secondary to the phosphor-text hierarchy. |
| **Near-black backgrounds** | `#0c1408`, `#060a05`, `#0b0f0a`, `#1a2410` | Base page/window backgrounds. Never pure `#000` — always a green-tinted near-black. |
| **Panel background** | `#182010`, `#2a3620`, `#11170f` | One step up from the base background, for cards/panels/input fields sitting on top of it. |

### Accent / Alert

| Name | Hex | Usage |
|---|---|---|
| **Alert Red** | `#d84a3a` | Errors, the visor stripe detail, "stop/danger" cues. |
| **Amber** | `#e8b23d` / `#f4cf4a` | Secondary highlight — used for the C. Maximus ghost car, warning-tier states, gold/coin accents. |

### Character Roster (Match Filed `TYPES`, canon color-per-character)

| Character | Fill | Edge |
|---|---|---|
| R. Triy (triangle) | `#78b946` | `#3f5c28` |
| O. Val (oval) | `#c1443a` | `#7a281f` |
| H. Hex (hex) | `#d97a2b` | `#8a4d18` |
| P. Gon (pentagon) | `#3d7dbf` | `#254d75` |
| G. Lobe (circle) | `#2c4a7c` | `#16283f` |
| C. Ross (cross) | `#7a4fb5` | `#452766` |
| S. Tarr (star) | `#eecb2e` | `#a3861a` |

Every character fill color has a matching edge/outline color roughly 30-40% darker — maintain this fill/edge pairing convention for any new character.

**Rule:** a new character never gets a color already on this list. Check this table before assigning one.

---

## 3. Typography

Four fonts in rotation, each with a specific job — don't mix their roles:

| Font | Role |
|---|---|
| **VT323** | Display/heading font. Used for titles, big numbers, anything that should read as a CRT terminal's large text. Slightly irregular, monospace, unmistakably retro. |
| **Share Tech Mono** | Primary body/UI font. Clean, readable monospace for anything a user needs to actually read comfortably — instructions, stats, form labels. |
| **IBM Plex Mono** | Secondary body font, used where Share Tech Mono would be too "video-gamey" for the content (e.g. news article bodies in benco-local). |
| **Press Start 2P** | Sparingly, for genuine 8-bit/arcade moments (score displays, "GAME OVER" states) — the most stylized font in the set, so it's rationed rather than used broadly. |
| **Consolas** | Desktop app only (the printer GUI). Not a web font — used because it's a reliable system-monospace default on Windows, where that app actually runs. |

**Letter-spacing convention:** headings and labels consistently use `letter-spacing: 1px` (occasionally `0.5px` for smaller text, `2px` for hero titles). Never set body paragraph text with extra letter-spacing — it's a heading/label-only trait.

**Glow convention:** hero titles get a soft green text-shadow to sell the "phosphor" look:
```css
text-shadow: 0 0 8px rgba(120, 185, 70, 0.4);
```
Use this sparingly — one glowing title per screen, not every heading.

---

## 4. Layout & Structure

- **Never pure black backgrounds.** Always one of the near-black greens from the palette above.
- **Borders are thin and dim**, not decorative — typically a 1px border in a dark green (`#2a3a1e`-ish range) separating panels, not a bright accent border.
- **Border-radius stays small.** Real values in use: `2px`, `3px`, `4px` for buttons/inputs/panels. `20px` appears only once, for a fully-pill-shaped button — small radii are the default, full pills are the rare exception, not the norm.
- **Buttons are flat**, not gradient or glossy — solid fill, no shadow beyond an optional `box-shadow: 0 4px 0 rgba(0,0,0,0.25)` used for a slight "pressed key" 3D-button effect on interactive game buttons specifically (not on regular UI buttons).
- **Responsive canvas sizing** for games uses `min(92vw, height-derived-formula, hard-cap-px)` rather than fixed pixel dimensions — always scale to viewport, always keep a sane upper bound.

---

## 5. The Print Medium (receipts count as a BENCO surface too)

The physical/printed output has its own consistent conventions, distinct from screen UI but following the same voice:

- **40-column fixed width**, ASCII only. No Unicode, no emoji — smart quotes/em dashes/ellipses get auto-converted to plain ASCII rather than printing as `?`.
- **Dashes as the only divider**: a full-width line of `-` characters (`'-' * 40`) is the *only* section-break device. No boxes, no double-lines, no decorative rules.
- **Letter-spaced ALL CAPS for formal headers** — e.g. `M E M O R A N D U M` — reserved for genuinely formal documents (the R. Triy Memo format). Casual receipts don't get this treatment.
- **Centered ASCII art is a real, occasional device** (the C. Maximus asterisk mark) — always centered as one whole block (consistent left-padding computed from the block's own widest line), never per-line-centered, which distorts multi-line art.
- **Every printed piece ends on a closing line**, right before the final paper feed — default "the floor is clear.", customizable per job. R. Triy's casual voice specifically closes with "filed." — don't reuse that verb for other characters or contexts.

---

## 6. Logo / Wordmark

The plain-text ASCII banner (`benco-ascii.txt`) is the closest thing to a formal logo:
```
#####  #####  #   #  #####  #####
#   #  #      ##  #  #      #   #
#####  ####   # # #  #      #   #
#   #  #      #  ##  #      #   #
#####  #####  #   #  #####  #####

  B E N C O   H O L D I N G S

================================
```
Use as-is for CLI/terminal banners. Don't redraw it in a different block-letter style — this specific rendering is the canonical one.

---

## 7. Do / Don't

**Do:**
- Reuse an existing hex value from this doc before introducing a new one.
- Keep new UI elements flat, dark, green-tinted, and quiet.
- Let silence/restraint do the work — a blank line, a plain dash divider, an unglamorous loading message.

**Don't:**
- Introduce a bright white background or pure black anywhere.
- Add decorative animation, particle effects, or gradients "for polish" — nothing in the existing surface area does this, and it would read as off-brand immediately.
- Give a new character a color already claimed by another roster member.
- Use Press Start 2P for body text — it's a garnish font, not a workhorse.
