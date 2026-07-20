// settings.ts — the settings overlay: theme editor + sound toggle.
//
// The editor previews changes live by applying tokens to :root as the user
// edits, so the whole app (including this panel, which is themed too) restyles
// in real time. Closing without saving reverts to the persisted theme.

import { Bridge } from "./bridge";
import {
  TOKENS,
  PRESETS,
  applyTokens,
  defaultTokens,
  loadAndApplyTheme,
  presetById,
  resolveTokens,
  saveTheme,
  type ThemeTokens,
  type TokenSpec,
} from "./theme";
import {
  SOUND_EVENTS,
  SOUND_PACKS,
  DEFAULT_PACK,
  CUSTOM_PACK,
  setSoundPack,
  previewSound,
  loadCustomSounds,
  hasCustomSound,
  isSoundMuted,
  setSoundMuted,
  type SoundKey,
} from "./sound";
import { alertDialog, confirmDialog, promptDialog } from "./dialog";
import { offerRecoveryKeyRotation } from "./identity";

/** Minimal HTML escape for values interpolated into this panel's markup.
 *  Device keys are base64 and fingerprints are digits, but neither is worth
 *  trusting into innerHTML unescaped. */
function escapeHTML(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export interface SettingsHandle {
  destroy(): void;
}

export function openSettings(onSoundChange: (on: boolean) => void): SettingsHandle {
  const overlay = document.createElement("div");
  overlay.className = "settings-overlay";
  document.body.appendChild(overlay);

  // Working state: the theme being edited. Starts from whatever is persisted.
  let name = "benco";
  let tokens: ThemeTokens = defaultTokens();
  let saved = false;

  const escHandler = (e: KeyboardEvent) => {
    if (e.key === "Escape") close();
  };
  document.addEventListener("keydown", escHandler);

  function close(): void {
    document.removeEventListener("keydown", escHandler);
    // Discard an unsaved live-preview by reapplying what's on disk.
    if (!saved) void loadAndApplyTheme();
    overlay.remove();
    handle.destroy = () => {};
  }

  const groups: TokenSpec["group"][] = ["Colors", "Text", "Structure"];

  function render(p: {
    soundEnabled: boolean;
    soundPack: string;
    historyEnabled: boolean;
    historyRetentionDays: number;
    e2eeEnabled: boolean;
    profile: string;
    customFrame: boolean;
  }): void {
    overlay.innerHTML = `
      <div class="settings" role="dialog" aria-label="Settings">
        <header class="settings__head">
          <h2 class="benco-title settings__title">Settings</h2>
          <button class="benco-button benco-button--ghost settings__close" id="setClose">Done</button>
        </header>
        <hr class="benco-rule" />

        <div class="settings__main">
          <nav class="settings__nav" id="settingsNav">
            <button class="settings__tab is-active" data-tab="appearance">Appearance</button>
            <button class="settings__tab" data-tab="sound">Sound</button>
            <button class="settings__tab" data-tab="privacy">Privacy &amp; Security</button>
            <button class="settings__tab" data-tab="account">Account</button>
            <button class="settings__tab" data-tab="profile">Profile</button>
          </nav>

          <div class="settings__body">
            <div class="settings__panel is-active" data-panel="appearance">
              <section class="settings__section">
                <div class="benco-label">Theme</div>
                <div class="settings__presets" id="presets">
                  ${PRESETS.map(
                    (p) =>
                      `<button class="benco-button benco-button--ghost settings__preset" data-preset="${p.id}">${p.name}</button>`,
                  ).join("")}
                </div>

                ${groups
                  .map(
                    (g) => `
                  <div class="settings__group">
                    <div class="benco-caption settings__group-label">${g}</div>
                    ${TOKENS.filter((t) => t.group === g).map(tokenRow).join("")}
                  </div>`,
                  )
                  .join("")}
              </section>

              <section class="settings__section">
                <div class="benco-label">Window</div>
                <label class="settings__toggle">
                  <input type="checkbox" id="frameToggle" ${p.customFrame ? "checked" : ""} />
                  <span>Use BENCchat's own titlebar (custom window frame)</span>
                </label>
                <p class="benco-caption settings__hint">Replaces your desktop's window bar with a themed one. Off by default — your desktop normally handles this. <strong>Takes effect after you restart BENCchat.</strong></p>
              </section>
            </div>

            <div class="settings__panel" data-panel="sound">
              <section class="settings__section">
                <label class="settings__toggle">
                  <input type="checkbox" id="soundToggle" ${p.soundEnabled ? "checked" : ""} />
                  <span>Play sounds for sign-ons and incoming messages</span>
                </label>
                <p class="benco-caption settings__hint">The master switch. Individual events can be silenced below without turning everything off.</p>

                <div class="benco-caption settings__group-label">Sound pack</div>
                <div class="settings__presets" id="soundPacks">
                  ${Object.entries(SOUND_PACKS)
                    .map(
                      ([id, pk]) =>
                        `<button class="benco-button benco-button--ghost settings__preset settings__soundpack" data-pack="${id}">${pk.label}</button>`,
                    )
                    .join("")}
                  <button class="benco-button benco-button--ghost settings__preset settings__soundpack" data-pack="${CUSTOM_PACK}">Custom (import)</button>
                </div>
                <p class="benco-caption settings__hint">Original BENCchat sounds — click any event to hear it in the selected pack, or use the speaker to silence just that event.</p>
                <div class="settings__sounds" id="soundGrid">
                  ${SOUND_EVENTS.map(
                    (e) =>
                      `<div class="settings__sound-cell">
                         <button class="benco-button benco-button--ghost settings__sound" data-sound="${e.key}" title="Preview">
                           <span class="settings__sound-play">▶</span>
                           <span class="settings__sound-label">${e.label}${e.wired ? "" : ' <span class="settings__sound-soon">·future</span>'}</span>
                         </button>
                         ${
                           e.wired
                             ? `<button class="benco-button benco-button--ghost settings__sound-mute" data-mute="${e.key}" aria-pressed="false" title="Mute this event"></button>`
                             : ""
                         }
                       </div>`,
                  ).join("")}
                </div>

                <div class="benco-caption settings__group-label">Import your own</div>
                <p class="benco-caption settings__hint">Load an audio file (.wav / .mp3 / .ogg) for any event to build your <strong>Custom</strong> pack, then pick “Custom (import)” above. Events with no file fall back to the default pack.</p>
                <div class="settings__imports" id="soundImports">
                  ${SOUND_EVENTS.map(
                    (e) =>
                      `<div class="settings__import" data-key="${e.key}">
                         <span class="settings__import-label">${e.label}</span>
                         <span class="benco-caption settings__import-status" data-status="${e.key}"></span>
                         <button class="benco-button benco-button--ghost settings__import-btn" data-import="${e.key}">Import…</button>
                         <button class="benco-button benco-button--ghost settings__import-clear" data-clear="${e.key}" title="Remove" hidden>✕</button>
                       </div>`,
                  ).join("")}
                </div>
                <input type="file" id="soundFileInput" accept="audio/*" hidden />
              </section>
            </div>

            <div class="settings__panel" data-panel="privacy">
              <section class="settings__section">
                <div class="benco-label">Chat History</div>
                <label class="settings__toggle">
                  <input type="checkbox" id="historyToggle" ${p.historyEnabled ? "checked" : ""} />
                  <span>Save chat history on this computer</span>
                </label>
                <p class="benco-caption settings__hint">Stored locally and per-account — never sent to the server.</p>
                <div class="settings__history-row">
                  <label class="benco-caption" for="historyRetention">Auto-delete messages older than</label>
                  <select class="benco-input settings__select" id="historyRetention">
                    <option value="0">Never</option>
                    <option value="7">7 days</option>
                    <option value="30">30 days</option>
                    <option value="90">90 days</option>
                    <option value="365">1 year</option>
                  </select>
                </div>
                <div class="settings__history-row">
                  <button class="benco-button benco-button--ghost" id="historyClear">Clear all history</button>
                  <span class="benco-caption settings__history-msg" id="historyMsg"></span>
                </div>
              </section>

              <section class="settings__section">
                <div class="benco-label">Encryption</div>
                <p class="benco-caption settings__hint"><strong>Always on, and not optional.</strong> The connection is TLS — sign-on <strong>fails</strong> rather than falling back to cleartext, which is what stops an attacker steering you onto a plaintext port. Messages between BENCchat users are additionally encrypted end-to-end (look for the 🔒); clients that don't support it are marked <strong>⚠ not encrypted</strong> rather than quietly downgraded. TLS covers what end-to-end encryption can't — your login, buddy list, presence, profiles and who you talk to — though the server itself still sees that metadata. Your keys stay in this device's keychain. Group chats are <em>not</em> covered by end-to-end encryption.</p>

                <div class="benco-caption settings__group-label">Your devices</div>
                <p class="benco-caption settings__hint">Each machine you sign in on has its own encryption key. Messages sent to you are encrypted to every device listed here, so they're readable everywhere. This list is signed by your account's identity, which is why both adding and removing a machine cost the recovery key — nothing else can sign it, and that is what stops the server adding a device of its own. An account holds at most five; at the limit BENCchat refuses to publish a sixth rather than quietly dropping one, so retire a machine you no longer use first.</p>
                <div class="settings__devices" id="deviceList"></div>

                <div class="benco-caption settings__group-label">Recovery key</div>
                <!-- Proposal §13: passive, and passive is the whole design. There is no
                     timer behind this, no badge, no reminder and no prompt anywhere else
                     in the app — it is seen only by someone who came looking, which is
                     exactly the person it helps. An alert that fires when nothing is
                     wrong is one people learn to dismiss, and this project has already
                     paid for that lesson once with safety-number churn. -->
                <div class="settings__recovery" id="recoveryLine"></div>
                <p class="benco-caption settings__hint">Checking actually decrypts your account's identity with the key you type, so the answer is real either way — there's no "yes, I still have it" to tick. Losing this key is a slow failure: your devices keep working, but you can't link a new one or remove an old one, and you'd normally find out the day you replace a laptop.</p>
              </section>
            </div>

            <div class="settings__panel" data-panel="account">
              <section class="settings__section">
                <div class="benco-label">Account</div>
                <p class="benco-caption settings__hint">Change your password or email. Requires being signed on. These travel over the TLS connection rather than in the clear, but they go to the server, which reads them — end-to-end encryption covers messages, not account changes.</p>
                <div class="settings__acct">
                  <input class="benco-input" id="acctOldPw" type="password" placeholder="Current password" autocomplete="current-password" />
                  <input class="benco-input" id="acctNewPw" type="password" placeholder="New password" autocomplete="new-password" />
                  <button class="benco-button benco-button--ghost" id="acctPwSave">Change Password</button>
                </div>
                <div class="settings__acct">
                  <input class="benco-input" id="acctEmail" type="email" placeholder="New email address" autocomplete="email" />
                  <button class="benco-button benco-button--ghost" id="acctEmailSave">Change Email</button>
                </div>
                <span class="benco-caption settings__acct-msg" id="acctMsg"></span>
              </section>
            </div>

            <div class="settings__panel" data-panel="profile">
              <section class="settings__section">
                <div class="benco-label">Your Profile</div>
                <p class="benco-caption settings__hint">Shown to buddies who view your info. Sent when you click Set.</p>
                <textarea class="benco-input settings__profile" id="profileText" rows="4"
                          placeholder="Tell people about yourself…"></textarea>
                <div class="settings__profile-row">
                  <button class="benco-button benco-button--ghost" id="profileSave">Set Profile</button>
                  <span class="benco-caption settings__profile-msg" id="profileMsg"></span>
                </div>
              </section>
            </div>
          </div>
        </div>

        <div id="settingsFootWrap">
          <hr class="benco-rule" />
          <footer class="settings__foot">
            <button class="benco-button benco-button--ghost" id="setReset">Reset to preset</button>
            <div class="benco-error settings__msg" id="setMsg"></div>
            <button class="benco-button" id="setSave">Save</button>
          </footer>
        </div>
      </div>`;

    wire(p);
    reflectControls();
  }

  function tokenRow(spec: TokenSpec): string {
    const id = `tok-${spec.key}`;
    const hint = spec.hint ? `<span class="benco-caption settings__hint">${spec.hint}</span>` : "";
    if (spec.type === "color") {
      return `
        <div class="settings__row">
          <label class="settings__row-label" for="${id}">${spec.label}${hint}</label>
          <div class="settings__color">
            <input type="color" id="${id}" data-key="${spec.key}" class="settings__swatch" />
            <input type="text" id="${id}-hex" data-key="${spec.key}" class="benco-input settings__hex" spellcheck="false" />
          </div>
        </div>`;
    }
    // font and size are free-text stacks/values.
    return `
      <div class="settings__row">
        <label class="settings__row-label" for="${id}">${spec.label}${hint}</label>
        <input type="text" id="${id}" data-key="${spec.key}" class="benco-input settings__text" spellcheck="false" />
      </div>`;
  }

  // Pushes the working token values into the form controls.
  function reflectControls(): void {
    for (const spec of TOKENS) {
      const val = tokens[spec.key] ?? "";
      if (spec.type === "color") {
        const sw = overlay.querySelector<HTMLInputElement>(`#tok-${spec.key}`);
        const hex = overlay.querySelector<HTMLInputElement>(`#tok-${spec.key}-hex`);
        // The native color input only accepts #rrggbb; guard so a font-ish value
        // in a mis-set token can't throw.
        if (sw && /^#[0-9a-fA-F]{6}$/.test(val)) sw.value = val;
        if (hex) hex.value = val;
      } else {
        const inp = overlay.querySelector<HTMLInputElement>(`#tok-${spec.key}`);
        if (inp) inp.value = val;
      }
    }
    // Mark the active theme preset (or none, when custom). Scoped to #presets so
    // it never touches the sound-pack buttons that share the class.
    for (const btn of overlay.querySelectorAll<HTMLButtonElement>("#presets .settings__preset")) {
      btn.classList.toggle("is-active", btn.dataset.preset === name);
    }
  }

  // Applies a single token edit: update state, go custom, live-preview.
  function edit(key: string, value: string): void {
    tokens = { ...tokens, [key]: value };
    saved = false;
    if (name !== "custom") {
      // Diverging from a preset makes this a custom theme.
      const preset = presetById(name);
      if (!preset || preset.tokens[key] !== value) {
        name = "custom";
        for (const btn of overlay.querySelectorAll<HTMLButtonElement>(".settings__preset")) {
          btn.classList.remove("is-active");
        }
      }
    }
    applyTokens(tokens);
  }

  function selectPreset(id: string): void {
    const preset = presetById(id);
    if (!preset) return;
    name = id;
    tokens = { ...preset.tokens };
    saved = false;
    applyTokens(tokens);
    reflectControls();
  }

  function wire(p: {
    soundEnabled: boolean;
    soundPack: string;
    historyEnabled: boolean;
    historyRetentionDays: number;
    e2eeEnabled: boolean;
    profile: string;
    customFrame: boolean;
  }): void {
    overlay.querySelector<HTMLButtonElement>("#setClose")!.addEventListener("click", close);
    overlay.addEventListener("click", (e) => {
      // Click on the dimmed backdrop (not the panel) closes.
      if (e.target === overlay) close();
    });

    // Category tabs: show one panel at a time. The Reset/Save footer is a theme
    // control, so it only appears on the Appearance tab.
    const body = overlay.querySelector<HTMLDivElement>(".settings__body")!;
    const footWrap = overlay.querySelector<HTMLDivElement>("#settingsFootWrap")!;
    const showTab = (tab: string): void => {
      for (const b of overlay.querySelectorAll<HTMLButtonElement>(".settings__tab")) {
        b.classList.toggle("is-active", b.dataset.tab === tab);
      }
      for (const pnl of overlay.querySelectorAll<HTMLElement>(".settings__panel")) {
        pnl.classList.toggle("is-active", pnl.dataset.panel === tab);
      }
      footWrap.hidden = tab !== "appearance";
      body.scrollTop = 0;
    };
    for (const b of overlay.querySelectorAll<HTMLButtonElement>(".settings__tab")) {
      b.addEventListener("click", () => showTab(b.dataset.tab!));
    }

    // Theme presets only (exclude the sound-pack buttons that share the class).
    for (const btn of overlay.querySelectorAll<HTMLButtonElement>("#presets .settings__preset")) {
      btn.addEventListener("click", () => selectPreset(btn.dataset.preset!));
    }

    for (const inp of overlay.querySelectorAll<HTMLInputElement>("[data-key]")) {
      inp.addEventListener("input", () => edit(inp.dataset.key!, inp.value));
    }

    overlay.querySelector<HTMLButtonElement>("#setReset")!.addEventListener("click", () => {
      // Reset reverts to the current preset, or to BENCO if we're on a custom theme.
      selectPreset(name === "custom" ? "benco" : name);
    });

    const msg = overlay.querySelector<HTMLDivElement>("#setMsg")!;
    overlay.querySelector<HTMLButtonElement>("#setSave")!.addEventListener("click", async () => {
      const err = await saveTheme(name, tokens);
      if (err) {
        msg.textContent = err;
        return;
      }
      saved = true;
      msg.textContent = "";
      msg.classList.add("is-ok");
      msg.textContent = "Saved.";
      window.setTimeout(() => (msg.textContent = ""), 1500);
    });

    const sound = overlay.querySelector<HTMLInputElement>("#soundToggle")!;
    sound.addEventListener("change", async () => {
      await Bridge.setSoundEnabled(sound.checked);
      onSoundChange(sound.checked);
    });

    // Custom window frame — persisted, applied on next launch.
    const frameToggle = overlay.querySelector<HTMLInputElement>("#frameToggle")!;
    frameToggle.addEventListener("change", async () => {
      await Bridge.setCustomFrame(frameToggle.checked);
      await alertDialog("Restart BENCchat for the window-frame change to take effect.", {
        title: "Window frame",
      });
    });

    // Sound pack selection + per-event previews. Selecting a pack applies it
    // immediately (so future notifications use it) and persists the choice.
    let activePack = p.soundPack === CUSTOM_PACK || SOUND_PACKS[p.soundPack] ? p.soundPack : DEFAULT_PACK;
    const reflectPack = (): void => {
      for (const btn of overlay.querySelectorAll<HTMLButtonElement>(".settings__soundpack")) {
        btn.classList.toggle("is-active", btn.dataset.pack === activePack);
      }
    };
    reflectPack();
    for (const btn of overlay.querySelectorAll<HTMLButtonElement>(".settings__soundpack")) {
      btn.addEventListener("click", () => {
        activePack = btn.dataset.pack!;
        setSoundPack(activePack);
        void Bridge.setSoundPack(activePack);
        reflectPack();
        // Give immediate feedback in the newly-chosen pack.
        previewSound("imrcv", activePack);
      });
    }
    for (const btn of overlay.querySelectorAll<HTMLButtonElement>(".settings__sound")) {
      btn.addEventListener("click", () => previewSound(btn.dataset.sound as SoundKey, activePack));
    }

    // Device list. Rendered on open and after any removal.
    const deviceListEl = overlay.querySelector<HTMLDivElement>("#deviceList")!;

    const renderDevices = async (): Promise<void> => {
      let devices: Awaited<ReturnType<typeof Bridge.listDevices>> = [];
      try {
        devices = (await Bridge.listDevices()) ?? [];
      } catch {
        devices = [];
      }
      if (!devices.length) {
        deviceListEl.innerHTML = `<p class="benco-caption">No encryption keys set up yet.</p>`;
        return;
      }
      deviceListEl.innerHTML = devices
        .map(
          (d) => `
          <div class="settings__device">
            <div class="settings__device-id">
              <span class="settings__device-name">${d.thisDevice ? "This device" : "Linked device"}</span>
              <span class="benco-caption settings__device-fp">${escapeHTML(d.fingerprint)}</span>
            </div>
            ${
              d.thisDevice
                ? `<span class="benco-caption settings__device-here">in use</span>`
                : `<button class="benco-button benco-button--ghost settings__device-remove" data-device="${escapeHTML(d.key)}">Remove</button>`
            }
          </div>`,
        )
        .join("");

      for (const btn of deviceListEl.querySelectorAll<HTMLButtonElement>(".settings__device-remove")) {
        btn.addEventListener("click", async () => {
          // Removal is not a request to the server any more — it publishes a
          // new, signed device list that simply doesn't name this machine.
          // Signing needs the account's identity, and the only way to reach
          // that is the recovery key, so ask for it here and say why: the cost
          // is what makes the removal something the server cannot undo.
          const key = await promptDialog(
            "Removing this device publishes a new signed list of devices for your account " +
              "without it. That's what makes the removal stick — the server can't put it " +
              "back — and it's why it needs your recovery key.\n\n" +
              "The device will no longer be able to read messages sent to you. Nobody you " +
              "talk to sees anything change: safety numbers follow your account's identity, " +
              "not the machines under it.",
            "",
            {
              title: "Remove device",
              okLabel: "Remove",
              placeholder: "Recovery key",
            },
          );
          if (key === null) return;
          if (!key.trim()) {
            void alertDialog("Enter your recovery key to remove a device.", {
              title: "Could not remove device",
            });
            return;
          }
          const err = await Bridge.removeDevice(btn.dataset.device!, key.trim());
          if (err) {
            // Straight through, prefix aside: the useful failures here name the
            // position of a mistyped word rather than saying "wrong key".
            void alertDialog(err.replace(/^e2ee:\s*/, ""), {
              title: "Could not remove device",
            });
            return;
          }
          void renderDevices();
        });
      }
    };
    void renderDevices();

    // The recovery key line (proposal §13). Rendered when the panel opens and
    // after a check; nothing else triggers it, and nothing triggers it on a
    // timer.
    const recoveryEl = overlay.querySelector<HTMLDivElement>("#recoveryLine")!;

    /** "19 July 2026", or "" for a zero timestamp. Long-form on purpose: this
     *  line is read once in a blue moon, so an unambiguous date beats a compact
     *  one, and "3 months ago" would hide exactly the detail being asked for. */
    const onDate = (unix: number): string =>
      unix
        ? new Date(unix * 1000).toLocaleDateString(undefined, {
            day: "numeric",
            month: "long",
            year: "numeric",
          })
        : "";

    const renderRecovery = async (): Promise<void> => {
      let st;
      try {
        st = await Bridge.getRecoveryKeyStatus();
      } catch (e) {
        st = { available: false, created: 0, lastVerified: 0, error: String(e) };
      }
      if (!st.available) {
        // Deliberately terse, and deliberately not alarming: no identity yet, no
        // key directory, or a round trip that failed are all "nothing to report
        // here", not "something is wrong with your recovery key".
        recoveryEl.innerHTML = `<p class="benco-caption">${escapeHTML(
          st.error || "No recovery key on this account yet.",
        )}</p>`;
        return;
      }
      const created = onDate(st.created);
      const verified = onDate(st.lastVerified);
      // "Created date unknown" rather than a guess: this file is per machine, so
      // a device that was linked rather than set up genuinely never saw the key
      // being made, and inventing a date would be the one dishonest thing on a
      // line whose only job is to say something true.
      const createdText = created ? `created ${created}` : "created date unknown on this computer";
      const verifiedText = verified ? `last checked ${verified}` : "never checked";
      recoveryEl.innerHTML = `
        <div class="settings__recovery-row">
          <span class="settings__recovery-text">${escapeHTML(createdText)}, ${escapeHTML(verifiedText)}.</span>
          <button class="benco-button benco-button--ghost" id="recoveryVerify">Verify now</button>
        </div>`;

      overlay.querySelector<HTMLButtonElement>("#recoveryVerify")!.addEventListener(
        "click",
        async () => {
          const key = await promptDialog(
            "Type your recovery key and BENCchat will try to decrypt your account's " +
              "identity with it. That's the only check that proves anything — it either " +
              "opens or it doesn't.\n\n" +
              "Nothing about your account changes either way.",
            "",
            { title: "Check your recovery key", okLabel: "Check", placeholder: "Recovery key" },
          );
          if (key === null || !key.trim()) return;
          const err = await Bridge.verifyRecoveryKey(key.trim());
          if (err) {
            await alertDialog(err.replace(/^e2ee:\s*/, ""), {
              title: "That key didn't open your identity",
            });
            void renderRecovery();
            return;
          }
          await alertDialog(
            "That key opened your account's identity. It's the right one, and it still works.",
            { title: "Recovery key checked" },
          );
          // §10: the identity key was in memory during that check and is not any
          // more, so this is one of the two moments a re-key is possible — and
          // the offer has to be made now or not at all. It asks for the key
          // again rather than holding the identity across this round trip.
          await offerRecoveryKeyRotation(key.trim());
          void renderRecovery();
        },
      );
    };
    void renderRecovery();

    // Per-event mute. Independent of the master switch: these persist so a user
    // who only wants, say, the sign-on chime silenced keeps the rest.
    // Inline SVG rather than emoji: it inherits the theme's currentColor, where
    // a 🔇 glyph would drop a fixed-palette bitmap into the phosphor UI.
    const speaker = (mutedIcon: boolean): string =>
      `<svg viewBox="0 0 16 16" width="13" height="13" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linecap="round">
         <path d="M3 6.2h2.4L8.6 3.4v9.2L5.4 9.8H3z" stroke-linejoin="round"/>
         ${
           mutedIcon
             ? `<line x1="11" y1="5.8" x2="14.4" y2="10.2"/><line x1="14.4" y1="5.8" x2="11" y2="10.2"/>`
             : `<path d="M11 5.6a3.2 3.2 0 0 1 0 4.8"/><path d="M12.8 3.9a5.6 5.6 0 0 1 0 8.2"/>`
         }
       </svg>`;
    const reflectMute = (btn: HTMLButtonElement): void => {
      const on = isSoundMuted(btn.dataset.mute as SoundKey);
      btn.setAttribute("aria-pressed", String(on));
      btn.classList.toggle("is-muted", on);
      btn.innerHTML = speaker(on);
      btn.title = on ? "Muted — click to unmute" : "Mute this event";
    };
    for (const btn of overlay.querySelectorAll<HTMLButtonElement>(".settings__sound-mute")) {
      reflectMute(btn);
      btn.addEventListener("click", () => {
        const key = btn.dataset.mute as SoundKey;
        const on = !isSoundMuted(key);
        setSoundMuted(key, on);
        void Bridge.setSoundMuted(key, on);
        reflectMute(btn);
      });
    }

    // Custom sound import. One hidden file input, reused per event. Importing
    // saves the file to the backend, reloads the decoded set, and switches to the
    // Custom pack so the change is immediately audible.
    const fileInput = overlay.querySelector<HTMLInputElement>("#soundFileInput")!;
    let importKey: string | null = null;
    const refreshImportStatuses = (): void => {
      for (const e of SOUND_EVENTS) {
        const set = hasCustomSound(e.key);
        overlay.querySelector(`[data-status="${e.key}"]`)!.textContent = set ? "✓ custom" : "";
        (overlay.querySelector(`[data-clear="${e.key}"]`) as HTMLElement).hidden = !set;
      }
    };
    const reloadCustom = async (): Promise<void> => {
      try {
        await loadCustomSounds(await Bridge.getCustomSounds());
      } catch {
        /* ignore */
      }
      refreshImportStatuses();
    };
    for (const btn of overlay.querySelectorAll<HTMLButtonElement>(".settings__import-btn")) {
      btn.addEventListener("click", () => {
        importKey = btn.dataset.import!;
        fileInput.click();
      });
    }
    fileInput.addEventListener("change", async () => {
      const file = fileInput.files?.[0];
      const key = importKey;
      fileInput.value = "";
      if (!file || !key) return;
      const dataUrl = await new Promise<string>((res, rej) => {
        const r = new FileReader();
        r.onload = () => res(String(r.result));
        r.onerror = () => rej(r.error);
        r.readAsDataURL(file);
      });
      const err = await Bridge.setCustomSound(key, dataUrl);
      if (err) {
        await alertDialog(`Couldn't import sound: ${err}`, { title: "Import failed" });
        return;
      }
      await reloadCustom();
      // Switch to Custom and audition the freshly-imported event.
      activePack = CUSTOM_PACK;
      setSoundPack(CUSTOM_PACK);
      void Bridge.setSoundPack(CUSTOM_PACK);
      reflectPack();
      previewSound(key as SoundKey, CUSTOM_PACK);
    });
    for (const btn of overlay.querySelectorAll<HTMLButtonElement>(".settings__import-clear")) {
      btn.addEventListener("click", async () => {
        await Bridge.clearCustomSound(btn.dataset.clear!);
        await reloadCustom();
      });
    }
    void reloadCustom();

    // Chat history controls.
    const historyToggle = overlay.querySelector<HTMLInputElement>("#historyToggle")!;
    historyToggle.addEventListener("change", () => {
      void Bridge.setHistoryEnabled(historyToggle.checked);
    });
    const retention = overlay.querySelector<HTMLSelectElement>("#historyRetention")!;
    retention.value = String(p.historyRetentionDays);
    retention.addEventListener("change", () => {
      void Bridge.setHistoryRetention(Number(retention.value));
    });
    const historyMsg = overlay.querySelector<HTMLSpanElement>("#historyMsg")!;
    overlay.querySelector<HTMLButtonElement>("#historyClear")!.addEventListener("click", async () => {
      if (
        !(await confirmDialog("Delete all saved chat history on this computer? This can't be undone.", {
          title: "Clear history",
          okLabel: "Delete",
          danger: true,
        }))
      )
        return;
      const err = await Bridge.clearHistory();
      historyMsg.classList.toggle("is-ok", !err);
      historyMsg.textContent = err || "History cleared.";
      window.setTimeout(() => (historyMsg.textContent = ""), 2000);
    });

    // Profile is only settable while signed on (it's session state, not config),
    // so the control degrades to a note when the bindings aren't available.
    const profileText = overlay.querySelector<HTMLTextAreaElement>("#profileText")!;
    profileText.value = p.profile;
    const profileMsg = overlay.querySelector<HTMLSpanElement>("#profileMsg")!;
    const profileSave = overlay.querySelector<HTMLButtonElement>("#profileSave")!;
    profileSave.addEventListener("click", async () => {
      try {
        const err = await Bridge.setProfile(profileText.value);
        profileMsg.textContent = err || "Profile set.";
      } catch {
        profileMsg.textContent = "Sign on to set your profile.";
      }
      window.setTimeout(() => (profileMsg.textContent = ""), 2000);
    });

    // Account changes. The server's actual accept/reject arrives asynchronously
    // as a notice toast; these handlers report only the immediate send result.
    const acctMsg = overlay.querySelector<HTMLSpanElement>("#acctMsg")!;
    const oldPw = overlay.querySelector<HTMLInputElement>("#acctOldPw")!;
    const newPw = overlay.querySelector<HTMLInputElement>("#acctNewPw")!;
    const email = overlay.querySelector<HTMLInputElement>("#acctEmail")!;
    const flash = (m: string) => {
      acctMsg.textContent = m;
      window.setTimeout(() => (acctMsg.textContent = ""), 3000);
    };
    overlay.querySelector<HTMLButtonElement>("#acctPwSave")!.addEventListener("click", async () => {
      if (!oldPw.value || !newPw.value) {
        flash("Enter your current and new password.");
        return;
      }
      try {
        const err = await Bridge.changePassword(oldPw.value, newPw.value);
        flash(err || "Password change submitted.");
        if (!err) {
          oldPw.value = "";
          newPw.value = "";
        }
      } catch {
        flash("Sign on to change your password.");
      }
    });
    overlay.querySelector<HTMLButtonElement>("#acctEmailSave")!.addEventListener("click", async () => {
      if (!email.value) {
        flash("Enter a new email address.");
        return;
      }
      try {
        const err = await Bridge.changeEmail(email.value);
        flash(err || "Email change submitted.");
        if (!err) email.value = "";
      } catch {
        flash("Sign on to change your email.");
      }
    });
  }

  // Load persisted prefs, seed working state, render.
  void Bridge.getPreferences()
    .then((prefs) => {
      name = prefs.theme?.name || "benco";
      tokens = resolveTokens(prefs.theme ?? {});
      // A custom theme resolves to a full token map but keeps the "custom" name.
      if (prefs.theme?.tokens && Object.keys(prefs.theme.tokens).length > 0 && !presetById(name)) {
        name = "custom";
      }
      render({
        soundEnabled: prefs.soundEnabled,
        soundPack: prefs.soundPack ?? "",
        historyEnabled: prefs.historyEnabled,
        historyRetentionDays: prefs.historyRetentionDays,
        e2eeEnabled: prefs.e2eeEnabled,
        profile: prefs.profile ?? "",
        customFrame: prefs.customFrame,
      });
    })
    .catch(() =>
      render({
        soundEnabled: true,
        soundPack: "",
        historyEnabled: true,
        historyRetentionDays: 0,
        e2eeEnabled: false,
        profile: "",
        customFrame: false,
      }),
    );

  const handle: SettingsHandle = { destroy: close };
  return handle;
}
