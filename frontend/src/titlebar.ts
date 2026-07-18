// titlebar.ts — BENCchat's own window titlebar, used only when the "Custom window
// frame" setting is on (the window is created frameless). The drag region uses
// Wails' --wails-draggable property; the buttons call bound Go window controls.

import { Bridge } from "./bridge";

/** Injects the custom titlebar and reserves space for it. No-op if already
 *  mounted. Called at startup only when custom-frame is enabled. */
export function mountTitlebar(): void {
  if (document.querySelector(".titlebar")) return;
  document.body.classList.add("has-custom-frame");

  const bar = document.createElement("div");
  bar.className = "titlebar";
  bar.innerHTML = `
    <div class="titlebar__drag" style="--wails-draggable:drag">
      <span class="titlebar__title">BENCchat</span>
    </div>
    <div class="titlebar__controls">
      <button class="titlebar__btn" id="tbMin" title="Minimize" aria-label="Minimize">
        <svg viewBox="0 0 10 10" width="10" height="10"><line x1="1" y1="5" x2="9" y2="5" stroke="currentColor" stroke-width="1.2"/></svg>
      </button>
      <button class="titlebar__btn" id="tbMax" title="Maximize" aria-label="Maximize">
        <svg viewBox="0 0 10 10" width="10" height="10"><rect x="1.3" y="1.3" width="7.4" height="7.4" fill="none" stroke="currentColor" stroke-width="1.2"/></svg>
      </button>
      <button class="titlebar__btn titlebar__btn--close" id="tbClose" title="Close" aria-label="Close">
        <svg viewBox="0 0 10 10" width="10" height="10"><line x1="1.5" y1="1.5" x2="8.5" y2="8.5" stroke="currentColor" stroke-width="1.2"/><line x1="8.5" y1="1.5" x2="1.5" y2="8.5" stroke="currentColor" stroke-width="1.2"/></svg>
      </button>
    </div>`;
  document.body.prepend(bar);

  bar.querySelector("#tbMin")!.addEventListener("click", () => void Bridge.minimizeWindow());
  bar.querySelector("#tbMax")!.addEventListener("click", () => void Bridge.toggleMaximiseWindow());
  bar.querySelector("#tbClose")!.addEventListener("click", () => void Bridge.closeWindow());
  // Double-clicking the drag area toggles maximize, the usual titlebar gesture.
  bar
    .querySelector(".titlebar__drag")!
    .addEventListener("dblclick", () => void Bridge.toggleMaximiseWindow());
}
