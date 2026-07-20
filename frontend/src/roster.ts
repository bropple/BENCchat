// roster.ts — the signed-on view: buddy list on the left, conversation on the
// right. Talks only to the Bridge; it has no idea FLAP or SNACs exist.

import {
  Bridge,
  normalizeScreenName,
  type Buddy,
  type Conversation,
  type DirEntry,
  type Message,
  type Room,
  type StateEvent,
  type Verification,
  type RoomSecurity,
} from "./bridge";
import { openSettings } from "./settings";
import {
  setSoundEnabled,
  playMessageIn,
  playMessageOut,
  playSignOn,
  playSignOff,
  playAlert,
} from "./sound";
import { alertDialog, confirmDialog, promptDialog, choiceDialog } from "./dialog";
import { renderMessageBody } from "./message";
import { EMOJI_CATEGORIES } from "./emoji";

/** How long after the last keystroke we tell the other end we stopped typing. */
const TYPING_IDLE_MS = 3000;

export interface RosterHandle {
  destroy(): void;
}

export function renderRoster(
  root: HTMLElement,
  onSignOff: () => void,
): RosterHandle {
  root.innerHTML = `
    <div class="roster">
      <aside class="roster__list">
        <header class="roster__header">
          <button class="roster__me" id="meMenuBtn" aria-haspopup="true" aria-expanded="false" title="Account">
            <span class="roster__me-name" id="meName">—</span>
            <span class="roster__me-caret" aria-hidden="true">▾</span>
          </button>
          <span class="benco-caption roster__me-status" id="meStatus"></span>
        </header>
        <hr class="benco-rule" />
        <div class="roster__actions">
          <button class="benco-button benco-button--ghost roster__act-btn" id="addBuddy">+ Add Buddy</button>
          <button class="benco-button benco-button--ghost roster__act-btn" id="newIM">+ New IM</button>
          <button class="benco-button benco-button--ghost roster__act-btn" id="joinRoom">👥 Room</button>
          <button class="benco-button benco-button--ghost roster__act-btn" id="findUser">🔍 Find</button>
        </div>
        <div class="roster__scroll">
          <div class="roster__invites" id="connreqs"></div>
          <div class="roster__invites" id="invites"></div>
          <div class="roster__convos" id="convos"></div>
          <div class="roster__buddies" id="buddies"></div>
          <div class="roster__rooms" id="rooms"></div>
        </div>
        <footer class="roster__foot">
          <button class="roster__log-btn" id="logBtn" type="button"
                  title="System log" aria-expanded="false">
            <span aria-hidden="true">▤</span>
            <span>System Log</span>
            <span class="roster__log-dot" id="logDot" hidden></span>
          </button>
          <div class="roster__log" id="logPanel" hidden>
            <header class="roster__log-head">
              <span class="benco-label">System Log</span>
              <span class="roster__log-head-btns">
                <button class="settings-gear" id="logCopy" type="button"
                        title="Copy the whole log">Copy all</button>
                <button class="settings-gear" id="logClear" type="button"
                        title="Clear the log">Clear</button>
              </span>
            </header>
            <hr class="benco-rule" />
            <div class="roster__log-list" id="logList"></div>
          </div>
        </footer>
      </aside>

      <section class="chat" id="chat">

        <div class="chat__empty" id="chatEmpty">
          <p class="benco-caption">Select a buddy to start a conversation.</p>
        </div>

        <div class="chat__active" id="chatActive" hidden>
          <header class="chat__header">
            <span class="chat__with" id="chatWith"></span>
            <span class="chat__enc" id="chatEnc" hidden title="Messages in this conversation are end-to-end encrypted">🔒 encrypted</span>
            <span class="benco-caption chat__status" id="chatStatus"></span>
            <button class="settings-gear chat__warn" id="warnBtn" title="Warn this user">⚠ Warn</button>
          </header>
          <div class="chat__participants" id="roomParticipants" hidden></div>
          <hr class="benco-rule" />
          <div class="chat__away" id="chatAway" hidden></div>
          <details class="chat__profile" id="chatProfile" hidden>
            <summary class="benco-caption">Profile</summary>
            <div class="chat__profile-text" id="chatProfileText"></div>
          </details>
          <div class="chat__log" id="chatLog"></div>
          <div class="chat__typing benco-caption" id="chatTyping"></div>
          <div class="chat__compose">
            <textarea class="benco-input chat__input" id="chatInput" rows="2"
                      placeholder="Type a message; Enter sends"></textarea>
            <button class="chat__emoji-btn" id="emojiBtn" type="button" title="Insert emoji" aria-label="Insert emoji">☺</button>
            <button class="benco-button" id="chatSend">Send</button>
            <div class="chat__emoji-panel" id="emojiPanel" hidden></div>
          </div>
          <div class="benco-error" id="chatError"></div>
        </div>

        <!-- Last child of the pane and IN FLOW, not floating over it: a toast
             that overlays always ends up covering something eventually. Here it
             takes its own strip along the bottom and obstructs nothing. -->
        <div class="roster__toast" id="toast" hidden></div>
      </section>
    </div>`;

  const el = <T extends HTMLElement>(id: string): T => {
    const node = document.getElementById(id);
    if (!node) throw new Error(`missing element #${id}`);
    return node as T;
  };

  const buddiesEl = el<HTMLDivElement>("buddies");
  const convosEl = el<HTMLDivElement>("convos");
  const invitesEl = el<HTMLDivElement>("invites");
  const connReqsEl = el<HTMLDivElement>("connreqs");
  const roomsEl = el<HTMLDivElement>("rooms");
  const meNameEl = el<HTMLSpanElement>("meName");
  const chatEmptyEl = el<HTMLDivElement>("chatEmpty");
  const chatActiveEl = el<HTMLDivElement>("chatActive");
  const chatWithEl = el<HTMLSpanElement>("chatWith");
  const chatEncEl = el<HTMLSpanElement>("chatEnc");
  const chatStatusEl = el<HTMLSpanElement>("chatStatus");
  const chatLogEl = el<HTMLDivElement>("chatLog");
  const chatTypingEl = el<HTMLDivElement>("chatTyping");
  const chatAwayEl = el<HTMLDivElement>("chatAway");
  const chatProfileEl = el<HTMLDetailsElement>("chatProfile");
  const chatProfileTextEl = el<HTMLDivElement>("chatProfileText");
  const chatInputEl = el<HTMLTextAreaElement>("chatInput");
  const chatSendEl = el<HTMLButtonElement>("chatSend");
  const chatErrorEl = el<HTMLDivElement>("chatError");
  const roomParticipantsEl = el<HTMLDivElement>("roomParticipants");
  const emojiBtn = el<HTMLButtonElement>("emojiBtn");
  const emojiPanel = el<HTMLDivElement>("emojiPanel");

  /** The conversation currently open, as a normalized key. */
  let activeKey: string | null = null;
  let activeScreenName: string | null = null;
  /** The chat room currently open, by cookie (mutually exclusive with a 1:1). */
  let activeRoom: string | null = null;
  /** Set while a user-initiated join is in flight, so only that join auto-opens
   *  the room view (a background room's roster update must not yank focus). */
  let wantOpenRoom = false;
  let rooms: Room[] = [];
  let buddies: Buddy[] = [];
  /** Our own screen name, for guarding against messaging ourselves. */
  let selfName = "";
  // Read by the account menu (to label the away item) and set by refreshSelf,
  // which run in that order, so it is declared up here rather than beside its
  // updater.
  let selfAway = false;
  let unread = new Map<string, number>();
  let typingTimer: number | undefined;
  let stopTypingTimer: number | undefined;
  let sentTyping = false;

  // Conversations with people who aren't on the buddy list, keyed by normalized
  // screen name. Anyone can message you without being on your list — and an
  // empty feedbag is perfectly normal — so these must be reachable in the UI or
  // their messages would arrive into a thread nothing ever shows.
  const looseConvos = new Map<string, string>();

  // Pending room invitations live in the roster rather than interrupting with a
  // modal: one can arrive before you have verified the sender, and demanding an
  // immediate yes/no about someone you haven't checked is the wrong prompt at
  // the wrong moment.
  async function renderConnectionRequests(): Promise<void> {
    let reqs: Awaited<ReturnType<typeof Bridge.pendingConnectionRequests>> = [];
    try {
      reqs = (await Bridge.pendingConnectionRequests()) ?? [];
    } catch {
      reqs = [];
    }
    if (!reqs.length) {
      connReqsEl.innerHTML = "";
      return;
    }
    connReqsEl.innerHTML = `
      <div class="roster__group-head roster__section-head">
        <span class="benco-label">Requests <span class="roster__invite-dot"></span></span>
        <span class="benco-caption">${reqs.length}</span>
      </div>
      ${reqs
        .map(
          (r) => `
        <div class="roster__invite" data-sn="${escapeAttr(r.screenName)}">
          <div class="roster__invite-what">
            <span class="roster__invite-room">👤 ${escapeHTML(r.screenName)}</span>
            <span class="benco-caption">wants to connect${r.reason ? ` — ${escapeHTML(r.reason)}` : ""}</span>
          </div>
          <div class="roster__invite-acts">
            <button class="benco-button roster__invite-yes" data-conn-yes="${escapeAttr(r.screenName)}">Accept</button>
            <button class="benco-button benco-button--ghost roster__invite-no" data-conn-no="${escapeAttr(r.screenName)}">✕</button>
          </div>
        </div>`,
        )
        .join("")}`;

    for (const btn of connReqsEl.querySelectorAll<HTMLButtonElement>("[data-conn-yes]")) {
      btn.addEventListener("click", async () => {
        const sn = btn.dataset.connYes!;
        // Accepting is mutual: it connects you both, so you'll see each other's
        // presence and can message. Say so, since it's more than "let them in".
        const ok = await confirmDialog(
          `Connect with ${sn}?\n\nYou'll be able to message each other and see when the other is online.`,
          { title: "Accept connection", okLabel: "Connect" },
        );
        if (!ok) return;
        const err = await Bridge.approveConnectionRequest(sn);
        if (err) void alertDialog(err, { title: "Couldn't connect" });
        void renderConnectionRequests();
        void refreshBuddies();
      });
    }
    for (const btn of connReqsEl.querySelectorAll<HTMLButtonElement>("[data-conn-no]")) {
      btn.addEventListener("click", async () => {
        await Bridge.declineConnectionRequest(btn.dataset.connNo!);
        void renderConnectionRequests();
      });
    }
  }

  async function renderInvites(): Promise<void> {
    let invites: Awaited<ReturnType<typeof Bridge.pendingRoomInvites>> = [];
    try {
      invites = (await Bridge.pendingRoomInvites()) ?? [];
    } catch {
      invites = [];
    }
    if (!invites.length) {
      invitesEl.innerHTML = "";
      return;
    }
    invitesEl.innerHTML = `
      <div class="roster__group-head roster__section-head">
        <span class="benco-label">Invitations <span class="roster__invite-dot"></span></span>
        <span class="benco-caption">${invites.length}</span>
      </div>
      ${invites
        .map(
          (i) => `
        <div class="roster__invite" data-room="${escapeAttr(i.room)}">
          <div class="roster__invite-what">
            <span class="roster__invite-room">👥 ${escapeHTML(i.room)}</span>
            <span class="benco-caption">from ${escapeHTML(i.from || "someone")}</span>
          </div>
          <div class="roster__invite-acts">
            <button class="benco-button roster__invite-yes" data-accept="${escapeAttr(i.room)}">Join</button>
            <button class="benco-button benco-button--ghost roster__invite-no" data-decline="${escapeAttr(i.room)}">✕</button>
          </div>
        </div>`,
        )
        .join("")}`;

    for (const btn of invitesEl.querySelectorAll<HTMLButtonElement>("[data-accept]")) {
      btn.addEventListener("click", async () => {
        const room = btn.dataset.accept!;
        const ok = await confirmDialog(
          `Join the encrypted room “${room}”?\n\n` +
            `You'll be visible to everyone in it, including anyone who can't read it. ` +
            `Only join if you trust whoever invited you — check their safety number first if you haven't.`,
          { title: "Join encrypted room", okLabel: "Join" },
        );
        if (!ok) return;
        wantOpenRoom = true;
        const err = await Bridge.acceptRoomInvite(room);
        if (err) {
          wantOpenRoom = false;
          void alertDialog(err, { title: "Couldn't join" });
        }
        void renderInvites();
      });
    }
    for (const btn of invitesEl.querySelectorAll<HTMLButtonElement>("[data-decline]")) {
      btn.addEventListener("click", async () => {
        await Bridge.declineRoomInvite(btn.dataset.decline!);
        void renderInvites();
      });
    }
  }

  // --- Tray notification badge -------------------------------------------
  // Show the tray's notification dot when a message arrives while the window is
  // not the user's focus (hidden to tray, minimized, or in the background), and
  // clear it the moment they come back. The frontend keeps running while hidden,
  // so it can drive this even when closed to the tray.
  let trayNotifying = false;
  const windowActive = (): boolean =>
    document.hasFocus() && document.visibilityState === "visible";
  const markTrayNotify = (): void => {
    if (!trayNotifying && !windowActive()) {
      trayNotifying = true;
      void Bridge.setTrayNotify(true);
    }
  };
  const clearTrayNotify = (): void => {
    if (trayNotifying) {
      trayNotifying = false;
      void Bridge.setTrayNotify(false);
    }
  };
  window.addEventListener("focus", clearTrayNotify);
  document.addEventListener("visibilitychange", () => {
    if (windowActive()) clearTrayNotify();
  });

  // --- Rendering ----------------------------------------------------------

  const presenceLabel = (b: Buddy): string => {
    switch (b.presence) {
      case "away":
        return "Away";
      case "idle":
        return "Idle";
      case "online":
        return "Online";
      default:
        return "Offline";
    }
  };

  // buddyRow renders a single roster row (buddy or off-list conversation).
  function buddyRow(b: Buddy): string {
    const n = unread.get(b.key) ?? 0;
    const badge = n > 0 ? `<span class="roster__badge">${n}</span>` : "";
    const selected = b.key === activeKey ? " is-selected" : "";
    const onList = buddies.some((x) => x.key === b.key);
    const sn = escapeAttr(b.screenName);
    const blockedCls = b.blocked ? " is-blocked" : "";
    return `
      <div class="roster__buddy roster__buddy--${b.presence}${selected}${blockedCls}" data-sn="${sn}">
        <span class="roster__dot"></span>
        ${buddyIconImg(b)}
        <span class="roster__name" data-open="${sn}">${escapeHTML(b.alias || b.screenName)}</span>
        ${b.blocked ? `<span class="roster__blocked-tag">blocked</span>` : ""}
        ${b.pending && !b.blocked ? `<span class="roster__pending-tag" title="Waiting for them to accept your connection request">pending</span>` : ""}
        ${badge}
        <button class="roster__act roster__menu-btn" title="More…"
                data-menu-sn="${sn}" data-menu-kind="${onList ? "onlist" : "offlist"}"
                data-menu-blocked="${b.blocked ? "true" : "false"}">⋯</button>
      </div>`;
  }

  // wireRows attaches click + menu handlers to the rows inside a section element.
  function wireRows(container: HTMLElement): void {
    for (const row of container.querySelectorAll<HTMLElement>(".roster__buddy")) {
      row.addEventListener("click", (e) => {
        if ((e.target as HTMLElement).closest(".roster__act")) return;
        void openConversation(row.dataset.sn!);
      });
    }
    for (const btn of container.querySelectorAll<HTMLElement>(".roster__menu-btn")) {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        openRowMenu(btn);
      });
    }
    void hydrateIcons(container);
  }

  // renderBuddies renders the two people-sections: off-list "Conversations" at
  // the top (only when present), then the "Buddies" list below. Rooms are a
  // separate section (renderRooms). Both are always clearly labeled.
  function renderBuddies(): void {
    // Off-list conversations: people we've messaged who aren't on the buddy list.
    const loose: Buddy[] = [];
    for (const [key, screenName] of looseConvos) {
      if (buddies.some((b) => b.key === key)) continue;
      loose.push({
        screenName,
        key,
        group: "Conversations",
        presence: "offline",
        idleSince: "",
        signedOnAt: "",
      });
    }

    // --- Conversations (non-buddy) section ---
    if (loose.length > 0) {
      convosEl.innerHTML = `
        <div class="roster__group">
          <div class="roster__group-head">
            <span class="benco-label">Conversations</span>
            <span class="benco-caption">${loose.length}</span>
          </div>
          ${loose.map(buddyRow).join("")}
        </div>`;
      wireRows(convosEl);
    } else {
      convosEl.innerHTML = "";
    }

    // --- Buddies section ---
    // Preserve the order the Go side sorted buddies into, but split by feedbag
    // group so multi-group lists keep their structure under the "Buddies" header.
    const groups: { name: string; members: Buddy[] }[] = [];
    for (const b of buddies) {
      const last = groups[groups.length - 1];
      if (last && last.name === b.group) last.members.push(b);
      else groups.push({ name: b.group, members: [b] });
    }

    const onlineTotal = buddies.filter((b) => b.presence !== "offline").length;
    const multiGroup = groups.length > 1;

    let buddiesHTML = `
      <div class="roster__group-head roster__section-head">
        <span class="benco-label">Buddies</span>
        <span class="benco-caption">${onlineTotal}/${buddies.length}</span>
      </div>`;

    if (buddies.length === 0) {
      buddiesHTML += `<p class="benco-caption roster__hint">
        Your buddy list is empty. Use <strong>+ Add Buddy</strong> to add someone,
        or <strong>+ New IM</strong> to message without adding.
      </p>`;
    } else {
      buddiesHTML += groups
        .map((g) => {
          const online = g.members.filter((b) => b.presence !== "offline").length;
          // Only show a per-group sub-label when there's more than one group;
          // a single default group would just repeat the "Buddies" header.
          const sub = multiGroup
            ? `<div class="roster__group-head roster__group-head--sub">
                 <span class="benco-caption">${escapeHTML(g.name)}</span>
                 <span class="benco-caption">${online}/${g.members.length}</span>
               </div>`
            : "";
          return `<div class="roster__group">${sub}${g.members.map(buddyRow).join("")}</div>`;
        })
        .join("");
    }
    buddiesEl.innerHTML = buddiesHTML;
    wireRows(buddiesEl);
  }

  async function blockBuddy(screenName: string): Promise<void> {
    if (
      !(await confirmDialog(`Block ${screenName}? They won't be able to message you or see you online.`, {
        title: "Block buddy",
        okLabel: "Block",
        danger: true,
      }))
    ) {
      return;
    }
    const err = await Bridge.blockBuddy(screenName);
    if (err) showToast(err, "error");
  }

  async function unblockBuddy(screenName: string): Promise<void> {
    const err = await Bridge.unblockBuddy(screenName);
    if (err) showToast(err, "error");
  }

  async function addBuddy(screenName?: string): Promise<void> {
    const sn = (screenName ?? (await promptDialog("Add buddy — screen name:", "", { title: "Add buddy" })) ?? "").trim();
    if (!sn) return;
    // Off-list adds go to the default group; a fresh prompt lets the user choose.
    const group = screenName
      ? ""
      : ((await promptDialog(`Group for ${sn} (blank = default):`, "", { title: "Add buddy" })) ?? "").trim();
    const err = await Bridge.addBuddy(sn, group);
    if (err) await alertDialog(err, { title: "Add buddy" });
    // The store emits buddyListChanged, which refreshes the roster.
  }

  async function removeBuddy(screenName: string): Promise<void> {
    if (
      !(await confirmDialog(`Remove ${screenName} from your buddy list?`, {
        title: "Remove buddy",
        okLabel: "Remove",
        danger: true,
      }))
    )
      return;
    const err = await Bridge.removeBuddy(screenName);
    if (err) await alertDialog(err, { title: "Remove buddy" });
  }

  async function renameBuddy(screenName: string): Promise<void> {
    const current = buddies.find((b) => normalizeScreenName(b.screenName) === normalizeScreenName(screenName));
    const alias = await promptDialog(`Nickname for ${screenName} (blank to clear):`, current?.alias ?? "", {
      title: "Rename buddy",
    });
    if (alias === null) return;
    const err = await Bridge.renameBuddy(screenName, alias.trim());
    if (err) await alertDialog(err, { title: "Rename buddy" });
  }

  function renderMessages(messages: Message[] | null | undefined): void {
    // An empty thread arrives from Go as a nil slice → JSON null; without this
    // guard, `.length` throws and the previous thread's messages linger on
    // screen when switching conversations or rooms.
    if (!messages || messages.length === 0) {
      chatLogEl.innerHTML = `<p class="benco-caption chat__hint">No messages yet.</p>`;
      return;
    }
    chatLogEl.innerHTML = messages
      .map((m) => {
        const cls = m.outgoing ? "chat__msg--out" : "chat__msg--in";
        const auto = m.autoResponse
          ? `<span class="chat__auto benco-caption">auto-reply</span>`
          : "";
        // Signatures are a ROOM feature. A 1:1 message is already authenticated
        // by its encryption — NaCl box proves who sealed it — so there is
        // nothing unattributable about one, and showing a warning there would
        // be noise on every message the user ever receives.
        const roomMsg = activeRoom !== null;
        const lock = m.forged
          ? `<span class="chat__lock chat__lock--forged benco-caption" title="This message is NOT signed by the person it claims to be from — someone in the room may be impersonating them">⚠</span>`
          : m.encrypted && (m.senderVerified || !roomMsg)
            ? `<span class="chat__lock benco-caption" title="End-to-end encrypted">🔒</span>`
            : m.encrypted
              ? `<span class="chat__lock chat__lock--unsigned benco-caption" title="Encrypted, but not signed — authorship can't be confirmed">🔒<span class="chat__lock-warn">⚠</span></span>`
              : "";
        const forgedCls = m.forged ? " chat__msg--forged" : "";
        return `
          <div class="chat__msg ${cls}${forgedCls}">
            <div class="chat__msg-meta">
              <span class="chat__msg-from">${escapeHTML(m.from)}</span>
              <span class="benco-caption">${formatTime(m.at)}</span>
              ${lock}
              ${auto}
            </div>
            <div class="chat__msg-text">${renderMessageBody(m.text)}</div>
          </div>`;
      })
      .join("");
    // Keep the newest message in view.
    chatLogEl.scrollTop = chatLogEl.scrollHeight;
  }

  // refreshEncBadge shows the header lock when the active DM will be encrypted
  // (E2EE on and the peer's key known), and reflects verification status:
  // grey "encrypted" (unverified), green "verified", or a "key changed" warning.
  // Rooms and plaintext peers hide it. Clicking opens the verify dialog.
  async function refreshEncBadge(screenName: string): Promise<void> {
    let on = false;
    try {
      on = await Bridge.conversationEncrypted(screenName);
    } catch {
      on = false;
    }
    // Guard against a slow reply after the user switched conversations.
    if (activeScreenName !== screenName || activeRoom) return;

    chatEncEl.classList.remove(
      "chat__enc--verified",
      "chat__enc--changed",
      "chat__enc--plain",
      "chat__enc--checking",
    );
    if (!on) {
      // Not encrypting, and we have looked (openConversation shows a neutral
      // "checking" state until the key fetch finishes, so reaching here means we
      // genuinely could not encrypt). Every BENCchat account publishes keys, so
      // this is the unexpected case, and it must be impossible to miss: a
      // conversation in the clear cannot look like one that isn't.
      chatEncEl.hidden = false;
      chatEncEl.textContent = "⚠ NOT ENCRYPTED";
      chatEncEl.classList.add("chat__enc--plain");
      chatEncEl.title =
        `Messages with ${screenName} are NOT end-to-end encrypted — they are sent in the ` +
        `clear and the server can read them. This is unexpected: their account may not have ` +
        `finished setting up encryption. Don't send anything sensitive.`;
      return;
    }
    chatEncEl.hidden = false;
    let status = "unverified";
    try {
      status = (await Bridge.verificationInfo(screenName)).status;
    } catch {
      status = "unverified";
    }
    if (activeScreenName !== screenName || activeRoom) return;
    if (status === "verified") {
      chatEncEl.textContent = "🔒 verified";
      chatEncEl.classList.add("chat__enc--verified");
      chatEncEl.title = "Encrypted and verified — click to review";
    } else if (status === "changed") {
      chatEncEl.textContent = "⚠ key changed";
      chatEncEl.classList.add("chat__enc--changed");
      chatEncEl.title = "This person's key changed since you verified it — click to review";
    } else if (status === "device-added") {
      // Their device set grew rather than being replaced. Under cross-signing
      // the safety number follows their ACCOUNT identity, not their machines,
      // so nothing about it moved and there is nothing to re-check. What this
      // status actually means is that the conversation was never verified in
      // the first place and they happen to have added a machine — so the badge
      // says that, neutrally. Raising an alarm over a change the signature
      // already accounts for is exactly what teaches people to dismiss the
      // warning that matters.
      chatEncEl.textContent = "🔒 new device";
      chatEncEl.title =
        "They added a device — messages to them are encrypted to it too, and the safety " +
        "number is unchanged. This conversation is still unverified; click to verify.";
    } else if (status === "unavailable") {
      // Encrypting, but there is no identity on one side yet, so there is no
      // safety number to compare. Distinguished from plain "unverified"
      // because "click to verify" would open a dialog with nothing in it.
      chatEncEl.textContent = "🔒 encrypted";
      chatEncEl.title =
        "Encrypted, but there's no safety number to compare yet — that needs an account " +
        "identity on both sides.";
    } else {
      chatEncEl.textContent = "🔒 encrypted";
      chatEncEl.title = "Encrypted (unverified) — click to verify";
    }
  }

  function renderChatStatus(): void {
    if (!activeKey) return;
    const b = buddies.find((x) => x.key === activeKey);
    chatStatusEl.textContent = b ? presenceLabel(b) : "";
    updateBuddyInfo();
  }

  // Shows the active buddy's away message and profile. Both are fetched
  // separately from presence, so each shows a placeholder until its reply lands
  // and updates in place when it does.
  function updateBuddyInfo(): void {
    const b = buddies.find((x) => x.key === activeKey);

    if (b && b.presence === "away") {
      const msg = b.awayMessage
        ? escapeHTML(b.awayMessage)
        : `<span class="chat__away-pending">fetching away message…</span>`;
      chatAwayEl.innerHTML = `<span class="chat__away-label">🌙 Away</span> ${msg}`;
      chatAwayEl.hidden = false;
    } else {
      chatAwayEl.hidden = true;
    }

    if (b && b.profile) {
      chatProfileTextEl.innerHTML = escapeHTML(b.profile);
      chatProfileEl.hidden = false;
    } else {
      chatProfileEl.hidden = true;
    }
  }

  // --- Actions ------------------------------------------------------------

  async function openConversation(screenName: string): Promise<void> {
    // You can't hold a conversation with yourself — the server won't relay it.
    if (selfName && normalizeScreenName(screenName) === normalizeScreenName(selfName)) {
      showToast("You can't message yourself.", "info");
      return;
    }
    activeRoom = null;
    // Cancel any pending "open the next room that appears". Accepting an
    // invitation for a room we are ALREADY in is a no-op, so no room-changed
    // event arrives to clear this — and every later roster update would then
    // yank the user out of whatever they opened and back into that room.
    wantOpenRoom = false;
    // Leave "room mode" for the header/participant list.
    roomParticipantsEl.hidden = true;
    chatStatusEl.classList.remove("chat__status--room");
    activeScreenName = screenName;
    activeKey = normalizeScreenName(screenName);

    // Remember anyone we're talking to who isn't on the list, so the thread
    // stays reachable after the window is closed.
    if (!buddies.some((b) => b.key === activeKey)) {
      looseConvos.set(activeKey, screenName);
    }
    chatErrorEl.textContent = "";
    chatTypingEl.textContent = "";

    chatEmptyEl.hidden = true;
    chatActiveEl.hidden = false;
    chatWithEl.textContent = screenName;
    // Neutral "checking" until the key lookup finishes, so the red NOT ENCRYPTED
    // alarm never flashes for the moment before we actually know.
    chatEncEl.hidden = false;
    chatEncEl.textContent = "checking…";
    chatEncEl.className = "chat__enc chat__enc--checking";
    // Proactively learn the peer's keys — every BENCchat account has them — so
    // the lock (or the warning) is right before the first message, not after.
    void Bridge.prepareConversation(screenName).then(() => {
      if (activeScreenName === screenName && !activeRoom) void refreshEncBadge(screenName);
    });
    renderChatStatus();

    // Fetch the buddy's profile (and away text) — replies land via buddyChanged
    // events that refresh the info area.
    void Bridge.requestUserInfo(screenName);

    const convo: Conversation = await Bridge.getConversation(screenName);
    renderMessages(convo.messages);

    unread.set(activeKey, 0);
    await Bridge.markRead(screenName);
    renderBuddies();
    chatInputEl.focus();
  }

  // --- Chat rooms ---------------------------------------------------------

  function renderRooms(): void {
    const head = `
      <div class="roster__group-head roster__section-head">
        <span class="benco-label">Rooms</span>
        ${rooms.length > 0 ? `<span class="benco-caption">${rooms.length}</span>` : ""}
      </div>`;
    if (rooms.length === 0) {
      roomsEl.innerHTML = `${head}<p class="benco-caption roster__hint">No rooms yet. Use <strong>👥 Room</strong> to join one.</p>`;
      return;
    }
    // Joined rooms first, then re-joinable recents; alphabetical within each.
    const sorted = [...rooms].sort(
      (a, b) => Number(b.joined) - Number(a.joined) || a.name.localeCompare(b.name),
    );
    roomsEl.innerHTML = `
      ${head}
      ${sorted
        .map((r) => {
          const sel = r.cookie === activeRoom ? " is-selected" : "";
          const recent = r.joined ? "" : " roster__room--recent";
          const meta = r.joined
            ? `<span class="benco-caption roster__room-count">${r.participants.length}</span>`
            : `<span class="benco-caption roster__room-rejoin">↻</span>`;
          return `
            <div class="roster__room${sel}${recent}" data-room="${escapeAttr(r.cookie)}" data-name="${escapeAttr(r.name)}" data-joined="${r.joined}">
              <span class="roster__room-icon">👥</span>
              <span class="roster__name">${escapeHTML(r.name || r.cookie)}</span>
              ${meta}
              <button class="roster__act roster__menu-btn" title="More…"
                      data-menu-room="${escapeAttr(r.cookie)}" data-menu-name="${escapeAttr(r.name)}"
                      data-menu-joined="${r.joined}">⋯</button>
            </div>`;
        })
        .join("")}`;
    for (const row of roomsEl.querySelectorAll<HTMLElement>(".roster__room")) {
      row.addEventListener("click", (e) => {
        if ((e.target as HTMLElement).closest(".roster__menu-btn")) return;
        // A joined room opens; a recent one re-joins (which then opens it).
        if (row.dataset.joined === "true") void openRoom(row.dataset.room!);
        else void rejoinRoom(row.dataset.name!);
      });
    }
    for (const btn of roomsEl.querySelectorAll<HTMLElement>(".roster__menu-btn")) {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        openRowMenu(btn);
      });
    }
  }

  async function refreshRooms(): Promise<void> {
    rooms = await Bridge.getRooms();
    renderRooms();
  }

  // Re-join a recent room by name; the join flow reuses its cookie so the saved
  // scrollback is preserved and new messages append.
  async function rejoinRoom(name: string): Promise<void> {
    showToast(`Rejoining “${name}”…`, "info");
    wantOpenRoom = true;
    showJoiningRoom(name);
    const err = await Bridge.joinRoom(name);
    if (err) {
      wantOpenRoom = false;
      restoreFromJoin();
      showToast(err, "error");
    }
  }

  // Joining a room is a multi-connection round-trip (BOS → ChatNav → Chat), so
  // the roomChanged event that actually opens it can be a second or more away.
  // Clear the old thread immediately: leaving the previous conversation's
  // messages and header on screen reads as "the click did nothing", and worse,
  // as though those messages belong to the room being joined.
  function showJoiningRoom(name: string): void {
    activeScreenName = null;
    activeKey = null;
    activeRoom = null;
    chatErrorEl.textContent = "";
    chatTypingEl.textContent = "";
    chatAwayEl.hidden = true;
    chatProfileEl.hidden = true;
    chatEncEl.hidden = true;
    roomParticipantsEl.hidden = true;
    chatEmptyEl.hidden = true;
    chatActiveEl.hidden = false;
    chatWithEl.textContent = `👥 ${name}`;
    chatStatusEl.classList.add("chat__status--room");
    setRoomStatusText(0); // renders "Joining…" while the count is zero
    renderMessages([]);
    renderBuddies();
  }

  // A join that failed leaves us with no conversation at all rather than a
  // half-open room header.
  function restoreFromJoin(): void {
    chatActiveEl.hidden = true;
    chatEmptyEl.hidden = false;
    chatStatusEl.classList.remove("chat__status--room");
  }

  // Close (remove) a 1:1 thread without blocking the person.
  async function closeConversation(sn: string): Promise<void> {
    await Bridge.closeConversation(sn);
    const key = normalizeScreenName(sn);
    looseConvos.delete(key);
    unread.delete(key);
    if (activeKey === key) {
      activeScreenName = null;
      activeKey = null;
      chatActiveEl.hidden = true;
      chatEmptyEl.hidden = false;
    }
    // The conversationsChanged event re-renders the list.
  }

  // --- Row action menu (the ⋯ button on every buddy / room) --------------

  interface MenuItem {
    label: string;
    run: () => void | Promise<void>;
    danger?: boolean;
  }

  // One reusable floating menu, shared across re-mounts (found by id).
  const menuEl = ((): HTMLDivElement => {
    const existing = document.getElementById("rowMenu");
    if (existing) return existing as HTMLDivElement;
    const m = document.createElement("div");
    m.id = "rowMenu";
    m.className = "roster__menu";
    m.hidden = true;
    document.body.appendChild(m);
    return m;
  })();

  function closeRowMenu(): void {
    menuEl.hidden = true;
    menuEl.innerHTML = "";
  }

  function openRowMenu(btn: HTMLElement): void {
    const items = rowMenuItems(btn.dataset);
    if (items.length === 0) return;
    menuEl.innerHTML = items
      .map(
        (it, i) =>
          `<button type="button" class="roster__menu-item${it.danger ? " is-danger" : ""}" data-i="${i}">${escapeHTML(it.label)}</button>`,
      )
      .join("");
    menuEl.querySelectorAll<HTMLButtonElement>(".roster__menu-item").forEach((el, i) => {
      el.addEventListener("click", () => {
        closeRowMenu();
        void items[i].run();
      });
    });
    menuEl.hidden = false;
    // Anchor under the button, flipping up / clamping left to stay on screen.
    const r = btn.getBoundingClientRect();
    const left = Math.max(6, Math.min(r.left, window.innerWidth - menuEl.offsetWidth - 6));
    let top = r.bottom + 4;
    if (top + menuEl.offsetHeight > window.innerHeight - 6) top = r.top - menuEl.offsetHeight - 4;
    menuEl.style.left = `${left}px`;
    menuEl.style.top = `${Math.max(6, top)}px`;
  }

  function rowMenuItems(d: DOMStringMap): MenuItem[] {
    if (d.menuRoom) {
      const cookie = d.menuRoom;
      const name = d.menuName ?? "";
      if (d.menuJoined === "true") {
        return [{ label: "Leave room", run: () => leaveRoom(cookie), danger: true }];
      }
      return [
        { label: "Rejoin room", run: () => rejoinRoom(name) },
        { label: "Forget room", run: () => Bridge.forgetRoom(cookie), danger: true },
      ];
    }
    const sn = d.menuSn ?? "";
    const blocked = d.menuBlocked === "true";
    const items: MenuItem[] = [{ label: "Message", run: () => openConversation(sn) }];
    if (d.menuKind === "onlist") {
      items.push({ label: "Rename…", run: () => renameBuddy(sn) });
    } else {
      items.push({ label: "Add to buddy list", run: () => addBuddy(sn) });
    }
    items.push(
      blocked
        ? { label: "Unblock", run: () => unblockBuddy(sn) }
        : { label: "Block", run: () => blockBuddy(sn), danger: true },
    );
    items.push({ label: "Close conversation", run: () => closeConversation(sn) });
    if (d.menuKind === "onlist") {
      items.push({ label: "Remove from list", run: () => removeBuddy(sn), danger: true });
    }
    return items;
  }

  async function openRoom(cookie: string): Promise<void> {
    activeScreenName = null;
    activeKey = null;
    activeRoom = cookie;
    wantOpenRoom = false;
    chatErrorEl.textContent = "";
    chatTypingEl.textContent = "";
    chatEmptyEl.hidden = true;
    chatActiveEl.hidden = false;
    // Rooms have no away/profile banner; the participant list starts collapsed.
    chatAwayEl.hidden = true;
    chatProfileEl.hidden = true;
    roomParticipantsEl.hidden = true;

    const room = await Bridge.getRoom(cookie);
    renderRoomHeader(room);
    renderMessages(room.messages);
    renderRooms();
    renderBuddies();
    chatInputEl.focus();
  }

  function renderRoomHeader(room: Room): void {
    chatWithEl.textContent = `👥 ${room.name || room.cookie}`;
    chatStatusEl.classList.add("chat__status--room");
    setRoomStatusText(room.participants.length);
    void refreshRoomSecurity(room);
  }

  // Rooms carry their own lock badge, and — more importantly — a count of who
  // is present but unable to read. A single non-reader means the room is not
  // private, so that has to be visible rather than inferred.
  async function refreshRoomSecurity(room: Room): Promise<void> {
    let sec: RoomSecurity | null = null;
    try {
      sec = await Bridge.roomSecurityInfo(room.cookie);
    } catch {
      sec = null;
    }
    if (activeRoom !== room.cookie) return; // switched away mid-fetch

    const nonReaders = sec?.nonReaders ?? [];
    chatEncEl.classList.remove("chat__enc--verified", "chat__enc--changed", "chat__enc--plain");
    if (!sec?.encrypted) {
      chatEncEl.hidden = true;
    } else if (!sec.readable) {
      // Encrypted, but we have no key: everything here is unreadable and
      // sending is blocked. Saying so beats a hidden badge, which would imply
      // an ordinary plaintext room.
      chatEncEl.hidden = false;
      chatEncEl.textContent = "🔒 no key";
      chatEncEl.classList.add("chat__enc--changed");
      chatEncEl.title = "This room is encrypted but you don't have its key — ask a member to invite you again";
    } else if (nonReaders.length > 0) {
      chatEncEl.hidden = false;
      chatEncEl.textContent = `⚠ ${nonReaders.length} can't read`;
      chatEncEl.classList.add("chat__enc--changed");
      chatEncEl.title = `${nonReaders.join(", ")} can see who is talking and when, but not what is said — click for options`;
    } else {
      chatEncEl.hidden = false;
      chatEncEl.textContent = "🔒 encrypted room";
      chatEncEl.title = "Only invited people can read this room — click to invite or manage";
    }

    roomParticipantsEl.innerHTML = room.participants
      .map((p) => {
        const blind = nonReaders.some((n) => normalizeScreenName(n) === normalizeScreenName(p));
        const cls = sec?.encrypted ? (blind ? " chat__participant--blind" : " chat__participant--reader") : "";
        const mark = sec?.encrypted ? (blind ? " ⚠" : " 🔒") : "";
        return `<span class="chat__participant${cls}" title="${blind ? "can't read this room" : ""}">${escapeHTML(p)}${mark}</span>`;
      })
      .join("");
  }

  // The header's "N here ▸/▾" toggle text; the arrow reflects whether the
  // participant list below it is expanded.
  function setRoomStatusText(count: number): void {
    if (!count) {
      chatStatusEl.textContent = "Joining…";
      return;
    }
    chatStatusEl.textContent = `👥 ${count} here ${roomParticipantsEl.hidden ? "▸" : "▾"}`;
  }

  async function joinRoomPrompt(): Promise<void> {
    const name = await promptDialog("Join or create a chat room:", "", { title: "Chat room" });
    if (!name || !name.trim()) return;
    const room = name.trim();

    // Encryption is decided at creation and can't be switched on later, because
    // everyone already in the room would be unable to read what follows.
    const kind = await choiceDialog(
      `Create “${room}” as an encrypted room?\n\n` +
        `Encrypted: only people you invite can read it. Anyone else who joins sees ` +
        `scrambled text — you can't stop them entering, but they learn nothing.\n\n` +
        `Normal: anyone who joins can read everything, and so can the server.`,
      [
        { label: "Normal room", value: "plain" },
        { label: "Encrypted room", value: "enc" },
      ],
      { title: "Chat room" },
    );
    if (kind === null) return;

    showToast(`Joining “${room}”…`, "info");
    wantOpenRoom = true;
    showJoiningRoom(room);
    const err = kind === "enc" ? await Bridge.createEncryptedRoom(room) : await Bridge.joinRoom(room);
    if (err) {
      wantOpenRoom = false;
      restoreFromJoin();
      showToast(err, "error");
    }
    // Success surfaces via a roomChanged event, which opens the room (below).
  }

  async function leaveRoom(cookie: string): Promise<void> {
    await Bridge.leaveRoom(cookie);
    if (activeRoom === cookie) {
      activeRoom = null;
      chatActiveEl.hidden = true;
      chatEmptyEl.hidden = false;
    }
  }

  // Clicking the "N here" status toggles the participant list open/closed.
  function toggleParticipants(): void {
    if (!activeRoom || roomParticipantsEl.childElementCount === 0) return;
    roomParticipantsEl.hidden = !roomParticipantsEl.hidden;
    setRoomStatusText(roomParticipantsEl.childElementCount);
  }

  // --- Emoji picker -------------------------------------------------------

  // Discord-style: category tabs (jump-scroll) above a scrolling grid of
  // labelled sections. Picking an emoji inserts it and keeps the panel open so
  // several can be chosen in a row.
  function buildEmojiPanel(): void {
    const tabs = EMOJI_CATEGORIES.map(
      (c, i) =>
        `<button type="button" class="chat__emoji-tab" data-cat="${i}" title="${escapeAttr(c.label)}">${c.icon}</button>`,
    ).join("");
    const sections = EMOJI_CATEGORIES.map(
      (c, i) => `
        <div class="chat__emoji-section" data-cat="${i}">
          <div class="chat__emoji-cat-label">${escapeHTML(c.label)}</div>
          <div class="chat__emoji-row">
            ${c.list.map((e) => `<button type="button" class="chat__emoji" tabindex="-1">${e}</button>`).join("")}
          </div>
        </div>`,
    ).join("");
    emojiPanel.innerHTML =
      `<div class="chat__emoji-tabs">${tabs}</div>` +
      `<div class="chat__emoji-grid" id="emojiGrid">${sections}</div>`;

    for (const btn of emojiPanel.querySelectorAll<HTMLButtonElement>(".chat__emoji")) {
      // mousedown + preventDefault keeps the textarea's focus and caret; the
      // panel deliberately stays open so you can pick several.
      btn.addEventListener("mousedown", (e) => {
        e.preventDefault();
        insertAtCursor(chatInputEl, btn.textContent ?? "");
      });
    }
    const grid = emojiPanel.querySelector<HTMLDivElement>("#emojiGrid")!;
    for (const tab of emojiPanel.querySelectorAll<HTMLButtonElement>(".chat__emoji-tab")) {
      tab.addEventListener("mousedown", (e) => {
        e.preventDefault();
        grid
          .querySelector<HTMLElement>(`.chat__emoji-section[data-cat="${tab.dataset.cat}"]`)
          ?.scrollIntoView({ block: "start" });
      });
    }
  }

  function insertAtCursor(ta: HTMLTextAreaElement, text: string): void {
    const start = ta.selectionStart ?? ta.value.length;
    const end = ta.selectionEnd ?? ta.value.length;
    ta.value = ta.value.slice(0, start) + text + ta.value.slice(end);
    const pos = start + text.length;
    ta.selectionStart = ta.selectionEnd = pos;
    ta.focus();
  }

  async function send(): Promise<void> {
    const text = chatInputEl.value.trim();
    if (!text) return;

    chatErrorEl.textContent = "";
    chatSendEl.disabled = true;
    try {
      const err = activeRoom
        ? await Bridge.sendRoomMessage(activeRoom, text)
        : activeScreenName
          ? await Bridge.sendMessage(activeScreenName, text)
          : "";
      if (err) {
        chatErrorEl.textContent = err;
        return;
      }
      chatInputEl.value = "";
      // Only after the send actually succeeded — a rejected message shouldn't
      // sound like it went out.
      playMessageOut();
      stopTyping();
    } catch (e) {
      chatErrorEl.textContent = String(e);
    } finally {
      chatSendEl.disabled = false;
      chatInputEl.focus();
    }
  }

  function stopTyping(): void {
    window.clearTimeout(stopTypingTimer);
    if (sentTyping && activeScreenName) {
      sentTyping = false;
      void Bridge.setTyping(activeScreenName, false);
    }
  }

  function noteTyping(): void {
    if (!activeScreenName) return;
    if (!sentTyping) {
      sentTyping = true;
      void Bridge.setTyping(activeScreenName, true);
    }
    // Re-arm: we only claim to have stopped once the user actually pauses.
    window.clearTimeout(stopTypingTimer);
    stopTypingTimer = window.setTimeout(stopTyping, TYPING_IDLE_MS);
  }

  // --- Wiring -------------------------------------------------------------

  // Links inside messages (AIM <a href>) must open in the real browser, not
  // navigate the webview away from the app. renderMessageBody marks them with
  // data-ext and only ever emits vetted http/https/mailto/ftp/aim URLs.
  chatLogEl.addEventListener("click", (e) => {
    const link = (e.target as HTMLElement).closest("a[data-ext]");
    if (!link) return;
    e.preventDefault();
    const href = link.getAttribute("href");
    if (href) Bridge.openExternal(href);
  });

  chatSendEl.addEventListener("click", () => void send());

  // The encryption badge opens the safety-number verify dialog for the active DM.
  chatEncEl.addEventListener("click", () => {
    if (activeRoom) {
      void openRoomSecurityDialog(activeRoom);
      return;
    }
    if (!activeScreenName) return;
    // In the "not encrypted" state there's no key and so no safety number to
    // show; explain the situation instead of opening an empty verify dialog.
    if (chatEncEl.classList.contains("chat__enc--plain")) {
      void alertDialog(
        `${activeScreenName}'s client doesn't support end-to-end encryption, so messages ` +
          `in this conversation are sent in the clear — the server can read them.\n\n` +
          `BENCchat encrypts automatically when the other person is also using a client that supports it.`,
        { title: "Not encrypted" },
      );
      return;
    }
    openVerifyDialog(activeScreenName);
  });

  // Emoji picker: toggle on the button, insert on pick, close on outside click.
  buildEmojiPanel();
  emojiBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    emojiPanel.hidden = !emojiPanel.hidden;
    if (!emojiPanel.hidden) chatInputEl.focus();
  });
  document.addEventListener("click", (e) => {
    if (
      !emojiPanel.hidden &&
      e.target !== emojiBtn &&
      !emojiPanel.contains(e.target as Node)
    ) {
      emojiPanel.hidden = true;
    }
    // A click anywhere but inside the row menu closes it (the ⋯ buttons
    // stopPropagation, so they don't self-close).
    if (!menuEl.hidden && !menuEl.contains(e.target as Node)) closeRowMenu();
    // Same for the account menu; its toggle stopPropagations so it doesn't self-close.
    if (!meMenu.hidden && !meMenu.contains(e.target as Node)) closeMeMenu();
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      closeRowMenu();
      closeMeMenu();
    }
  });

  // Expand/collapse the room participant list from the header status.
  chatStatusEl.addEventListener("click", () => toggleParticipants());
  chatInputEl.addEventListener("keydown", (e) => {
    // Enter sends; Shift+Enter is a newline, which is what a chat client should do.
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      void send();
    } else {
      noteTyping();
    }
  });
  // The account menu: name + caret at the top, everything that used to be a row
  // of buttons folded behind it. Away toggles, so its label reflects state; sign
  // off confirms first, because it is the one item here that throws away a live
  // session and a misclick should not.
  const meMenuBtn = el<HTMLButtonElement>("meMenuBtn");
  const meMenu = (() => {
    const m = document.createElement("div");
    m.className = "roster__menu";
    m.hidden = true;
    document.body.appendChild(m);
    return m;
  })();
  function closeMeMenu(): void {
    meMenu.hidden = true;
    meMenu.innerHTML = "";
    meMenuBtn.setAttribute("aria-expanded", "false");
  }
  function openMeMenu(): void {
    const items: MenuItem[] = [
      {
        label: selfAway ? "I'm back (clear away)" : "Set away message…",
        run: async () => {
          if (selfAway) {
            const err = await Bridge.setAway("");
            if (err) await alertDialog(err, { title: "Away" });
            return;
          }
          const msg = await promptDialog("Away message:", "I am away from my computer.", { title: "Set away" });
          if (msg === null) return;
          const err = await Bridge.setAway(msg.trim() || "Away");
          if (err) await alertDialog(err, { title: "Away" });
        },
      },
      {
        label: "Settings…",
        run: () => {
          openSettings((on) => setSoundEnabled(on));
        },
      },
      {
        label: "Sign off",
        danger: true,
        run: async () => {
          if (
            await confirmDialog("Sign off BENCchat? You'll need your password to sign back in.", {
              title: "Sign off",
              okLabel: "Sign off",
            })
          ) {
            void Bridge.signOff().then(onSignOff);
          }
        },
      },
    ];
    meMenu.innerHTML = items
      .map(
        (it, i) =>
          `<button type="button" class="roster__menu-item${it.danger ? " is-danger" : ""}" data-i="${i}">${escapeHTML(it.label)}</button>`,
      )
      .join("");
    meMenu.querySelectorAll<HTMLButtonElement>(".roster__menu-item").forEach((elm, i) => {
      elm.addEventListener("click", () => {
        closeMeMenu();
        void items[i].run();
      });
    });
    meMenu.hidden = false;
    meMenuBtn.setAttribute("aria-expanded", "true");
    // Anchor under the name, left-aligned, clamped on screen.
    const r = meMenuBtn.getBoundingClientRect();
    const left = Math.max(6, Math.min(r.left, window.innerWidth - meMenu.offsetWidth - 6));
    meMenu.style.left = `${left}px`;
    meMenu.style.top = `${Math.min(r.bottom + 4, window.innerHeight - meMenu.offsetHeight - 6)}px`;
  }
  meMenuBtn.addEventListener("click", (e) => {
    e.stopPropagation();
    if (meMenu.hidden) openMeMenu();
    else closeMeMenu();
  });

  el<HTMLButtonElement>("newIM").addEventListener("click", async () => {
    // Being able to message someone not on your list is the point; a nicer
    // picker is cosmetic and can come later.
    const sn = await promptDialog("Send an instant message to which screen name?", "", { title: "New message" });
    if (!sn?.trim()) return;
    void openConversation(sn.trim()).then(renderBuddies);
  });

  el<HTMLButtonElement>("addBuddy").addEventListener("click", () => void addBuddy());
  el<HTMLButtonElement>("findUser").addEventListener("click", () => openFindUser());
  el<HTMLButtonElement>("joinRoom").addEventListener("click", () => void joinRoomPrompt());

  // --- Find user by email ------------------------------------------------

  // Set while the find dialog is open, so a search-result event knows where to
  // render. The server reply doesn't echo the query, so we correlate loosely.
  let onFindResult: ((screenName: string, found: boolean) => void) | null = null;
  let onDirResult: ((entries: DirEntry[], ok: boolean) => void) | null = null;

  function openFindUser(): void {
    const overlay = document.createElement("div");
    overlay.className = "settings-overlay";
    overlay.innerHTML = `
      <div class="settings find">
        <header class="settings__head">
          <h2 class="benco-title settings__title">Find a User</h2>
          <button class="benco-button benco-button--ghost" id="findClose">Done</button>
        </header>
        <hr class="benco-rule" />
        <div class="find__body">
          <div class="find__tabs">
            <button class="find__tab is-active" data-mode="email">By email</button>
            <button class="find__tab" data-mode="name">By name</button>
          </div>

          <div class="find__pane" data-pane="email">
            <p class="benco-caption">Find the account registered to an email address.</p>
            <div class="find__row">
              <input class="benco-input" id="findEmail" type="email" placeholder="name@example.com" spellcheck="false" />
              <button class="benco-button" id="findEmailGo">Search</button>
            </div>
          </div>

          <div class="find__pane" data-pane="name" hidden>
            <p class="benco-caption">Search the member directory by name.</p>
            <div class="find__row">
              <input class="benco-input" id="findFirst" type="text" placeholder="First name" spellcheck="false" />
              <input class="benco-input" id="findLast" type="text" placeholder="Last name" spellcheck="false" />
              <button class="benco-button" id="findNameGo">Search</button>
            </div>
          </div>

          <div class="find__result" id="findResult"></div>
        </div>
      </div>`;
    document.body.appendChild(overlay);

    const emailEl = overlay.querySelector<HTMLInputElement>("#findEmail")!;
    const firstEl = overlay.querySelector<HTMLInputElement>("#findFirst")!;
    const lastEl = overlay.querySelector<HTMLInputElement>("#findLast")!;
    const resultEl = overlay.querySelector<HTMLDivElement>("#findResult")!;
    const close = () => {
      onFindResult = null;
      onDirResult = null;
      overlay.remove();
    };
    overlay.querySelector<HTMLButtonElement>("#findClose")!.addEventListener("click", close);
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) close();
    });

    // Tab switching between the two search modes.
    for (const tab of overlay.querySelectorAll<HTMLButtonElement>(".find__tab")) {
      tab.addEventListener("click", () => {
        for (const t of overlay.querySelectorAll(".find__tab")) t.classList.remove("is-active");
        tab.classList.add("is-active");
        for (const pane of overlay.querySelectorAll<HTMLElement>(".find__pane")) {
          pane.hidden = pane.dataset.pane !== tab.dataset.mode;
        }
        resultEl.innerHTML = "";
      });
    }

    // Renders a result list (one or many), each row actionable. Shared by both
    // search modes; the email match is just a one-row list with no extra detail.
    const renderHits = (entries: DirEntry[]): void => {
      if (entries.length === 0) {
        resultEl.innerHTML = `<span class="find__none">No matches.</span>`;
        return;
      }
      resultEl.innerHTML = entries
        .map((e) => {
          const detail = [
            [e.firstName, e.lastName].filter(Boolean).join(" "),
            [e.city, e.state, e.country].filter(Boolean).join(", "),
          ]
            .filter(Boolean)
            .join(" · ");
          const sn = escapeAttr(e.screenName);
          return `
            <div class="find__hit">
              <div class="find__hit-who">
                <span class="find__name">${escapeHTML(e.screenName)}</span>
                ${detail ? `<span class="find__detail">${escapeHTML(detail)}</span>` : ""}
              </div>
              <button class="benco-button" data-find-msg="${sn}">Message</button>
              <button class="benco-button benco-button--ghost" data-find-add="${sn}">Add</button>
            </div>`;
        })
        .join("");
      for (const btn of resultEl.querySelectorAll<HTMLButtonElement>("[data-find-msg]")) {
        btn.addEventListener("click", () => {
          close();
          void openConversation(btn.dataset.findMsg!);
        });
      }
      for (const btn of resultEl.querySelectorAll<HTMLButtonElement>("[data-find-add]")) {
        btn.addEventListener("click", async () => {
          const name = btn.dataset.findAdd!;
          const err = await Bridge.addBuddy(name, "");
          showToast(err || `Added ${name}.`, err ? "error" : "info");
        });
      }
    };

    const searchEmail = async () => {
      const email = emailEl.value.trim();
      if (!email) return;
      resultEl.textContent = "Searching…";
      onFindResult = (screenName, found) =>
        renderHits(found ? [{ screenName }] : []);
      const err = await Bridge.findUser(email);
      if (err) {
        resultEl.textContent = err;
        onFindResult = null;
      }
    };

    const searchName = async () => {
      const first = firstEl.value.trim();
      const last = lastEl.value.trim();
      if (!first && !last) return;
      resultEl.textContent = "Searching…";
      onDirResult = (entries, ok) => {
        if (!ok) {
          resultEl.innerHTML = `<span class="find__none">Enter a first or last name to search.</span>`;
          return;
        }
        renderHits(entries);
      };
      const err = await Bridge.searchDirectory(first, last);
      if (err) {
        resultEl.textContent = err;
        onDirResult = null;
      }
    };

    overlay.querySelector<HTMLButtonElement>("#findEmailGo")!.addEventListener("click", () => void searchEmail());
    overlay.querySelector<HTMLButtonElement>("#findNameGo")!.addEventListener("click", () => void searchName());
    emailEl.addEventListener("keydown", (e) => {
      if (e.key === "Enter") void searchEmail();
    });
    for (const inp of [firstEl, lastEl]) {
      inp.addEventListener("keydown", (e) => {
        if (e.key === "Enter") void searchName();
      });
    }
    emailEl.focus();
  }

  // openRoomSecurityDialog is where an encrypted room is managed: invite
  // someone, rotate the key, or move the conversation away from whoever is
  // sitting in it unable to read.
  async function openRoomSecurityDialog(cookie: string): Promise<void> {
    const room = rooms.find((r) => r.cookie === cookie);
    if (!room) return;
    let sec: RoomSecurity | null = null;
    try {
      sec = await Bridge.roomSecurityInfo(cookie);
    } catch {
      sec = null;
    }
    if (sec?.encrypted && !sec.readable) {
      void alertDialog(
        "This room is encrypted, but you don't have its key — so you can't read what's " +
          "said here, and BENCchat won't let you send into it (a message would go out in " +
          "the clear, into a room everyone else believes is private).\n\n" +
          "Ask someone already in the room to invite you again.",
        { title: "No key for this room" },
      );
      return;
    }
    if (!sec?.encrypted) {
      void alertDialog(
        "This room isn't encrypted, so everyone in it — and the server — can read what's said.\n\n" +
          "Encryption has to be chosen when a room is created: switching it on later would leave " +
          "everyone already here unable to read anything that follows.",
        { title: "Not encrypted" },
      );
      return;
    }

    const nonReaders = sec.nonReaders ?? [];
    const members = sec.members ?? [];
    const summary =
      `Encrypted room “${room.name}”.\n\n` +
      `Invited and able to read: ${members.length ? members.join(", ") : "nobody yet"}\n` +
      (nonReaders.length
        ? `\n⚠ Present but unable to read: ${nonReaders.join(", ")}\n` +
          `They can still see who is talking and when. There is no way to remove someone from ` +
          `an OSCAR room — moving the conversation to a new room is the only option.\n`
        : "\nEveryone here can read it.\n");

    const action = await choiceDialog(summary, [
      { label: "Invite someone", value: "invite" },
      { label: "Rotate key", value: "rotate" },
      ...(nonReaders.length ? [{ label: "Move to a new room", value: "reform", danger: true }] : []),
    ], { title: "Room encryption" });
    if (action === null) return;

    if (action === "invite") {
      const who = await promptDialog(
        `Who should be able to read “${room.name}”?\n\n` +
          `They'll be sent the key over your encrypted 1:1 conversation, so you must have ` +
          `messaged them before. Once someone has the key it can't be taken back — the only ` +
          `remedy is moving the room.`,
        "",
        { title: "Invite to encrypted room" },
      );
      if (!who || !who.trim()) return;
      const err = await Bridge.inviteToRoom(cookie, who.trim());
      if (err) void alertDialog(err, { title: "Couldn't invite" });
      else void refreshRoomSecurity(room);
      return;
    }

    if (action === "rotate") {
      const ok = await confirmDialog(
        "Give this room a new key?\n\n" +
          "Everyone currently invited gets the new key automatically. Messages already sent stay " +
          "readable to anyone who had the old one — rotating protects what comes next, not what's past.",
        { title: "Rotate key", okLabel: "Rotate" },
      );
      if (!ok) return;
      const err = await Bridge.rotateRoomKey(cookie, []);
      if (err) void alertDialog(err, { title: "Couldn't rotate" });
      return;
    }

    if (action === "reform") {
      const ok = await confirmDialog(
        `Move this conversation to a new room?\n\n` +
          `A fresh room with an unguessable name and a new key. Everyone on the invited list ` +
          `comes along; ${nonReaders.join(", ")} stays behind.\n\n` +
          `They will see everyone leave at once — this is a relocation, not a silent removal.`,
        { title: "Move to a new room", okLabel: "Move", danger: true },
      );
      if (!ok) return;
      wantOpenRoom = true;
      const err = await Bridge.reformRoom(cookie, nonReaders);
      if (err) {
        wantOpenRoom = false;
        void alertDialog(err, { title: "Couldn't move the room" });
      }
      return;
    }
  }

  // openVerifyDialog shows the safety number for a DM so the two people can
  // compare it out of band, and lets the user mark the key verified (or drop a
  // verification). This closes the trust-on-first-use gap: a matching number
  // means no third key was substituted in the middle.
  async function openVerifyDialog(screenName: string): Promise<void> {
    let info: Verification;
    try {
      info = await Bridge.verificationInfo(screenName);
    } catch {
      showToast("Couldn't load verification info.", "error");
      return;
    }
    if (info.status === "unavailable") {
      showToast(
        "No safety number to compare yet — one is derived from both accounts' identities, " +
          "and one of you doesn't have one set up.",
        "info",
      );
      return;
    }

    const overlay = document.createElement("div");
    overlay.className = "settings-overlay";
    const groups = info.safetyNumber
      .split(" ")
      .map((g) => `<span class="verify__group">${escapeHTML(g)}</span>`)
      .join("");
    // Emoji lead, digits follow. Both render the same number, so this is purely
    // about which one someone will actually read out loud on a phone call —
    // and it is not the thirty digits.
    const emoji = info.safetyEmoji
      .map(
        (e) =>
          `<span class="verify__emoji"><span class="verify__emojiGlyph">${escapeHTML(e.emoji)}</span>` +
          `<span class="verify__emojiName">${escapeHTML(e.name)}</span></span>`,
      )
      .join("");
    const close = () => overlay.remove();

    const render = (status: Verification["status"]): void => {
      const changed =
        status === "changed"
          ? `<div class="verify__alert">⚠ This person's key has changed since you last verified it. That's normal if they reinstalled BENCchat — but it can also mean someone is intercepting your messages. Compare the number again before trusting it.</div>`
          : status === "device-added"
            ? `<div class="verify__note">${escapeHTML(screenName)} added a device. Messages are encrypted separately to each of their machines, and the number below is unchanged — it is derived from their account's identity, not from the devices under it, so machines coming and going never move it. You haven't verified this conversation yet, which is the only reason this is mentioned at all.</div>`
            : "";
      const deviceNote =
        info.devices > 1
          ? `<p class="benco-caption">Encrypting to <b>${info.devices}</b> of their devices.</p>`
          : "";
      const verifiedBadge =
        status === "verified"
          ? `<div class="verify__ok">✓ Verified</div>`
          : "";
      const action =
        status === "verified"
          ? `<button class="benco-button benco-button--ghost" id="verUnverify">Remove verification</button>`
          : `<button class="benco-button" id="verMark">Mark as verified</button>`;
      overlay.innerHTML = `
        <div class="settings verify">
          <header class="settings__head">
            <h2 class="benco-title settings__title">Verify ${escapeHTML(screenName)}</h2>
            <button class="benco-button benco-button--ghost" id="verClose">Done</button>
          </header>
          <hr class="benco-rule" />
          <div class="verify__body">
            ${changed}
            ${verifiedBadge}
            <p class="benco-caption">Compare this with ${escapeHTML(screenName)} over a channel you both trust — a phone call, in person, another app. If it matches, your conversation is private end-to-end. If it doesn't, stop.</p>
            ${emoji ? `<div class="verify__emojiGrid">${emoji}</div>` : ""}
            <details class="verify__digits">
              <summary class="benco-caption">Show as numbers instead</summary>
              <div class="verify__number">${groups}</div>
            </details>
            ${deviceNote}
            <div class="verify__actions">
              ${action}
            </div>
          </div>
        </div>`;
      overlay.querySelector<HTMLButtonElement>("#verClose")!.addEventListener("click", close);
      overlay.querySelector<HTMLButtonElement>("#verMark")?.addEventListener("click", async () => {
        const err = await Bridge.markVerified(screenName);
        if (err) {
          showToast(err, "error");
          return;
        }
        showToast(`Marked ${screenName} as verified.`, "info");
        render("verified");
        void refreshEncBadge(screenName);
      });
      overlay.querySelector<HTMLButtonElement>("#verUnverify")?.addEventListener("click", async () => {
        const err = await Bridge.unverify(screenName);
        if (err) {
          showToast(err, "error");
          return;
        }
        render("unverified");
        void refreshEncBadge(screenName);
      });
    };

    render(info.status);
    document.body.appendChild(overlay);
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) close();
    });
  }

  el<HTMLButtonElement>("warnBtn").addEventListener("click", async () => {
    if (!activeScreenName) return;
    // Anonymous vs named changes both the penalty and whether they see it's you.
    // One dialog with three clear choices — including a real Cancel.
    const choice = await choiceDialog(
      `Warn ${activeScreenName}?\n\n“Anonymously” = smaller penalty, they don't see it's you.\n“As yourself” = larger penalty, your name is attached.`,
      [
        { label: "As yourself", value: "named" },
        { label: "Anonymously", value: "anon" },
      ],
      { title: "Warn user" },
    );
    if (choice === null) return;
    const err = await Bridge.warnUser(activeScreenName, choice === "anon");
    if (err) showToast(err, "error");
  });

  // --- Notices: transient toast, durable log ------------------------------

  // A toast is gone in five seconds, which is fine for "message sent" and
  // useless for anything you might want to act on. Every notice is therefore
  // also filed in the system log, where it keeps its timestamp and stays
  // clickable. The log is session-scoped — it's a record of what happened
  // while signed on, not a persisted audit trail.

  const toastEl = el<HTMLDivElement>("toast");
  const logBtnEl = el<HTMLButtonElement>("logBtn");
  const logDotEl = el<HTMLSpanElement>("logDot");
  const logPanelEl = el<HTMLDivElement>("logPanel");
  const logListEl = el<HTMLDivElement>("logList");
  const logClearEl = el<HTMLButtonElement>("logClear");
  const logCopyEl = el<HTMLButtonElement>("logCopy");

  type NoticeLevel = "info" | "warn" | "error";

  interface LogEntry {
    id: number;
    at: Date;
    level: NoticeLevel;
    text: string;
    /** Set when the server sent this; also means `text` is AIM HTML. */
    from?: string;
  }

  /** Oldest entries fall off the end; a chat client left running for days
   *  shouldn't accumulate notices without bound. */
  const LOG_MAX = 200;

  let logEntries: LogEntry[] = [];
  let logSeq = 0;
  let logUnseen = 0;
  let toastTimer: number | undefined;

  function showToast(text: string, level: NoticeLevel, from?: string): void {
    logEntries.unshift({ id: ++logSeq, at: new Date(), level, text, from });
    if (logEntries.length > LOG_MAX) logEntries.length = LOG_MAX;

    if (logPanelEl.hidden) {
      logUnseen++;
      renderLogDot();
    }
    renderLog();

    // Server notices arrive as markup. The toast shows their text only: a link
    // that disappears after five seconds is a tease, and the log keeps the real
    // one. Our own notices are already plain text.
    toastEl.textContent = from ? plainText(text) : text;
    toastEl.className = `roster__toast roster__toast--${level}`;
    toastEl.hidden = false;
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(() => (toastEl.hidden = true), 5000);
  }

  /** Flatten markup to the text a toast can show, without executing anything:
   *  DOMParser builds an inert document, so no script or loader ever runs. */
  function plainText(html: string): string {
    return new DOMParser().parseFromString(html, "text/html").body.textContent ?? "";
  }

  /** One log entry as plain text: timestamp, sender if any, then the message
   *  with any markup flattened. This is what gets copied, so a pasted notice
   *  reads the same as the one on screen rather than as raw HTML. */
  function entryText(e: LogEntry): string {
    const stamp = e.at.toLocaleString();
    const who = e.from ? ` ${e.from}` : "";
    const body = e.from ? plainText(e.text) : e.text;
    return `[${stamp}]${who} ${body}`;
  }

  function renderLogDot(): void {
    logDotEl.hidden = logUnseen === 0;
    logDotEl.textContent = logUnseen > 9 ? "9+" : String(logUnseen);
  }

  function renderLog(): void {
    logListEl.replaceChildren();

    if (logEntries.length === 0) {
      const empty = document.createElement("p");
      empty.className = "benco-caption roster__log-empty";
      empty.textContent = "Nothing yet. Notices land here as they happen.";
      logListEl.appendChild(empty);
      return;
    }

    for (const entry of logEntries) {
      const row = document.createElement("div");
      row.className = `roster__log-entry roster__log-entry--${entry.level}`;

      const meta = document.createElement("div");
      meta.className = "roster__log-meta";

      const time = document.createElement("span");
      time.className = "roster__log-time";
      time.textContent = entry.at.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      });
      meta.appendChild(time);

      if (entry.from) {
        const who = document.createElement("span");
        who.className = "roster__log-from";
        who.textContent = entry.from;
        meta.appendChild(who);
      }

      // Per-entry copy. The body is selectable too (see roster.css), but the
      // markup in a server notice means a hand-selection picks up link text
      // without the URL — this copies the plain text of the whole entry.
      const copy = document.createElement("button");
      copy.className = "roster__log-copy";
      copy.type = "button";
      copy.title = "Copy this notice";
      copy.setAttribute("aria-label", "Copy this notice");
      copy.textContent = "⧉";
      copy.addEventListener("click", async () => {
        const ok = await Bridge.copyText(entryText(entry));
        copy.textContent = ok ? "✓" : "✗";
        window.setTimeout(() => (copy.textContent = "⧉"), 1500);
      });
      meta.appendChild(copy);

      const dismiss = document.createElement("button");
      dismiss.className = "roster__log-x";
      dismiss.type = "button";
      dismiss.title = "Dismiss this notice";
      dismiss.setAttribute("aria-label", "Dismiss this notice");
      dismiss.textContent = "×";
      dismiss.addEventListener("click", () => {
        logEntries = logEntries.filter((x) => x.id !== entry.id);
        renderLog();
      });
      meta.appendChild(dismiss);

      const body = document.createElement("div");
      body.className = "roster__log-body";
      // Server text is markup and goes through the same sanitizer as messages,
      // which is what keeps its links clickable. Ours is plain text, and
      // textContent is the only correct way to place it.
      if (entry.from) body.innerHTML = renderMessageBody(entry.text);
      else body.textContent = entry.text;

      row.append(meta, body);
      logListEl.appendChild(row);
    }
  }

  function setLogOpen(open: boolean): void {
    logPanelEl.hidden = !open;
    logBtnEl.setAttribute("aria-expanded", String(open));
    if (!open) return;
    logUnseen = 0;
    renderLogDot();
    logListEl.scrollTop = 0;
  }

  logBtnEl.addEventListener("click", (e) => {
    e.stopPropagation(); // don't let the close-on-outside-click handler undo this
    setLogOpen(logPanelEl.hidden);
  });

  logClearEl.addEventListener("click", () => {
    logEntries = [];
    renderLog();
  });

  // Oldest first when copying: a log you're pasting for someone else to read
  // should run in the order things happened, even though the panel shows the
  // newest at the top.
  logCopyEl.addEventListener("click", async () => {
    if (logEntries.length === 0) return;
    const text = [...logEntries].reverse().map(entryText).join("\n");
    const ok = await Bridge.copyText(text);
    logCopyEl.textContent = ok ? "Copied" : "Failed";
    window.setTimeout(() => (logCopyEl.textContent = "Copy all"), 2000);
  });

  // Links in server notices open in the real browser, exactly as they do in
  // messages — renderMessageBody vets the URL and marks it data-ext.
  logListEl.addEventListener("click", (e) => {
    const link = (e.target as HTMLElement).closest("a[data-ext]");
    if (!link) return;
    e.preventDefault();
    const href = link.getAttribute("href");
    if (href) Bridge.openExternal(href);
  });

  logPanelEl.addEventListener("click", (e) => e.stopPropagation());

  const closeLogOnOutsideClick = (): void => {
    if (!logPanelEl.hidden) setLogOpen(false);
  };
  const closeLogOnEscape = (e: KeyboardEvent): void => {
    if (e.key === "Escape" && !logPanelEl.hidden) setLogOpen(false);
  };
  document.addEventListener("click", closeLogOnOutsideClick);
  document.addEventListener("keydown", closeLogOnEscape);

  renderLog();

  async function refreshBuddies(): Promise<void> {
    buddies = await Bridge.getBuddies();
    renderBuddies();
    renderChatStatus();
  }

  // Seeds the conversation-derived UI state (off-list partners, unread counts)
  // from whatever threads currently exist — restored local history on sign-on,
  // or a cleared set. Live messages keep these maps current after this; this is
  // the bulk-load path. Assumes buddies are already loaded (for the on-list test).
  async function seedConversations(): Promise<void> {
    const convs = await Bridge.getConversations();
    for (const c of convs) {
      if (!buddies.some((b) => b.key === c.key)) {
        looseConvos.set(c.key, c.screenName);
      }
      if (c.unread > 0) unread.set(c.key, c.unread);
    }
    renderBuddies();
  }

  function handleStateEvent(e: StateEvent): void {
    switch (e.kind) {
      case "buddyListChanged":
        void refreshBuddies();
        break;

      case "buddyChanged":
        if (!e.buddy) break;
        // Patch in place when we already know the buddy; a full refetch would
        // reorder the list under the user's cursor on every presence blip.
        {
          const i = buddies.findIndex((b) => b.key === e.buddy!.key);
          const was = i >= 0 ? buddies[i].presence : "offline";
          if (i >= 0) buddies[i] = e.buddy;
          else void refreshBuddies();
          // Only a genuine offline→online transition is a "sign-on"; arrivals are
          // re-sent for away/idle/icon changes too, which shouldn't chime.
          if (was === "offline" && e.buddy.presence !== "offline") {
            playSignOn();
            // Their profile — and so their E2EE key — is only published while
            // they're online. If we opened this window before they signed on we
            // fetched nothing, and without a re-fetch the lock never appears
            // until the conversation is reopened. Scoped to the conversation
            // we're actually looking at: re-requesting for every buddy in a mass
            // sign-on would walk straight into the server's rate limiter.
            if (e.buddy.key === activeKey && !activeRoom) {
              void Bridge.requestUserInfo(e.buddy.screenName);
            }
          }
          // ...and the mirror case: a genuine online→offline transition.
          else if (was !== "offline" && e.buddy.presence === "offline") playSignOff();
          // If the active buddy just became away and we don't have their text
          // yet, fetch their info so the banner fills in.
          if (
            e.buddy.key === activeKey &&
            e.buddy.presence === "away" &&
            !e.buddy.awayMessage
          ) {
            void Bridge.requestUserInfo(e.buddy.screenName);
          }
          renderBuddies();
          renderChatStatus();
          // A profile refresh may have just taught us this buddy's E2EE key.
          if (e.buddy.key === activeKey && !activeRoom && activeScreenName) {
            void refreshEncBadge(activeScreenName);
          }
        }
        break;

      case "message":
        if (!e.conversation) break;
        // Chime on inbound messages only — never echo our own sends back at us.
        if (e.message && !e.message.outgoing) {
          playMessageIn();
          markTrayNotify();
        }
        // A message from someone not on the buddy list must still surface, or it
        // lands in a thread the UI never offers a way to open.
        if (e.message && !buddies.some((b) => b.key === e.conversation)) {
          const other = e.message.outgoing ? e.message.to : e.message.from;
          looseConvos.set(e.conversation, other);
        }
        if (e.conversation === activeKey && activeScreenName) {
          void Bridge.getConversation(activeScreenName).then((c) => {
            renderMessages(c.messages);
            void Bridge.markRead(activeScreenName!);
          });
        } else if (e.message && !e.message.outgoing) {
          unread.set(e.conversation, (unread.get(e.conversation) ?? 0) + 1);
          renderBuddies();
        }
        break;

      case "typing":
        if (e.conversation === activeKey) {
          chatTypingEl.textContent = e.typing
            ? `${activeScreenName} is typing…`
            : "";
        }
        break;

      case "selfChanged":
        void refreshSelf();
        break;

      case "notice":
        if (e.notice) {
          const level = e.noticeLevel ?? "info";
          if (level === "error" || level === "warn") playAlert();
          showToast(e.notice, level, e.noticeFrom);
        }
        break;

      case "searchResult":
        if (onFindResult) onFindResult(e.screenName ?? "", e.searchFound ?? false);
        break;

      case "directoryResult":
        if (onDirResult) onDirResult(e.directory ?? [], e.directoryOK ?? false);
        break;

      case "conversationsChanged":
        // History was restored (sign-on) or cleared. Rebuild the conversation-
        // derived state from scratch and refresh whatever's on screen.
        unread.clear();
        looseConvos.clear();
        void (async () => {
          await refreshBuddies();
          await seedConversations();
          if (activeScreenName) {
            const c = await Bridge.getConversation(activeScreenName);
            renderMessages(c.messages ?? []);
          }
        })();
        break;

      case "roomChanged":
        // A room was joined, its roster changed, or it was removed (room=null).
        void refreshRooms();
        if (!e.room && e.roomKey === activeRoom) {
          // The active room went away — drop back to the empty state.
          activeRoom = null;
          chatActiveEl.hidden = true;
          chatEmptyEl.hidden = false;
        } else if (e.room && e.roomKey === activeRoom) {
          renderRoomHeader(e.room);
          // The join completes before the room's scrollback is populated, so
          // the header alone isn't enough — without re-rendering the messages
          // the room sits empty until the user switches away and back.
          renderMessages(e.room.messages);
        } else if (e.room && wantOpenRoom && e.roomKey) {
          // The room this user just asked to join — open it once.
          wantOpenRoom = false;
          void openRoom(e.roomKey);
        }
        break;

      case "roomMessage":
        // Badge the tray for room traffic that arrives while we're away. (You
        // can't type into an unfocused window, so this won't fire on our sends.)
        markTrayNotify();
        if (e.roomKey === activeRoom && activeRoom) {
          void Bridge.getRoom(activeRoom).then((r) => renderMessages(r.messages));
        }
        break;
    }
  }

  const meStatusEl = el<HTMLSpanElement>("meStatus");

  async function refreshSelf(): Promise<void> {
    const s = await Bridge.getSelf();
    meNameEl.textContent = s.screenName || "—";
    selfName = s.screenName;
    selfAway = s.presence === "away";
    const bits: string[] = [];
    // The away state has to stay visible somewhere now that the toggle lives in
    // a menu — otherwise you could be away and have nothing on screen say so.
    if (selfAway) bits.push(`Away — ${s.awayMessage ?? ""}`.trim());
    // Warning level is in tenths of a percent; show it when non-zero.
    if (s.warningLevel > 0) bits.push(`⚠ Warning ${Math.round(s.warningLevel / 10)}%`);
    meStatusEl.textContent = bits.join("  ·  ");
    // A quiet cue on the name itself, so "you are away" reads at a glance.
    meMenuBtn.classList.toggle("is-away", selfAway);
  }

  Bridge.onStateEvent(handleStateEvent);

  // An invitation arrives quietly: it lands in the roster's Invitations
  // section with a dot, rather than seizing the screen.
  Bridge.onRoomInvite(() => {
    void renderInvites();
    markTrayNotify();
    playAlert();
  });
  void renderInvites();

  // A connection request arriving is worth the same quiet nudge as a room invite:
  // surface it in its section, dot the tray, play the alert — never seize the screen.
  Bridge.onConnectionRequest(() => {
    void renderConnectionRequests();
    markTrayNotify();
    playAlert();
  });
  // A request we sent was answered (or one we handled): refresh both the request
  // list and the buddy list, since an accept clears a pending buddy.
  Bridge.onConnectionUpdate(() => {
    void renderConnectionRequests();
    void refreshBuddies();
  });
  void renderConnectionRequests();

  void refreshSelf();
  // Load buddies, then seed conversation state so restored local history's
  // off-list threads are openable from the first render.
  void refreshBuddies().then(seedConversations);
  void refreshRooms();

  return {
    destroy() {
      window.clearTimeout(typingTimer);
      window.clearTimeout(stopTypingTimer);
      window.clearTimeout(toastTimer);
      // These two are on `document`, so clearing root would leave them bound to
      // detached nodes and firing for the rest of the process's life.
      document.removeEventListener("click", closeLogOnOutsideClick);
      document.removeEventListener("keydown", closeLogOnEscape);
      root.innerHTML = "";
    },
  };
}

// --- Helpers --------------------------------------------------------------

/**
 * Escapes text for interpolation into HTML.
 *
 * Message text arrives from other users over the network, and AIM-to-AIM
 * messages legitimately carry HTML that the server does not strip. Rendering it
 * raw would let any buddy inject markup — or script — into this window.
 */
function escapeHTML(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function escapeAttr(s: string): string {
  return escapeHTML(s);
}

// Buddy-icon (BART) rendering. Icons are fetched lazily from the Go side as data
// URLs and cached here by their hash, so re-renders (which happen on every
// presence change) reuse the bytes instead of re-fetching. Cache only non-empty
// results: an empty answer means the download hasn't landed yet, and a later
// buddy-changed event will re-render and retry.
const iconCache = new Map<string, string>();

/** The <img> for a buddy's icon: inlined from cache when we have it, otherwise a
 *  hidden placeholder that hydrateIcons fills in after render. Empty when the
 *  buddy has no icon. */
function buddyIconImg(b: Buddy): string {
  if (!b.iconHash) return "";
  const cached = iconCache.get(b.iconHash);
  if (cached) return `<img class="roster__icon" src="${escapeAttr(cached)}" alt="" />`;
  return `<img class="roster__icon" data-icon-sn="${escapeAttr(b.screenName)}" data-icon-hash="${escapeAttr(b.iconHash)}" alt="" hidden />`;
}

/** Fill in any placeholder icon images under root by asking the Go side for the
 *  bytes. Missing bytes (still downloading) are left for a later re-render. */
async function hydrateIcons(root: HTMLElement): Promise<void> {
  const imgs = root.querySelectorAll<HTMLImageElement>("img.roster__icon[data-icon-sn]");
  for (const img of imgs) {
    const hash = img.dataset.iconHash ?? "";
    const cached = iconCache.get(hash);
    if (cached) {
      img.src = cached;
      img.hidden = false;
      continue;
    }
    const url = await Bridge.getBuddyIcon(img.dataset.iconSn ?? "");
    if (url) {
      iconCache.set(hash, url);
      img.src = url;
      img.hidden = false;
    }
  }
}

function formatTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}
