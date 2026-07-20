// bridge.ts — the only file that knows about Wails' injected globals.
//
// Wails binds Go methods under window.go.main.App.* (each returns a Promise)
// and exposes an event bus under window.runtime.*. We access those globals
// through thin typed wrappers so the rest of the UI depends on a small, stable
// surface rather than on Wails internals — and so the app still loads even
// before the generated ./wailsjs bindings exist.

export interface ServerSettings {
  host: string;
  port: number;
  lastScreenName: string;
  remembered: boolean;
  /** Connections use TLS. */
  tls: boolean;
  /** Certificate verification is disabled — testing only. */
  tlsInsecure: boolean;
}

/** Sign-on lifecycle state. Mirrors app.go's SessionStatus. */
export type SessionState = "signing-on" | "online" | "offline" | "error";

export interface SessionStatus {
  state: SessionState;
  message: string;
  server: string;
}

export type Presence = "offline" | "online" | "away" | "idle";

export interface Buddy {
  screenName: string;
  key: string;
  group: string;
  alias?: string;
  presence: Presence;
  awayMessage?: string;
  profile?: string;
  blocked?: boolean;
  /** Hex MD5 of the buddy's icon (BART), empty/absent if none. Changes when the
   *  buddy swaps icons; the image itself is fetched via Bridge.getBuddyIcon. */
  iconHash?: string;
  /** Their client advertised support for encrypted IM. */
  e2eeCapable?: boolean;
  /** Their client advertised any capabilities at all. Without this, a missing
   *  e2eeCapable means "hasn't said", not "can't encrypt". */
  capsKnown?: boolean;
  idleSince: string;
  signedOnAt: string;
}

export interface Message {
  from: string;
  to: string;
  text: string;
  at: string;
  outgoing?: boolean;
  autoResponse?: boolean;
  /** True when this message was end-to-end encrypted on the wire. */
  encrypted?: boolean;
  /** Room message whose signature verified as the claimed sender's. */
  senderVerified?: boolean;
  /** Room message whose signature did NOT verify — someone in the room is
   *  putting words in another member's mouth. */
  forged?: boolean;
}

export interface Room {
  cookie: string;
  name: string;
  /** True while joined (live connection); false for a re-joinable recent. */
  joined: boolean;
  participants: string[];
  messages: Message[];
}

export interface Conversation {
  key: string;
  screenName: string;
  messages: Message[];
  unread: number;
}

export interface Self {
  screenName: string;
  presence: Presence;
  awayMessage?: string;
  warningLevel: number;
}

export interface Theme {
  name?: string;
  tokens?: Record<string, string>;
}

/** Safety-number verification state of a 1:1 conversation. Mirrors app.Verification. */
/** One position in the emoji rendering of a safety number. The name is what
 *  gets read aloud, and the fallback wherever a font has no glyph. */
export interface SafetyEmoji {
  emoji: string;
  name: string;
}

export interface Verification {
  safetyNumber: string;
  /** The SAME code as safetyNumber, rendered as emoji — not a second, weaker
   *  thing to check. Matching either proves the same fact. Empty when there is
   *  nothing to compare yet. */
  safetyEmoji: SafetyEmoji[];
  /** "device-added" is a key set that GREW — they set up another machine —
   *  which is expected, unlike "changed" where a key we relied on is gone. */
  status: "unavailable" | "unverified" | "verified" | "changed" | "device-added";
  /** How many devices the peer publishes keys for. */
  devices: number;
}

/** An invitation waiting for a decision. */
export interface RoomInviteInfo {
  room: string;
  from: string;
}

/** Encryption state of a chat room. Mirrors app.RoomSecurity. */
export interface RoomSecurity {
  encrypted: boolean;
  /** We hold a usable key. False for an encrypted room we can't read — after a
   *  restart, or before an invitation is accepted. */
  readable: boolean;
  /** Participants whose client advertises no encryption support — present but
   *  unable to read. Detected from capabilities, so absence is reliable and
   *  presence is only suggestive. */
  nonReaders: string[] | null;
  /** People we deliberately gave the key to. */
  members: string[] | null;
}

/** One machine signed in to this account with its own encryption key. */
export interface DeviceInfo {
  key: string;
  fingerprint: string;
  thisDevice: boolean;
}

/** Whether THIS device is still waiting to be approved from another one.
 *  `fingerprint` is this device's own code, which the approving machine shows
 *  and asks the user to compare against. */
export interface DeviceLinkState {
  pending: boolean;
  fingerprint: string;
}

export interface Preferences {
  theme: Theme;
  soundEnabled: boolean;
  soundPack: string;
  mutedSounds: string[] | null;
  historyEnabled: boolean;
  historyRetentionDays: number;
  e2eeEnabled: boolean;
  profile: string;
  customFrame: boolean;
}

/** Event kinds emitted by the Go state store. Mirrors state.Event* constants. */
export type StateEventKind =
  | "buddyListChanged"
  | "buddyChanged"
  | "message"
  | "selfChanged"
  | "typing"
  | "notice"
  | "searchResult"
  | "directoryResult"
  | "conversationsChanged"
  | "roomChanged"
  | "roomMessage"
  | "disconnected";

/** One user-directory (ODir) search match. */
export interface DirEntry {
  screenName: string;
  firstName?: string;
  lastName?: string;
  city?: string;
  state?: string;
  country?: string;
}

export interface StateEvent {
  kind: StateEventKind;
  buddy?: Buddy;
  message?: Message;
  conversation?: string;
  typing?: boolean;
  screenName?: string;
  notice?: string;
  noticeLevel?: "info" | "warn" | "error";
  /** Reserved server screen name a notice came from; empty for our own
   *  notices. Its presence also means `notice` holds AIM HTML, not plain text. */
  noticeFrom?: string;
  searchQuery?: string;
  searchFound?: boolean;
  directory?: DirEntry[];
  directoryOK?: boolean;
  room?: Room;
  roomKey?: string;
}

interface AppBindings {
  GetServerSettings(): Promise<ServerSettings>;
  SaveServerSettings(host: string, port: number): Promise<string>;
  SetTLS(on: boolean, insecure: boolean): Promise<string>;
  ConnectionSecure(): Promise<boolean>;
  SignIn(screenName: string, password: string, remember: boolean): Promise<string>;
  AutoSignIn(): Promise<void>;
  SignOff(): Promise<void>;
  SignedOn(): Promise<boolean>;
  GetSelf(): Promise<Self>;
  GetBuddies(): Promise<Buddy[]>;
  GetBuddyIcon(screenName: string): Promise<string>;
  GetGroups(): Promise<string[]>;
  GetConversation(screenName: string): Promise<Conversation>;
  GetConversations(): Promise<Conversation[]>;
  SendMessage(to: string, text: string): Promise<string>;
  SetTyping(to: string, typing: boolean): Promise<void>;
  MarkRead(screenName: string): Promise<void>;
  CloseConversation(screenName: string): Promise<void>;
  AddBuddy(screenName: string, group: string): Promise<string>;
  RemoveBuddy(screenName: string): Promise<string>;
  RenameBuddy(screenName: string, alias: string): Promise<string>;
  BlockBuddy(screenName: string): Promise<string>;
  UnblockBuddy(screenName: string): Promise<string>;
  SetAway(message: string): Promise<string>;
  RequestAwayMessage(screenName: string): Promise<void>;
  RequestUserInfo(screenName: string): Promise<void>;
  SetProfile(text: string): Promise<string>;
  WarnUser(screenName: string, anonymous: boolean): Promise<string>;
  FindUser(email: string): Promise<string>;
  SearchDirectory(firstName: string, lastName: string): Promise<string>;
  JoinRoom(name: string): Promise<string>;
  CreateEncryptedRoom(name: string): Promise<string>;
  RoomSecurityInfo(cookie: string): Promise<RoomSecurity>;
  InviteToRoom(cookie: string, screenName: string): Promise<string>;
  PendingRoomInvites(): Promise<RoomInviteInfo[] | null>;
  AcceptRoomInvite(roomName: string): Promise<string>;
  DeclineRoomInvite(roomName: string): Promise<void>;
  RotateRoomKey(cookie: string, drop: string[]): Promise<string>;
  ReformRoom(cookie: string, drop: string[]): Promise<string>;
  LeaveRoom(cookie: string): Promise<void>;
  ForgetRoom(cookie: string): Promise<void>;
  SendRoomMessage(cookie: string, text: string): Promise<string>;
  GetRooms(): Promise<Room[]>;
  GetRoom(cookie: string): Promise<Room>;
  ChangePassword(oldPassword: string, newPassword: string): Promise<string>;
  ChangeEmail(email: string): Promise<string>;
  GetPreferences(): Promise<Preferences>;
  SaveTheme(name: string, tokens: Record<string, string>): Promise<string>;
  SetSoundEnabled(enabled: boolean): Promise<string>;
  SetSoundPack(name: string): Promise<string>;
  SetSoundMuted(key: string, muted: boolean): Promise<string>;
  ListDevices(): Promise<DeviceInfo[] | null>;
  RemoveDevice(key: string): Promise<string>;
  ApproveDevice(key: string): Promise<string>;
  ApproveDeviceByCode(code: string): Promise<string>;
  DeclineDevice(key: string): Promise<string>;
  GetDeviceLinkState(): Promise<DeviceLinkState>;
  SetCustomSound(key: string, data: string): Promise<string>;
  GetCustomSounds(): Promise<Record<string, string>>;
  ClearCustomSound(key: string): Promise<string>;
  ClearCustomSounds(): Promise<string>;
  SetHistoryEnabled(enabled: boolean): Promise<string>;
  SetHistoryRetention(days: number): Promise<string>;
  ClearHistory(): Promise<string>;
  SetE2EEEnabled(on: boolean): Promise<string>;
  SetTrayNotify(on: boolean): Promise<void>;
  ConversationEncrypted(screenName: string): Promise<boolean>;
  VerificationInfo(screenName: string): Promise<Verification>;
  MarkVerified(screenName: string): Promise<string>;
  Unverify(screenName: string): Promise<string>;
  SetCustomFrame(on: boolean): Promise<string>;
  MinimizeWindow(): Promise<void>;
  ToggleMaximiseWindow(): Promise<void>;
  CloseWindow(): Promise<void>;
}

interface WailsRuntime {
  EventsOn(event: string, cb: (data: unknown) => void): void;
  BrowserOpenURL(url: string): void;
  ClipboardSetText(text: string): Promise<boolean>;
}

declare global {
  interface Window {
    go?: { main?: { App?: AppBindings } };
    runtime?: WailsRuntime;
  }
}

function app(): AppBindings {
  const a = window.go?.main?.App;
  if (!a) {
    throw new Error("Wails bindings unavailable (window.go.main.App is missing)");
  }
  return a;
}

export const Bridge = {
  getServerSettings: () => app().GetServerSettings(),
  saveServerSettings: (host: string, port: number) =>
    app().SaveServerSettings(host, port),
  signIn: (screenName: string, password: string, remember: boolean) =>
    app().SignIn(screenName, password, remember),
  autoSignIn: () => app().AutoSignIn(),
  signOff: () => app().SignOff(),
  signedOn: () => app().SignedOn(),

  getSelf: () => app().GetSelf(),
  getBuddies: () => app().GetBuddies(),
  getBuddyIcon: (screenName: string) => app().GetBuddyIcon(screenName),
  getGroups: () => app().GetGroups(),
  getConversation: (screenName: string) => app().GetConversation(screenName),
  getConversations: () => app().GetConversations(),
  sendMessage: (to: string, text: string) => app().SendMessage(to, text),
  setTyping: (to: string, typing: boolean) => app().SetTyping(to, typing),
  markRead: (screenName: string) => app().MarkRead(screenName),
  closeConversation: (screenName: string) => app().CloseConversation(screenName),
  addBuddy: (screenName: string, group: string) =>
    app().AddBuddy(screenName, group),
  removeBuddy: (screenName: string) => app().RemoveBuddy(screenName),
  renameBuddy: (screenName: string, alias: string) =>
    app().RenameBuddy(screenName, alias),
  blockBuddy: (screenName: string) => app().BlockBuddy(screenName),
  unblockBuddy: (screenName: string) => app().UnblockBuddy(screenName),
  setAway: (message: string) => app().SetAway(message),
  requestAwayMessage: (screenName: string) => app().RequestAwayMessage(screenName),
  requestUserInfo: (screenName: string) => app().RequestUserInfo(screenName),
  setProfile: (text: string) => app().SetProfile(text),
  warnUser: (screenName: string, anonymous: boolean) =>
    app().WarnUser(screenName, anonymous),
  findUser: (email: string) => app().FindUser(email),
  searchDirectory: (firstName: string, lastName: string) =>
    app().SearchDirectory(firstName, lastName),
  joinRoom: (name: string) => app().JoinRoom(name),
  createEncryptedRoom: (name: string) => app().CreateEncryptedRoom(name),
  roomSecurityInfo: (cookie: string) => app().RoomSecurityInfo(cookie),
  inviteToRoom: (cookie: string, screenName: string) => app().InviteToRoom(cookie, screenName),
  pendingRoomInvites: () => app().PendingRoomInvites(),
  acceptRoomInvite: (room: string) => app().AcceptRoomInvite(room),
  declineRoomInvite: (room: string) => app().DeclineRoomInvite(room),
  rotateRoomKey: (cookie: string, drop: string[]) => app().RotateRoomKey(cookie, drop),
  reformRoom: (cookie: string, drop: string[]) => app().ReformRoom(cookie, drop),

  /** Someone shared an encrypted room's key with us. */
  onRoomInvite(cb: (req: { from: string; room: string }) => void): void {
    window.runtime?.EventsOn("room:invite", (data) =>
      cb(data as { from: string; room: string }),
    );
  },
  leaveRoom: (cookie: string) => app().LeaveRoom(cookie),
  forgetRoom: (cookie: string) => app().ForgetRoom(cookie),
  sendRoomMessage: (cookie: string, text: string) =>
    app().SendRoomMessage(cookie, text),
  getRooms: () => app().GetRooms(),
  getRoom: (cookie: string) => app().GetRoom(cookie),
  changePassword: (oldPassword: string, newPassword: string) =>
    app().ChangePassword(oldPassword, newPassword),
  changeEmail: (email: string) => app().ChangeEmail(email),

  getPreferences: () => app().GetPreferences(),
  saveTheme: (name: string, tokens: Record<string, string>) =>
    app().SaveTheme(name, tokens),
  setSoundEnabled: (enabled: boolean) => app().SetSoundEnabled(enabled),
  setSoundPack: (name: string) => app().SetSoundPack(name),
  setSoundMuted: (key: string, muted: boolean) => app().SetSoundMuted(key, muted),
  setTLS: (on: boolean, insecure: boolean) => app().SetTLS(on, insecure),
  connectionSecure: () => app().ConnectionSecure(),
  listDevices: () => app().ListDevices(),
  removeDevice: (key: string) => app().RemoveDevice(key),
  approveDevice: (key: string) => app().ApproveDevice(key),
  approveDeviceByCode: (code: string) => app().ApproveDeviceByCode(code),
  declineDevice: (key: string) => app().DeclineDevice(key),
  getDeviceLinkState: () => app().GetDeviceLinkState(),

  /** A new machine on this account is asking to be linked. */
  onDeviceLinkState(cb: (s: DeviceLinkState) => void): void {
    window.runtime?.EventsOn("device:link-state", (data) => cb(data as DeviceLinkState));
  },

  onDeviceLinkRequest(
    cb: (req: { key: string; fingerprint: string; returning?: string }) => void,
  ): void {
    window.runtime?.EventsOn("device:link-request", (data) =>
      cb(data as { key: string; fingerprint: string; returning?: string }),
    );
  },
  setCustomSound: (key: string, data: string) => app().SetCustomSound(key, data),
  getCustomSounds: () => app().GetCustomSounds(),
  clearCustomSound: (key: string) => app().ClearCustomSound(key),
  clearCustomSounds: () => app().ClearCustomSounds(),
  setHistoryEnabled: (enabled: boolean) => app().SetHistoryEnabled(enabled),
  setHistoryRetention: (days: number) => app().SetHistoryRetention(days),
  clearHistory: () => app().ClearHistory(),
  setE2EEEnabled: (on: boolean) => app().SetE2EEEnabled(on),
  setTrayNotify: (on: boolean) => app().SetTrayNotify(on),
  conversationEncrypted: (screenName: string) =>
    app().ConversationEncrypted(screenName),
  verificationInfo: (screenName: string) => app().VerificationInfo(screenName),
  markVerified: (screenName: string) => app().MarkVerified(screenName),
  unverify: (screenName: string) => app().Unverify(screenName),
  setCustomFrame: (on: boolean) => app().SetCustomFrame(on),
  minimizeWindow: () => app().MinimizeWindow(),
  toggleMaximiseWindow: () => app().ToggleMaximiseWindow(),
  closeWindow: () => app().CloseWindow(),

  onSessionStatus(cb: (status: SessionStatus) => void): void {
    window.runtime?.EventsOn("session:status", (data) =>
      cb(data as SessionStatus),
    );
  },

  onStateEvent(cb: (event: StateEvent) => void): void {
    window.runtime?.EventsOn("state:event", (data) => cb(data as StateEvent));
  },

  /** Open a URL in the user's real browser instead of navigating the webview
   *  (which would replace the whole app). Used for links inside messages. */
  openExternal(url: string): void {
    window.runtime?.BrowserOpenURL(url);
  },

  /** Copies text to the system clipboard.
   *
   *  Goes through the Wails runtime rather than navigator.clipboard: the
   *  latter needs a secure context and a permission the webview doesn't grant
   *  under the wails:// scheme, so it fails silently. Falls back to a hidden
   *  textarea + execCommand for the dev-server case, where window.runtime is
   *  the stub and not the real thing. */
  async copyText(text: string): Promise<boolean> {
    if (window.runtime?.ClipboardSetText) {
      try {
        return await window.runtime.ClipboardSetText(text);
      } catch {
        /* fall through */
      }
    }
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand("copy");
      ta.remove();
      return ok;
    } catch {
      return false;
    }
  },
};

/**
 * Normalizes a screen name the way OSCAR does: case- and space-insensitive.
 * Must match state.NormalizeScreenName in Go — the keys crossing the bridge are
 * produced there, and a mismatch would silently fail to find conversations.
 */
export function normalizeScreenName(sn: string): string {
  return sn.replace(/ /g, "").toLowerCase();
}
