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
  /** This client's version and short commit, e.g. "dev (a1b2c3d)". Shown on the
   *  sign-on screen so a stale build is visible before it fails cryptically. */
  build: string;
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
  /** We added them but they haven't accepted the connection yet — presence and
   *  messaging stay gated until they do. */
  pending?: boolean;
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
  signed?: boolean;
  /** Room message whose signature did NOT verify — someone in the room is
   *  putting words in another member's mouth. */
  forged?: boolean;
  /** Outgoing message the server never accepted — rejected, or silently dropped
   *  (which is what hitting a rate limit looks like). It's still in your local
   *  history, so it has to be visibly marked or it reads as delivered. */
  notSent?: boolean;
  /** Identifies an outgoing message, so a failed one can be resent. */
  id?: string;
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
  /** Closed by the user: kept for its history but omitted from the list until
   *  reopened. Set with omitempty on the Go side, so absent means visible. */
  hidden?: boolean;
}

export interface Self {
  screenName: string;
  presence: Presence;
  awayMessage?: string;
  warningLevel: number;
}

/** A one-shot profile lookup, for previewing a connection requester. Empty
 *  fields mean nothing was set or nothing arrived in time. */
export interface ProfilePreview {
  screenName: string;
  profile: string;
  away: string;
}

/** A buddy group and how many buddies are filed under it. */
export interface GroupInfo {
  name: string;
  count: number;
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
  /** "device-added" means never-verified AND their device set grew — they set
   *  up another machine. It does NOT mean the safety number moved: that is
   *  derived from account identities, so devices coming and going never touch
   *  it. Only "changed" is an identity that is not the one we verified. */
  status: "unavailable" | "unverified" | "verified" | "changed" | "device-added";
  /** How many devices the peer publishes keys for. */
  devices: number;
}

/** An invitation waiting for a decision. */
export interface RoomInviteInfo {
  room: string;
  from: string;
}

/** An incoming request to connect. Mirrors app.ConnectionRequestInfo. */
export interface ConnectionRequestInfo {
  screenName: string;
  reason: string;
}

/** Another device on this account, as a transfer can be addressed to it.
 *  Mirrors app.TransferTarget. */
export interface TransferTarget {
  /** The device's signing key ID — what names it in a bundle. */
  id: string;
  /** How it appears in a list. Derived from the ID; a manifest carries no
   *  nickname. */
  label: string;
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
  /** Who may remove people. Only the owner's removals are honoured, so the
   *  control belongs to them alone — offering it to anyone else produces a
   *  refusal, not a removal. */
  owner: string;
}

/** One machine signed in to this account with its own encryption key. */
export interface DeviceInfo {
  key: string;
  fingerprint: string;
  thisDevice: boolean;
}

/** Which account-identity flow this device is in. Mirrors app.IdentityState. */
export interface IdentityState {
  /** "unavailable" — not signed on, encryption off, or no key directory.
   *  "setup"       — no identity exists: first run, show the recovery key.
   *  "link"        — an identity exists but this device is not in it.
   *  "ready"       — this device is signed into the account's manifest. */
  flow: "unavailable" | "setup" | "link" | "ready";
  /** This device's own short code. */
  fingerprint: string;
  /** How many machines the current manifest names. */
  devices: number;
  /** When the current manifest was signed, Unix seconds UTC, or 0. Advisory
   *  only — nothing rejects a manifest for being old. */
  issuedAt: number;
  /** How many words a recovery key has, so copy can say the right number. */
  recoveryWords: number;
}

/** The one and only showing of a recovery key. Mirrors app.RecoveryKeyInfo.
 *
 *  `recoveryKey` cannot be re-fetched: nothing retains it, so there is nothing
 *  to ask for again. That is a property of the design, not a policy this file
 *  enforces. */
export interface RecoveryKeyInfo {
  recoveryKey: string;
  error: string;
}

/** The passive Settings line from proposal §13. Mirrors app.RecoveryKeyStatus.
 *
 *  Nothing in the app reacts to this on its own. It has no timer, no badge and
 *  no notice behind it — it is read when Settings is opened and at no other
 *  time, because an alert that fires when nothing is wrong is one people learn
 *  to dismiss. */
export interface RecoveryKeyStatus {
  /** Whether there is a key to report on: signed on, a key directory, and an
   *  identity backup that exists. */
  available: boolean;
  /** When the key in force was made, Unix seconds UTC, or 0 for "not known on
   *  this computer" — the normal state of a device that was linked rather than
   *  set up. Show "unknown", never a guess. */
  created: number;
  /** Last time THIS device watched the key open the backup, or 0 for never.
   *  Only a real decryption sets it; there is no "yes I still have it" button
   *  anywhere, because that would record a date meaning nothing. */
  lastVerified: number;
  /** Why `available` is false, when that is a failure rather than an answer. */
  error: string;
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
  /** Preferred emoji skin tone: 0 = neutral yellow default, 1–5 = Fitzpatrick. */
  skinTone: number;
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
  | "roomMessage";

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
  SignIn(screenName: string, password: string, remember: boolean): Promise<string>;
  AutoSignIn(): Promise<void>;
  SignOff(): Promise<void>;
  SignedOn(): Promise<boolean>;
  GetSelf(): Promise<Self>;
  GetBuddies(): Promise<Buddy[]>;
  GetBuddyIcon(screenName: string): Promise<string>;
  GetConversation(screenName: string): Promise<Conversation>;
  GetConversations(): Promise<Conversation[]>;
  SendMessage(to: string, text: string): Promise<string>;
  ResendMessage(screenName: string, id: string): Promise<string>;
  SetTyping(to: string, typing: boolean): Promise<void>;
  MarkRead(screenName: string): Promise<void>;
  CloseConversation(screenName: string): Promise<void>;
  ReopenConversation(screenName: string): Promise<void>;
  AddBuddy(screenName: string, group: string): Promise<string>;
  RemoveBuddy(screenName: string): Promise<string>;
  RenameBuddy(screenName: string, alias: string): Promise<string>;
  MoveBuddy(screenName: string, group: string): Promise<string>;
  BlockBuddy(screenName: string): Promise<string>;
  UnblockBuddy(screenName: string): Promise<string>;
  BlockedUsers(): Promise<string[]>;
  Groups(): Promise<GroupInfo[]>;
  RenameGroup(oldName: string, newName: string): Promise<string>;
  DeleteGroup(name: string): Promise<string>;
  ClearConversation(screenName: string): Promise<void>;
  SetAway(message: string): Promise<string>;
  RequestUserInfo(screenName: string): Promise<void>;
  LookupProfile(screenName: string): Promise<ProfilePreview>;
  SetProfile(text: string): Promise<string>;
  WarnUser(screenName: string, anonymous: boolean): Promise<string>;
  FindUser(email: string): Promise<string>;
  SearchDirectory(firstName: string, lastName: string): Promise<string>;
  JoinRoom(name: string): Promise<string>;
  CreateEncryptedRoom(name: string): Promise<string>;
  RoomSecurityInfo(cookie: string): Promise<RoomSecurity>;
  InviteToRoom(cookie: string, screenName: string): Promise<string>;
  PendingRoomInvites(): Promise<RoomInviteInfo[] | null>;
  PendingConnectionRequests(): Promise<ConnectionRequestInfo[] | null>;
  ApproveConnectionRequest(screenName: string): Promise<string>;
  DeclineConnectionRequest(screenName: string): Promise<string>;
  AcceptRoomInvite(roomName: string): Promise<string>;
  DeclineRoomInvite(roomName: string): Promise<void>;
  RotateRoomKey(cookie: string, drop: string[]): Promise<string>;
  TransferTargets(): Promise<TransferTarget[] | null>;
  ExportDeviceTransfer(recipientID: string, path: string): Promise<string>;
  ImportDeviceTransfer(path: string): Promise<string>;
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
  SetSkinTone(tone: number): Promise<string>;
  SetSoundEnabled(enabled: boolean): Promise<string>;
  SetSoundPack(name: string): Promise<string>;
  SetSoundMuted(key: string, muted: boolean): Promise<string>;
  ListDevices(): Promise<DeviceInfo[] | null>;
  RemoveDevice(key: string, recoveryKey: string): Promise<string>;
  GetIdentityState(): Promise<IdentityState>;
  BeginIdentitySetup(): Promise<RecoveryKeyInfo>;
  ConfirmIdentitySetup(): Promise<string>;
  CancelIdentitySetup(): Promise<void>;
  SaveRecoveryKeyToFile(): Promise<string>;
  LinkDevice(recoveryKey: string): Promise<string>;
  BeginRecoveryKeyRotation(current: string): Promise<RecoveryKeyInfo>;
  ConfirmRecoveryKeyRotation(): Promise<string>;
  CancelRecoveryKeyRotation(): Promise<void>;
  GetRecoveryKeyStatus(): Promise<RecoveryKeyStatus>;
  VerifyRecoveryKey(recoveryKey: string): Promise<string>;
  SetCustomSound(key: string, data: string): Promise<string>;
  GetCustomSounds(): Promise<Record<string, string>>;
  ClearCustomSound(key: string): Promise<string>;
  SetHistoryEnabled(enabled: boolean): Promise<string>;
  SetHistoryRetention(days: number): Promise<string>;
  ClearHistory(): Promise<string>;
  SetTrayNotify(on: boolean): Promise<void>;
  ConversationEncrypted(screenName: string): Promise<boolean>;
  PrepareConversation(screenName: string): Promise<boolean>;
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
  getConversation: (screenName: string) => app().GetConversation(screenName),
  getConversations: () => app().GetConversations(),
  sendMessage: (to: string, text: string) => app().SendMessage(to, text),
  resendMessage: (screenName: string, id: string) => app().ResendMessage(screenName, id),
  setTyping: (to: string, typing: boolean) => app().SetTyping(to, typing),
  markRead: (screenName: string) => app().MarkRead(screenName),
  closeConversation: (screenName: string) => app().CloseConversation(screenName),
  reopenConversation: (screenName: string) => app().ReopenConversation(screenName),
  clearConversation: (screenName: string) => app().ClearConversation(screenName),
  addBuddy: (screenName: string, group: string) =>
    app().AddBuddy(screenName, group),
  removeBuddy: (screenName: string) => app().RemoveBuddy(screenName),
  renameBuddy: (screenName: string, alias: string) =>
    app().RenameBuddy(screenName, alias),
  moveBuddy: (screenName: string, group: string) =>
    app().MoveBuddy(screenName, group),
  blockBuddy: (screenName: string) => app().BlockBuddy(screenName),
  unblockBuddy: (screenName: string) => app().UnblockBuddy(screenName),
  blockedUsers: () => app().BlockedUsers(),
  groups: () => app().Groups(),
  renameGroup: (oldName: string, newName: string) => app().RenameGroup(oldName, newName),
  deleteGroup: (name: string) => app().DeleteGroup(name),
  lookupProfile: (screenName: string) => app().LookupProfile(screenName),
  setAway: (message: string) => app().SetAway(message),
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
  transferTargets: () => app().TransferTargets(),
  exportDeviceTransfer: (recipientID: string, path: string) =>
    app().ExportDeviceTransfer(recipientID, path),
  importDeviceTransfer: (path: string) => app().ImportDeviceTransfer(path),
  reformRoom: (cookie: string, drop: string[]) => app().ReformRoom(cookie, drop),

  /** Someone shared an encrypted room's key with us. */
  onRoomInvite(cb: (req: { from: string; room: string }) => void): void {
    window.runtime?.EventsOn("room:invite", (data) =>
      cb(data as { from: string; room: string }),
    );
  },

  pendingConnectionRequests: () => app().PendingConnectionRequests(),
  approveConnectionRequest: (screenName: string) => app().ApproveConnectionRequest(screenName),
  declineConnectionRequest: (screenName: string) => app().DeclineConnectionRequest(screenName),
  /** Someone wants to connect (add you). */
  onConnectionRequest(cb: (req: ConnectionRequestInfo) => void): void {
    window.runtime?.EventsOn("connection:request", (data) =>
      cb(data as ConnectionRequestInfo),
    );
  },
  /** A request we sent, or one we're handling, changed state. */
  onConnectionUpdate(cb: (u: { screenName: string; accepted?: boolean; handled?: boolean }) => void): void {
    window.runtime?.EventsOn("connection:update", (data) =>
      cb(data as { screenName: string; accepted?: boolean; handled?: boolean }),
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
  setSkinTone: (tone: number) => app().SetSkinTone(tone),
  saveTheme: (name: string, tokens: Record<string, string>) =>
    app().SaveTheme(name, tokens),
  setSoundEnabled: (enabled: boolean) => app().SetSoundEnabled(enabled),
  setSoundPack: (name: string) => app().SetSoundPack(name),
  setSoundMuted: (key: string, muted: boolean) => app().SetSoundMuted(key, muted),
  listDevices: () => app().ListDevices(),
  /** Removing a device rewrites the account's signed device list, so it costs
   *  the recovery key — the same key linking one costs. */
  removeDevice: (key: string, recoveryKey: string) => app().RemoveDevice(key, recoveryKey),

  getIdentityState: () => app().GetIdentityState(),
  /** Generates an identity and a recovery key IN MEMORY. Writes nothing, on the
   *  server or on disk — that is what makes a crash before the user has the key
   *  harmless. Persistence happens in confirmIdentitySetup and nowhere else. */
  beginIdentitySetup: () => app().BeginIdentitySetup(),
  confirmIdentitySetup: () => app().ConfirmIdentitySetup(),
  cancelIdentitySetup: () => app().CancelIdentitySetup(),
  saveRecoveryKeyToFile: () => app().SaveRecoveryKeyToFile(),
  linkDevice: (recoveryKey: string) => app().LinkDevice(recoveryKey),

  /** Proves possession of the CURRENT recovery key and mints a replacement, in
   *  memory. Nothing is stored: until confirmRecoveryKeyRotation the server
   *  still holds the blob the current key opens, which is what makes abandoning
   *  this — or crashing — free. Same shape as the first-run pair, and the same
   *  reason for the split. */
  beginRecoveryKeyRotation: (current: string) => app().BeginRecoveryKeyRotation(current),
  /** Replaces the stored backup. The old key stops working the instant this
   *  succeeds, so it must not be called until the new one is saved. It does not
   *  publish a manifest: the identity is unchanged, so devices stay linked and
   *  no contact's safety number moves. */
  confirmRecoveryKeyRotation: () => app().ConfirmRecoveryKeyRotation(),
  cancelRecoveryKeyRotation: () => app().CancelRecoveryKeyRotation(),

  getRecoveryKeyStatus: () => app().GetRecoveryKeyStatus(),
  /** Actually decrypts the identity backup with the key given. Success and
   *  failure are both evidence; only success records a date. */
  verifyRecoveryKey: (recoveryKey: string) => app().VerifyRecoveryKey(recoveryKey),

  /** Which identity flow this device is in changed — first run finished, a link
   *  succeeded, or the session went away. */
  onIdentityState(cb: (s: IdentityState) => void): void {
    window.runtime?.EventsOn("identity:state", (data) => cb(data as IdentityState));
  },
  setCustomSound: (key: string, data: string) => app().SetCustomSound(key, data),
  getCustomSounds: () => app().GetCustomSounds(),
  clearCustomSound: (key: string) => app().ClearCustomSound(key),
  setHistoryEnabled: (enabled: boolean) => app().SetHistoryEnabled(enabled),
  setHistoryRetention: (days: number) => app().SetHistoryRetention(days),
  clearHistory: () => app().ClearHistory(),
  setTrayNotify: (on: boolean) => app().SetTrayNotify(on),
  conversationEncrypted: (screenName: string) =>
    app().ConversationEncrypted(screenName),
  /** Fetch a peer's keys on conversation open; resolves to whether it's now
   *  encryptable, so the badge can refresh once without a second call. */
  prepareConversation: (screenName: string) =>
    app().PrepareConversation(screenName),
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
