# BENCchat

A modern desktop chat client for the **OSCAR** protocol (the wire protocol AIM
ran on), speaking to a self-hosted [open-oscar-server](https://github.com/mk6i/open-oscar-server)
at a self-hosted OSCAR server. A BENCO Holdings project.

See [`CLAUDE.md`](CLAUDE.md) for scope and protocol notes, and
[`benco-design-style-guide.md`](benco-design-style-guide.md) for the visual
language.

## Stack

- **Wails v2** — Go backend + web frontend, packaged as a native desktop app
  for Windows, macOS, and Linux.
- **Go** owns the protocol: FLAP framing, SNAC commands, TLVs, the BUCP login
  flow, and the TCP socket. This mirrors the server's own Go source so the two
  can be cross-referenced directly.
- **TypeScript + Vite** (no UI framework) owns the interface. The UI talks only
  to the Go bridge (`app.go`) — never to FLAP/SNAC directly — so the protocol
  layer can later be reused headless (e.g. R. Triy, Home Assistant).

## Layout

```
main.go                     Wails bootstrap (window, embed)
app.go                      Go↔JS bridge: bound methods + events
internal/
  config/                   Server address + settings (configurable, not hardcoded)
  wire/                     OSCAR wire format — no I/O, all pure encode/decode
    codec.go                Reflection (un)marshaler driven by `oscar:"..."` tags
    flap.go                 FLAP outer framing
    snac.go                 SNAC header + foodgroup/subgroup constants
    tlv.go                  TLV + typed accessors
    login.go                BUCP SNAC bodies, login TLV tags, MD5 password hashing
    oservice.go             Session-management bodies (versions, client-online)
    feedbag.go              Buddy-list items + tree attribute tags
    buddy.go                TLVUserInfo + presence flags
    icbm.go                 Message bodies, fragments, charset handling
  oscar/                    Transport + session: the only package that does I/O
    transport.go            TCP socket, FLAP read/write, sequence numbers
    auth.go                 BUCP login → BOS address + auth cookie
    session.go              BOS connection, OSERVICE handshake, read loop
    feedbag.go              Buddy-list fetch + tree reconstruction
    buddy.go                Presence decoding
    icbm.go                 Message send/receive
    live_test.go            Opt-in tests against a real server
  state/                    Protocol-agnostic model (buddies, presence, chats)
  client/                   Joins oscar → state; the only layer that knows both
frontend/
  index.html
  src/
    main.ts                 Bootstrap + screen router
    signon.ts               Sign-on screen
    roster.ts               Buddy list + conversation view
    bridge.ts               Typed wrapper over Wails globals
    style.css               BENCO design system tokens
    signon.css / roster.css Per-screen layout
```

## Prerequisites

1. **Go** 1.23+ — https://go.dev/dl/
2. **Node.js** LTS (18+) — https://nodejs.org/
3. A **C toolchain** (cgo) — GCC on Linux; MinGW-w64 on Windows.
4. Platform webview:
   - **Linux**: GTK3 + WebKit2GTK (`gtk3`, `webkit2gtk-4.1` on Arch/Artix)
   - **Windows**: WebView2 runtime (preinstalled on Windows 11)
5. **Wails CLI**:
   ```sh
   go install github.com/wailsapp/wails/v2/cmd/wails@v2.10.1
   ```
   Ensure `~/go/bin` (or `%USERPROFILE%\go\bin`) is on your PATH, then run
   `wails doctor`.

## First run

```sh
go mod tidy          # populate go.sum (needs network once)
wails dev            # builds frontend + Go, opens the app with hot reload
```

To produce distributable binaries:

```sh
wails build          # outputs to build/bin/
```

### Linux + WebKit 4.1

Wails v2 probes for `webkit2gtk-4.0` by default and reports `libwebkit: Not
Found` in `wails doctor` on distros that ship only the newer **4.1** ABI
(current Arch/Artix, Debian 13, Ubuntu 24.04+). It still builds — pass the tag:

```sh
wails build -tags webkit2_41
wails dev   -tags webkit2_41
```

This is a `wails doctor` blind spot, not a real missing dependency.

## Tests

The protocol layer is unit-tested against byte fixtures and MD5 known-answer
vectors, and the handshake runs end-to-end against a scripted fake server. No
network required:

```sh
go test ./internal/...
```

### Live tests

A few tests talk to a real server and are opt-in, so the default run stays
hermetic. The first two need no account:

```sh
# Framing + BUCP branch selection + error decoding, no credentials needed.
BENCCHAT_LIVE_SERVER=your-server:5190 go test ./internal/oscar/ -run TestLive -v

# Full sign-on. Needs an account provisioned via the Management API.
BENCCHAT_LIVE_SERVER=your-server:5190 \
BENCCHAT_LIVE_SCREENNAME=... BENCCHAT_LIVE_PASSWORD=... \
  go test ./internal/oscar/ -run TestLiveSignOn -v
```

## Status

**Phase 3 (current): a real AIM client.** Core messaging plus most of the
classic feature set, verified end-to-end against a live server.

Foundation:
- [x] Wails scaffold + BENCO design system + themes (presets + live editor)
- [x] `wire` layer: codec, FLAP, SNAC, TLV, BUCP structs, password hashing
- [x] Configurable server address
- [x] Transport: TCP dial + FLAP loop, sequence numbers, keepalive
- [x] BUCP auth → BOS reconnect → OSERVICE handshake → client-online

Messaging & presence:
- [x] 1:1 instant messaging, typing notifications, sound effects
- [x] Presence (online / away / idle), buddy sign-on/off
- [x] Offline messages (retrieved on sign-on, shown with original send time)
- [x] Rich-text rendering of inbound AIM `<HTML>` messages (allowlist
      sanitizer in `frontend/src/message.ts`) + classic emoticons
- [x] Rate-limit honoring: decode `RateParamsReply` and pace outbound SNACs to
      the server's thresholds so bursts are slowed, not silently dropped
- [x] Local chat history: conversations persist to disk per-account and reload
      on sign-on (`internal/history`), with a settings toggle, retention
      (auto-delete older than N days), and a clear-all button. Local only —
      OSCAR stores no history server-side; this mirrors AIM's client-side logging

Buddy list & people:
- [x] View + edit buddy list (add / remove / rename / group), base structure
      auto-created on first sign-on
- [x] Buddy icons (BART): fetch + cache + display buddies' icons
- [x] Blocking / privacy (feedbag deny + pdinfo mode)
- [x] User search by email (UserLookup) + directory search by name (ODir)
- [x] Multi-user chat rooms (ChatNav/Chat): join/create a room, participant
      list, send/receive — on their own service connections (the client's first
      multi-connection support). Protocol + UI built and unit-tested; live
      multi-user verification is the one piece still pending

Profile & status:
- [x] Set own away message + view a buddy's (Locate SetInfo/UserInfoQuery)
- [x] Set own profile + view a buddy's
- [x] Warn ("evil") a user; receive warnings

Account:
- [x] In-band password / email change (Admin foodgroup)

**Not yet built:** file transfer and direct IM (both peer-to-peer OFT rendezvous
— they need NAT traversal and two reachable clients, so they can't be built or
verified without real networked peers), ICQ features, and setting your *own*
buddy icon (BART upload — display of others' icons is done). Transport
encryption is deferred pending server-side TLS (stunnel).

**Live-verified** against a live server: auth, BOS handshake, buddy-list edits,
1:1 messaging + typing, away messages (set + fetch), and block/unblock. Warn,
account changes, and the three newest protocol features — rate-limit decode
(`TestLiveRateParams`), buddy-icon download, and directory search — are
unit-tested and build-verified; their wire formats are mirrored from the server
source but not yet automated against the live server (icons need a buddy who set
one; directory search needs users with directory info; warn needs a prior
message; account changes are destructive to test).

## Notes

- **Accounts** are provisioned server-side via the Management API (SSH tunnel);
  BENCchat cannot create them. You need an existing screen name to sign in.
- **Fonts** (VT323 / Share Tech Mono / IBM Plex Mono) are vendored locally as
  `woff2` under `frontend/src/fonts/` (latin + latin-ext for all three, plus
  cyrillic/vietnamese where the family ships them — all OFL, see
  `fonts/LICENSES.md`). The client does not fetch fonts from a CDN at launch.
  IBM Plex Mono is the non-latin fallback in every `--font-*` stack, so
  cyrillic/vietnamese stay in the project's own type palette rather than the
  host's system monospace. **CJK (Japanese/Chinese/Korean) is intentionally not
  vendored** — those fonts are 5–40 MB — so it renders via named OS fonts
  through the `--cjk-fallback` chain (works on any desktop that ships a CJK
  font; the only failure case is a stripped host with none). To refresh the
  vendored latin/cyrillic/vietnamese, re-fetch the Google Fonts css2 API with a
  modern browser User-Agent and pull the per-subset woff2 URLs.
- **Chat history** is stored locally under the app config dir
  (`<config>/BENCchat/history/<screenname>.json`), one file per account, mode
  0600/0700. It never leaves the machine — OSCAR has no server-side history, so
  this is purely a client feature. On by default; disable, set a retention
  window, or clear it in Settings.
- `open-oscar-server` should be cloned next to this repo as a read-only wire
  reference; it is not vendored.
