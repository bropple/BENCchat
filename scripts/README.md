# Operational scripts

Server-side helpers for a BENCchat deployment. None of these are part of the
client — they exist because the OSCAR server needs things around it that
`open-oscar-server` doesn't provide itself.

Nothing here has a hostname baked in. Pass yours explicitly.

## `benchat-tls/`

Puts **stunnel** in front of `open-oscar-server` so clients can connect over
TLS, encrypting everything end-to-end encryption cannot: the login handshake,
buddy list, presence, profiles, chat rooms, and who talks to whom.

The OSCAR server is not modified and does not need restarting — stunnel listens
on a new port and forwards to the existing plaintext one on loopback, which
stays open for period AIM clients.

```bash
./scripts/build-tls-bundle.sh          # produces benchat-tls.tar.gz
scp benchat-tls.tar.gz your-vm:~/
# on the server:
tar xzf benchat-tls.tar.gz && cd benchat-tls
sudo HOSTNAME_FQDN=chat.example.com ./install.sh   # stunnel + self-signed cert
sudo HOSTNAME_FQDN=chat.example.com ./letsencrypt.sh  # real cert, auto-renewing
sudo ./ratelimit.sh                                # slow down password guessing
```

See `benchat-tls/README.md` for the full walkthrough, including the cloud
firewall rule that is easy to forget.

## `backup-db.sh`

Encrypted, no-downtime backups of the server database, which holds password
material, buddy lists, and offline messages.

Encryption is **asymmetric on purpose**: the server holds only a public key, so
it can create backups it cannot read — and neither can anyone who compromises it
later. Backups are taken with `sqlite3 .backup`, which is consistent against a
live database, so the server keeps running.

```bash
# on YOUR machine, never the server:
age-keygen -o backup.key

# on the server:
sudo ./backup-db.sh --install-timer --recipient age1... /path/to/oscar.sqlite
```

## `purge-rooms.sh`

Deletes chat rooms directly from the database.

This exists because the management API can only delete **public** rooms, while
BENCchat creates them on the private exchange — so there is no API route for
them. Room names are also permanently unique, so old test rooms squat their
names until removed.

Refuses to run while the server is up, backs up first, shows what it will delete
and makes you type the count to confirm.

```bash
sudo systemctl stop open-oscar-server
sudo ./purge-rooms.sh /path/to/oscar.sqlite --private
sudo systemctl start open-oscar-server
```

## `build-desktop.sh`

The one script here that isn't server-side: builds the **client** for Linux
(native) and Windows (cross-compiled), into `build/bin/`.

macOS is not included. Wails needs Cocoa through CGO and refuses to
cross-compile to it, so a `.app` requires a real macOS machine — that is what
the `macos-latest` runner in `.github/workflows/build.yml` is for.

```bash
./scripts/build-desktop.sh
```

By default the binaries contain **no server address**: `DefaultAuthHost` stays
empty and you enter the address on the sign-on screen. That is the build to give
to anyone else. For a personal build that already knows where to connect:

```bash
AUTH_HOST=chat.example.com ./scripts/build-desktop.sh
```

The host is passed through `-ldflags` and never written to a file, so it can't
reach git by accident. Don't use it for anything you publish — the value lands
in the binary as a plain string, so `strings` recovers it immediately.

## Code signing (Windows)

Windows Defender flags unsigned Go GUI binaries as a matter of course —
`Trojan:Win32/DefenseEvasion.A!ml` is a typical verdict. The `!ml` suffix means
a machine-learning heuristic rather than a signature match, and
"DefenseEvasion" is a MITRE ATT&CK tactic bucket, not a malware family.

BENCchat fits that heuristic unusually well: it's an unsigned Go binary that
reads the **Windows Credential Manager** (through `go-keyring` → `wincred`),
spawns a WebView2 host process, and draws a borderless window. Each of those is
ordinary; together they resemble the API profile of credential-stealing
malware.

The credential-store access is not something to design away — it's where the
E2EE private keys and the saved password belong, instead of on disk in the
clear. Removing it would make the client *less* safe to make an antivirus
quieter. The fix is a signature.

`.github/workflows/build.yml` signs Windows artifacts with **Azure Trusted
Signing** when these repository secrets are set, and silently skips signing
when they aren't (so forks still get working, unsigned builds):

| Secret | What it is |
| --- | --- |
| `AZURE_TENANT_ID` | Directory (tenant) ID of the app registration |
| `AZURE_CLIENT_ID` | Application (client) ID — also the on/off switch for the signing step |
| `AZURE_CLIENT_SECRET` | Client secret for that registration |
| `AZURE_SIGNING_ENDPOINT` | Regional endpoint, e.g. `https://eus.codesigning.azure.net` |
| `AZURE_SIGNING_ACCOUNT` | Trusted Signing account name |
| `AZURE_CERT_PROFILE` | Certificate profile name within that account |

Setup, roughly: create a Trusted Signing account in Azure, add a certificate
profile (public-trust needs an org identity validation; there's an individual
tier), register an app and give its service principal the **Trusted Signing
Certificate Profile Signer** role on the account, then store the six values
above as repository secrets.

Signing does **not** grant instant SmartScreen reputation — that accrues as
copies are seen in the wild — but it attaches a verified publisher, which is
what stops the "unknown publisher" path and clears most heuristic detections.

Two things worth knowing:

- **Reporting a false positive is free and works.** Submit the binary at
  <https://www.microsoft.com/en-us/wdsi/filesubmission>; these are usually
  cleared within a day or two, and it fixes it for everyone rather than one
  machine.
- **Never pack or obfuscate to dodge a detection.** Wails offers `-upx` and
  `-obfuscated`; both sharply *increase* false positives, and evading detection
  is what actual malware does. The builds here deliberately use neither.

macOS artifacts stay unsigned — notarization needs an Apple Developer account
($99/yr). Gatekeeper's workaround is in the release notes.
