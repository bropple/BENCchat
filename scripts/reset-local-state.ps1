# Reset BENCchat to a blank slate on Windows — as if freshly installed.
#
# The PowerShell counterpart of reset-local-state.sh. Clears everything the app
# remembers: the server address, the remembered screen name, the saved password,
# the encryption identity, remembered device keys, room keys and message
# history. Next launch shows the first-run sign-on screen with nothing filled in.
#
#   .\reset-local-state.ps1                  # blank slate
#   .\reset-local-state.ps1 -KeepIdentity    # keep the encryption keypair
#   .\reset-local-state.ps1 -KeepHistory     # keep message history
#   .\reset-local-state.ps1 -KeepServer      # keep the server address
#   .\reset-local-state.ps1 -DryRun          # show what would happen
#   .\reset-local-state.ps1 -Yes             # skip the confirmation
#
# If PowerShell refuses to run it, either unblock this one file:
#     Unblock-File .\reset-local-state.ps1
# or run it without changing your policy permanently:
#     powershell -ExecutionPolicy Bypass -File .\reset-local-state.ps1
#
# NOTHING IS DELETED. Files move to a timestamped backup folder and the restore
# command is printed. Credentials are the exception — those cannot be backed up,
# which is why -KeepIdentity exists.

[CmdletBinding()]
param(
    [switch]$KeepIdentity,
    [switch]$KeepHistory,
    [switch]$KeepServer,
    [switch]$DryRun,
    [switch]$Yes,
    [string]$Account = ""
)

$ErrorActionPreference = 'Stop'

# Go's os.UserConfigDir() on Windows is %APPDATA% (Roaming), so this is where
# BENCchat keeps config.json, trust\, history\ and rooms\.
$ConfDir = if ($env:BENCCHAT_CONFIG_DIR) { $env:BENCCHAT_CONFIG_DIR } else { Join-Path $env:APPDATA 'BENCchat' }

# Credentials live in Windows Credential Manager. go-keyring names each entry
# "<service>:<username>", so everything BENCchat stored starts with this prefix:
#   BENCchat:<account>        the saved password
#   BENCchat:e2ee:<account>   the encryption private key
#   BENCchat:sign:<account>   the room-message signing seed
#   BENCchat:hist:<account>   the key the message history file is sealed under
#   BENCchat:rooms:<account>  the key the room-state file is sealed under
$CredPrefix = 'BENCchat:'

function Say  { param($m) Write-Host "`n==> $m" -ForegroundColor Green }
function Warn { param($m) Write-Host "`n[!] $m" -ForegroundColor Yellow }
function Die  { param($m) Write-Host "`n[x] $m" -ForegroundColor Red; exit 1 }

if (-not (Test-Path $ConfDir)) {
    Die "No BENCchat folder at $ConfDir`n     Nothing to reset — it is already a blank slate."
}

# --- which accounts --------------------------------------------------------
# One file per account under trust\, history\ and rooms\. The remembered screen
# name in config.json counts too: it drives auto-login, so an account with no
# data files can still have a credential to clear.
function Get-Accounts {
    $names = @()
    foreach ($d in @('trust', 'history', 'rooms')) {
        $p = Join-Path $ConfDir $d
        if (Test-Path $p) {
            $names += Get-ChildItem -Path $p -Filter '*.json' -File |
                      ForEach-Object { $_.BaseName }
        }
    }
    $cfg = Join-Path $ConfDir 'config.json'
    if (Test-Path $cfg) {
        try {
            $j = Get-Content $cfg -Raw | ConvertFrom-Json
            foreach ($k in @('rememberedScreenName', 'lastScreenName')) {
                if ($j.$k) { $names += $j.$k }
            }
        } catch { }   # a corrupt config is exactly what someone is resetting
    }
    $names | Sort-Object -Unique
}

$Accounts = if ($Account) { @($Account) } else { @(Get-Accounts) }

# --- what will be moved ----------------------------------------------------
$Targets = @()
foreach ($a in $Accounts) {
    foreach ($rel in @("trust\$a.json", "rooms\$a.json")) {
        if (Test-Path (Join-Path $ConfDir $rel)) { $Targets += $rel }
    }
    if (-not $KeepHistory) {
        $rel = "history\$a.json"
        if (Test-Path (Join-Path $ConfDir $rel)) { $Targets += $rel }
    }
}
# config.json holds the server address AND the remembered screen name, so it is
# what makes the app auto-sign-on. Keeping it means keeping auto-login.
if (-not $KeepServer -and (Test-Path (Join-Path $ConfDir 'config.json'))) {
    $Targets += 'config.json'
}

Say "BENCchat reset"
Write-Host "    folder     : $ConfDir"
Write-Host "    accounts   : $(if ($Accounts) { $Accounts -join ', ' } else { '<none found>' })"
Write-Host ""
Write-Host "    will clear :"
if ($KeepServer)   { Write-Host "                 (keeping server address and remembered name)" }
else               { Write-Host "                 server address, remembered screen name" }
Write-Host     "                 remembered device keys, room keys"
if ($KeepHistory)  { Write-Host "                 (keeping message history)" }
else               { Write-Host "                 message history" }
Write-Host     "                 saved password"
if ($KeepIdentity) { Write-Host "                 (keeping encryption identity)" }
else               { Write-Host "                 encryption identity (keypair + signing seed)" }

if ($Targets) {
    Write-Host ""
    Write-Host "    files      :"
    $Targets | ForEach-Object { Write-Host "                 $_" }
}

if (-not $KeepIdentity) {
    Warn "This drops this device's ENCRYPTION IDENTITY."
    Write-Host @"
     A new keypair is generated on next sign-on, so every contact sees your
     safety number change and has to re-verify. That warning exists to catch
     an impersonator, so spending it needlessly teaches people to ignore it.
     Pass -KeepIdentity if you only meant to sign out.
"@
}

if ($DryRun) { Say "[dry run] nothing changed"; exit 0 }

if (-not $Yes) {
    Write-Host ""
    $reply = Read-Host 'Proceed? [y/N]'
    if ($reply -notmatch '^(y|Y|yes|YES)$') { Die "cancelled" }
}

# --- move, do not delete ---------------------------------------------------
$Backup = ""
if ($Targets) {
    $Backup = Join-Path $ConfDir ("backup-" + (Get-Date -Format 'yyyyMMdd-HHmmss'))
    Say "Moving files to $Backup"
    foreach ($rel in $Targets) {
        $dst = Join-Path $Backup $rel
        New-Item -ItemType Directory -Force -Path (Split-Path $dst -Parent) | Out-Null
        Move-Item -Path (Join-Path $ConfDir $rel) -Destination $dst -Force
        Write-Host "    $rel"
    }
}

# --- credentials -----------------------------------------------------------
# Enumerate rather than guess at names. Clearing by prefix catches entries for
# accounts whose files were already removed; building the list from account
# names would leave those orphans behind, and a blank slate should be blank.
Say "Clearing Windows Credential Manager entries"

$targets = @()
try {
    # cmdkey is built in, so this needs no modules and no elevation.
    $targets = (cmdkey /list) 2>$null |
               Select-String -Pattern 'Target:\s*(.+)$' |
               ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() } |
               Where-Object { $_ -like "*$CredPrefix*" }
} catch {
    Warn "Could not list credentials: $_"
}

if (-not $targets) {
    Write-Host "    (no $CredPrefix entries found)"
} else {
    foreach ($t in $targets) {
        # cmdkey reports targets as "LegacyGeneric:target=BENCchat:usec"; the
        # part after the last '=' is what /delete expects.
        $name = $t
        if ($t -match '=') { $name = $t.Substring($t.LastIndexOf('=') + 1) }

        if ($KeepIdentity -and ($name -like "$CredPrefix" + 'e2ee:*' -or $name -like "$CredPrefix" + 'sign:*')) {
            Write-Host "    kept    $name"
            continue
        }
        # -KeepHistory preserved the file while this loop took the key it is
        # sealed under, and history fails closed on a key it cannot use — so
        # "keep" produced scrollback that could never be read again.
        if ($KeepHistory -and $name -like "$CredPrefix" + 'hist:*') {
            Write-Host "    kept    $name  (the preserved history stays readable)"
            continue
        }
        $null = cmdkey /delete:$name 2>&1
        if ($LASTEXITCODE -eq 0) { Write-Host "    cleared $name" }
        else                     { Write-Host "    (could not clear $name)" }
    }
}

Say "Done."
if (-not $KeepServer) {
    Write-Host ""
    Write-Host "  Next launch shows the first-run sign-on screen with nothing filled in."
}
if ($Backup) {
    Write-Host @"

  Files were moved, not deleted. To undo:

      Copy-Item -Recurse -Force "$Backup\*" "$ConfDir\"

  Credentials cannot be restored — a cleared password must be typed again, and
  a cleared identity is regenerated on next sign-on.
"@
}
