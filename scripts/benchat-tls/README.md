# BENCchat TLS front-end

Puts **stunnel** in front of `open-oscar-server` so BENCchat can connect over
TLS. It encrypts everything end-to-end encryption can't: the BUCP login
handshake, your buddy list, presence, profiles, chat rooms, and who you talk to.

## Does open-oscar-server need restarting?

**No.** Nothing here touches it — not its config, not its process.

stunnel listens on a **new** port (5191), terminates TLS, and forwards plaintext
to `127.0.0.1:5190`, which is where your server already listens. Your server
sees an ordinary local connection and is none the wiser.

It also doesn't need reconfiguring to advertise the new port. open-oscar-server
tells clients where to reconnect for BOS and chat, and it will keep naming
`:5190` — BENCchat deliberately ignores that and forces its own configured port
whenever TLS is on, precisely so a proxy-fronted server can't downgrade the rest
of the session. All the core OSCAR services share the one listener, so one
stunnel port covers BOS, ChatNav, and Chat together.

Port 5190 stays open and unchanged, so legacy AIM clients keep working exactly
as they do today.

## Install

```bash
scp benchat-tls.tar.gz your-vm:~/
ssh your-vm
tar xzf benchat-tls.tar.gz
cd benchat-tls
sudo ./install.sh
```

That installs stunnel, generates a self-signed certificate, writes a systemd
service, opens the local firewall, and starts it.

### Then: open the port in Oracle Cloud

The VM firewall isn't the only gate — Oracle blocks it at the network layer too:

> Oracle Cloud console → Networking → Virtual Cloud Networks → your VCN →
> Security Lists → Default Security List → **Add Ingress Rule**
> - Source CIDR: `0.0.0.0/0`
> - IP Protocol: TCP
> - Destination Port Range: `5191`

### Then: point BENCchat at it

1. Settings → Privacy & Security → Connection
   - ☑ **Require an encrypted connection (TLS)**
   - ☑ **Skip the certificate check** — needed only while the cert is self-signed
2. Sign-on screen → change the server to `your-server.example.com:5191`
3. Sign off and back on. The sign-on screen should read `🔓 TLS (unverified)`.

## Get a real certificate

Self-signed works, but "skip the certificate check" means BENCchat will accept
*any* server claiming to be yours — which removes most of what TLS is for. Treat
it as a step on the way, not a destination.

```bash
sudo ./letsencrypt.sh
```

Needs a Cloudflare API token with **Zone → DNS → Edit** on `example.com`
(Cloudflare → My Profile → API Tokens → "Edit zone DNS" template). It uses
DNS-01, so no need to open port 80, and it sets up unattended renewal.

Afterwards, turn **off** "Skip the certificate check". The sign-on screen should
then read `🔒 TLS`.

## Optional: slow down password guessing

```bash
sudo ./ratelimit.sh
```

open-oscar-server doesn't throttle failed logins, and logs them only at debug
level — so fail2ban would mean running the whole server verbosely. This limits
new connections per IP at the firewall instead: 10/minute with a burst of 20.
Signing on normally uses a handful; guessing needs thousands.

## Checking and undoing

```bash
systemctl status benchat-tls
journalctl -u benchat-tls -f

# prove TLS works from anywhere
openssl s_client -connect your-server.example.com:5191

sudo ./uninstall.sh                    # remove the stunnel service + rate limits
sudo ./uninstall.sh --ratelimit-only   # just the rate limits
```

Uninstalling leaves the certificates and config in `/etc/benchat-tls/` on
purpose, and cannot affect open-oscar-server since nothing here ever touched it.

## Notes

- **Modern TLS only** (1.2+, ECDHE/AES-GCM). Legacy AIM 6.2–7.0 SSL clients need
  a *separate* stunnel built against OpenSSL 1.0.2u, because they open with an
  SSLv2-format ClientHello that modern OpenSSL rejects. Don't weaken this
  listener to accommodate them — run a second one if you ever need it.
- **TLS is hop-by-hop.** It protects the leg between one client and the server.
  It doesn't stop the *server* reading messages — that's what E2EE is for — and a
  legacy client on 5190 has an unencrypted leg regardless of yours.
- Still not covered: data at rest on the VM. That's the separate
  SQLCipher/LUKS item.
