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
