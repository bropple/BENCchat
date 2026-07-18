#!/usr/bin/env bash
# Packs scripts/benchat-tls/ into the tarball you copy to the server.
#
# The tarball itself is not tracked — it is generated from these sources, and a
# binary blob in git would drift from them silently.
set -euo pipefail
cd "$(dirname "$0")/.."
tar czf benchat-tls.tar.gz -C scripts benchat-tls
echo "wrote $(pwd)/benchat-tls.tar.gz"
echo
echo "Copy it to the server and run:"
echo "  tar xzf benchat-tls.tar.gz && cd benchat-tls"
echo "  sudo HOSTNAME_FQDN=your.hostname ./install.sh"
