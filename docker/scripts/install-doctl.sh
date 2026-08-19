#!/bin/bash
# Install doctl CLI into the Paperclip container
# Run after container recreate: docker exec docker-paperclip-1 /paperclip/scripts/install-doctl.sh
set -e
if command -v doctl &>/dev/null; then
    echo "doctl already installed: $(doctl version | head -1)"
    exit 0
fi
echo "Installing doctl v1.166.0..."
curl -sL https://github.com/digitalocean/doctl/releases/download/v1.166.0/doctl-1.166.0-linux-amd64.tar.gz | tar xz -C /usr/local/bin/
echo "Done: $(doctl version | head -1)"
