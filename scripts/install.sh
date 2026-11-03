#!/bin/sh
# Install dnctl as a monitor service on a Linux host with systemd.
#
#   sudo sh scripts/install.sh ./dnctl
#
# Creates a dnctl system user, /etc/dnctl (config and secrets, mode 700),
# /var/lib/dnctl (state), installs the binary and the systemd unit, and leaves
# the service stopped until you have filled in the config. It never asks for
# or handles a token: put it in /etc/dnctl/token yourself (see README).
set -eu

bin=${1:-}
die() { printf 'install: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root"
[ -n "$bin" ] && [ -x "$bin" ] || die "usage: sudo sh install.sh <path to dnctl binary>"
here=$(cd "$(dirname "$0")/.." && pwd)

id dnctl >/dev/null 2>&1 || useradd --system --home /var/lib/dnctl --shell /usr/sbin/nologin dnctl
install -m 0755 "$bin" /usr/local/bin/dnctl
install -d -m 0700 -o dnctl -g dnctl /etc/dnctl /var/lib/dnctl
if [ ! -e /etc/dnctl/monitor.json ]; then
  install -m 0600 -o dnctl -g dnctl "$here/examples/monitor.json" /etc/dnctl/monitor.json
fi
install -m 0644 "$here/deploy/systemd/dnctl-monitor.service" /etc/systemd/system/dnctl-monitor.service
systemctl daemon-reload

cat <<'EOF'
Installed. Before starting:
  1. Create a DartNode service key with only these scopes:
       account.read services.read billing.read network.read webhooks.read
     and save it:  sudo -u dnctl sh -c 'umask 077; cat > /etc/dnctl/token'
     (paste, then Ctrl-D; it never appears on the command line)
  2. Edit /etc/dnctl/monitor.json: expected hosts, sinks, min_credit.
  3. Dry run:  sudo -u dnctl dnctl monitor check --config /etc/dnctl/monitor.json
  4. Start:    systemctl enable --now dnctl-monitor
  5. Webhooks: put HTTPS (Caddy, nginx, Traefik) in front of 127.0.0.1:8787,
     then run scripts/setup-webhook.sh from a machine with a webhooks.write key.
EOF
