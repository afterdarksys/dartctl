#!/bin/sh
# Install dartctl as a monitor service on a Linux host with systemd.
#
#   sudo sh scripts/install.sh ./dartctl
#
# Creates a dartctl system user, /etc/dartctl (config and secrets, mode 700),
# /var/lib/dartctl (state), installs the binary and the systemd unit, and leaves
# the service stopped until you have filled in the config. It never asks for
# or handles a token: put it in /etc/dartctl/token yourself (see README).
set -eu

bin=${1:-}
die() { printf 'install: %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root"
[ -n "$bin" ] && [ -x "$bin" ] || die "usage: sudo sh install.sh <path to dartctl binary>"
here=$(cd "$(dirname "$0")/.." && pwd)

id dartctl >/dev/null 2>&1 || useradd --system --home /var/lib/dartctl --shell /usr/sbin/nologin dartctl
install -m 0755 "$bin" /usr/local/bin/dartctl
install -d -m 0700 -o dartctl -g dartctl /etc/dartctl /var/lib/dartctl
if [ ! -e /etc/dartctl/monitor.json ]; then
  install -m 0600 -o dartctl -g dartctl "$here/examples/monitor.json" /etc/dartctl/monitor.json
fi
install -m 0644 "$here/deploy/systemd/dartctl-monitor.service" /etc/systemd/system/dartctl-monitor.service
systemctl daemon-reload

cat <<'EOF'
Installed. Before starting:
  1. Create a DartNode service key with only these scopes:
       account.read services.read billing.read network.read webhooks.read
     and save it:  sudo -u dartctl sh -c 'umask 077; cat > /etc/dartctl/token'
     (paste, then Ctrl-D; it never appears on the command line)
  2. Edit /etc/dartctl/monitor.json: expected hosts, sinks, min_credit.
  3. Dry run:  sudo -u dartctl dartctl monitor check --config /etc/dartctl/monitor.json
  4. Start:    systemctl enable --now dartctl-monitor
  5. Webhooks: put HTTPS (Caddy, nginx, Traefik) in front of 127.0.0.1:8787,
     then run scripts/setup-webhook.sh from a machine with a webhooks.write key.
EOF
