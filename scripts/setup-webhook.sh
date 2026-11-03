#!/bin/sh
# Register a DartNode webhook that points at a dartctl receiver, and save its
# signing secret where the receiver reads it.
#
#   sh scripts/setup-webhook.sh https://hooks.example.com/dartnode/webhook /etc/dartctl/webhook-secret
#
# What it does, in order (it stops at the first problem):
#   1. checks dartctl and your API token (needs the webhooks.read and
#      webhooks.write scopes)
#   2. checks the receiver answers on its /healthz path
#   3. refuses if a webhook already points at the same URL
#   4. creates the webhook for all events and writes the secret, which DartNode
#      shows only once, straight to the secret file (mode 600, never printed)
#   5. prints the webhook ID to put in the monitor config (expect.webhook_id)
#
# Run it where dartctl can read your token (DARTNODE_TOKEN, --token-file via
# DARTCTL_TOKEN_FILE, or ~/.config/dartctl/token). It changes nothing until step 4.
set -eu

url=${1:-}
secret_file=${2:-}
events=${DARTCTL_EVENTS:-*}
name=${DARTCTL_WEBHOOK_NAME:-dartctl-monitor}

die() { printf 'setup-webhook: %s\n' "$*" >&2; exit 1; }

[ -n "$url" ] && [ -n "$secret_file" ] || die "usage: sh setup-webhook.sh <https receiver URL> <secret file path>"
case "$url" in https://*) ;; *) die "the receiver URL must be https (DartNode delivers to https only)" ;; esac
command -v dartctl >/dev/null 2>&1 || die "dartctl is not on PATH (go install github.com/afterdarksys/dartctl/cmd/dartctl@latest)"
[ ! -e "$secret_file" ] || die "$secret_file already exists; pick a new path so an existing secret is never lost"
[ -d "$(dirname "$secret_file")" ] || die "directory $(dirname "$secret_file") does not exist"

echo "1/5 checking the API token"
dartctl webhooks list >/dev/null || die "the token cannot list webhooks (needs webhooks.read)"

echo "2/5 checking the receiver"
origin=$(printf '%s' "$url" | sed -E 's#^(https://[^/]+).*#\1#')
code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$origin/healthz" 2>/dev/null || true)
if [ "$code" != 200 ]; then
  echo "    warning: $origin/healthz answered '$code', not 200."
  echo "    If dartctl monitor serve is not reachable yet, DartNode's deliveries will fail;"
  echo "    after 10 failures DartNode disables the webhook."
  printf '    continue anyway? [y/N] '
  read -r answer
  [ "$answer" = y ] || [ "$answer" = Y ] || die "stopped; nothing was changed"
fi

echo "3/5 checking for an existing webhook on this URL"
if [ "$(dartctl --json webhooks list --url "$url")" != "[]" ]; then
  die "a webhook already points at $url (dartctl webhooks list); delete it first or use another URL"
fi

echo "4/5 creating the webhook ($events)"
out=$(dartctl --json webhooks create --name "$name" --url "$url" --events "$events" --secret-out "$secret_file" --yes)
id=$(printf '%s' "$out" | sed -n 's/.*"id": *\([0-9][0-9]*\).*/\1/p' | head -n 1)

echo "5/5 done"
echo "    secret file: $secret_file (mode 600)"
echo "    webhook id:  ${id:-see dartctl webhooks list}"
echo
echo "Next:"
echo "  - set \"secret_file\": \"$secret_file\" and \"expect\": {\"webhook_url\": \"$url\"} in the monitor config"
echo "  - restart dartctl monitor serve so it loads the secret"
echo "  - prove the path end to end:"
echo "      dartctl monitor send-test --secret-file $secret_file --url $url"
