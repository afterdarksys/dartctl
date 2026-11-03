# dnctl

An unofficial command line and monitor for the [DartNode](https://dartnode.com)
API. It is not affiliated with or supported by DartNode.

`dnctl` does three things:

- **CLI.** Covers the whole v1 API: instances, power, console, configuration,
  IPs and reverse DNS, billing, deploy and webhooks.
- **Webhook receiver.** Verifies every delivery's signature before it raises an
  alert.
- **Reconciler.** Checks the account on a schedule, so a missed delivery, a
  disabled webhook or a past-due invoice is still caught.

It is a single static Go binary with no third-party dependencies.

## Install

```sh
go install github.com/afterdarksys/dnctl/cmd/dnctl@latest
# or
git clone https://github.com/afterdarksys/dnctl && cd dnctl && go build -o dnctl ./cmd/dnctl
```

## API token

Create a service key in the DartNode dashboard (Settings → API Keys) with only
the scopes you need. Then save it to a file only you can read:

```sh
mkdir -p ~/.config/dnctl
( umask 077; cat > ~/.config/dnctl/token )   # paste the dnt_ token, then Ctrl-D
```

`dnctl` looks for the token in this order:
1. `--token-file FILE`. When given, it always wins.
2. `$DARTNODE_TOKEN`
3. `$DNCTL_TOKEN_FILE`
4. `~/.config/dnctl/token`

It refuses token files that other users can read, and files owned by anyone
other than you or root. Global flags go before the command:
`dnctl --json compute list`. There is deliberately no
`--token` flag, because command-line arguments are visible to other processes
and stay in shell history.

| Use | Scopes |
| --- | --- |
| Reading and monitoring | `account.read services.read billing.read network.read webhooks.read` |
| Registering webhooks | add `webhooks.write`, ideally in a separate key used once |
| Power, console, reinstall, deploy, rDNS | add only the scopes you will use |

## CLI

```sh
dnctl compute list
dnctl compute get 123
dnctl ips list
dnctl billing balance            # shows credit or the amount owed
dnctl billing invoices --open    # everything that is not paid or refunded
dnctl webhooks list
dnctl --json compute list        # raw JSON for scripts
```

Every change needs `--yes`. Destructive changes also need `--confirm` with the
instance's exact hostname. `dnctl` fetches the instance and refuses on any
mismatch:

```sh
dnctl power 123 shutdown --yes                     # graceful ACPI shutdown
dnctl power 123 off --yes --confirm web-1          # hard power off
dnctl power 123 reboot-hard --yes --confirm web-1
dnctl reinstall 123 --os 5 --yes --confirm web-1   # wipes the disk
dnctl reset-password 123 --yes --confirm web-1
dnctl hostname 123 web-2.example.com --yes
dnctl rdns set 192.0.2.10 mail.example.com --yes
dnctl rdns clear 192.0.2.10 --yes --confirm 192.0.2.10
dnctl deploy estimate --plan 1 --region us-dal --hostname n1 --os 1 --os-version 5
dnctl deploy create   --plan 1 --region us-dal --hostname n1 --os 1 --os-version 5 --yes
```

Without `--yes`, `deploy create` prints the price estimate and stops.

## Monitoring

`dnctl monitor serve --config monitor.json` runs two things.

**Webhook receiver** (`POST /dartnode/webhook`):
- Verifies `X-DartNode-Signature` (`v1=` HMAC-SHA256 over `timestamp.body`)
  with a 5-minute replay window and a 64 KiB body limit.
- Dedupes on the event ID, so a retried or replayed delivery alerts once.
- Stores each event before answering, so a crash never loses an
  acknowledged event.
- During secret rotation, accepts both the current and the previous secret.
- Delivers alerts from its own worker, so a slow reconcile pass never delays
  them. An event no sink accepts for a day moves to `state_dir/inbox/failed/`
  instead of blocking later ones.

**Reconciler** (every `interval`, default 15 minutes) alerts when any of these
holds:
- an expected host is missing, stopped or not active
- an unexpected host appears (optional)
- an invoice is unpaid or overdue
- a balance is owed, or credit falls below `min_credit`
- an expected IP is detached
- the monitored webhook was disabled or deleted. Set `expect.webhook_url` (or
  `webhook_id`). DartNode disables a webhook after 10 failed deliveries, so
  this check is what notices.

It alerts on change: new, worse, and resolved findings. Open critical findings
are re-sent daily. When part of the API cannot be read, the findings in that
area stay open, and an API-error finding is raised instead of a false
"resolved".

One process owns a `state_dir` at a time; it is locked. Give `monitor check`
its own `state_dir` if `monitor serve` is running.

Run `dnctl monitor check --config monitor.json` for a single pass, from cron or
CI. It exits 3 while a critical finding is open.

### Alert sinks

Credentials are always read from files:

| `type` | Delivers to | Needs |
| --- | --- | --- |
| `stdout` | JSON lines (journald, Docker logs) | — |
| `slack` | Slack or Mattermost incoming webhook | `url_file` |
| `discord` | Discord webhook | `url_file` |
| `webhook` | any HTTPS endpoint, as the alert JSON | `url_file` |
| `matrix` | a Matrix room, as an `m.notice` | `homeserver`, `room_id`, `token_file` |

Each sink takes `min_severity`: `info`, `warning` (default) or `critical`.
`dnctl monitor test-alert --config monitor.json` sends a test to every sink.

### Event severities

| Severity | Events |
| --- | --- |
| Critical | `service.suspended`, `service.terminated`, `invoice.past_due`, `service.power.off`, `ip.detached` |
| Warning | `service.cancelled`, `service.power.reboot`, `service.power.shutdown`, `refund.issued`, unknown types |
| Info | `invoice.created`, `invoice.paid`, `service.provisioned`, `service.deployed`, `service.unsuspended`, `service.power.on`, `ip.attached` |

### Setup, end to end

1. **Install on a server.** `sudo sh scripts/install.sh ./dnctl` creates the
   `dnctl` user, `/etc/dnctl`, `/var/lib/dnctl` and a hardened systemd unit.
2. **Add the token and config.** Save a read-only service key to
   `/etc/dnctl/token`, and edit `/etc/dnctl/monitor.json`
   (see `examples/monitor.json`).
3. **Add HTTPS in front of the receiver.** DartNode delivers to HTTPS only;
   `examples/Caddyfile` is a working example. Keep the receiver itself on
   `127.0.0.1`.
4. **Start it.** `systemctl enable --now dnctl-monitor`.
5. **Register the webhook.** From a machine holding a `webhooks.write` key:
   ```sh
   sh scripts/setup-webhook.sh https://hooks.example.com/dartnode/webhook /etc/dnctl/webhook-secret
   ```
   The signing secret is shown once by DartNode, so `dnctl` writes it straight
   to the secret file (mode 600, never printed). Set `secret_file` and
   `expect.webhook_url` in the config, then restart the service.
6. **Prove the path.**
   ```sh
   dnctl monitor send-test --secret-file /etc/dnctl/webhook-secret --url https://hooks.example.com/dartnode/webhook
   ```

**Docker:** `deploy/docker/Dockerfile` builds a distroless image that runs as
uid 65532. Inside a container, set `"listen": "0.0.0.0:8787"`, publish the port
on loopback only, and make the mounted secret files mode 600 and owned by
65532.

## Security

See [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
