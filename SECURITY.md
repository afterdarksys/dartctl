# Security

## Threat model

**Webhook receiver**
- **Refuses** these with no detail in the response:
  - deliveries without a valid `v1=` HMAC-SHA256 signature, compared in
    constant time
  - deliveries outside a ±5 minute timestamp window
  - bodies over 64 KiB
  - malformed event IDs or types
  - a mismatched `X-DartNode-Event` header
- **Dedupe:** event IDs are deduped, so a capture replayed inside the window
  alerts once.
- **Storage:** inbox files are named by the SHA-256 of the event ID, so
  case-insensitive filesystems cannot merge two events.
- **Durability:** every write is fsynced, including its directory, before the
  2xx answer.
- **State directory:** it is locked against a second process, and a directory
  owned by another user is refused.
- **Does not:** rate-limit floods from the network. Put a proxy in front of
  it.
- **Does not:** survive a leaked webhook secret. Rotate it: register a new
  webhook, move the old secret to `previous_secret_file`, then delete the old
  webhook.

**API client**
- **Token handling:** sends the token only as a Bearer header to the
  configured HTTPS base, and refuses redirects so the header is never replayed
  to another host.
- **Limits:** bounds response size and time.
- **Retries:** retries rate-limited reads only, and a retry wait stops on
  shutdown. A power, deploy or reinstall request is never retried.
- **TLS:** TLS 1.2 or newer with AEAD-only ECDHE suites, verified against the
  system roots. The same applies to alert sinks.
- **Errors:** never contain the token.

**Secrets**
- **Sources:** tokens, webhook secrets, sink URLs and Matrix tokens are read
  only from files.
- **Permissions:** files that other users can read, or that are owned by
  anyone other than the current user or root, are refused.
- **Shown-once secrets:** the webhook secret is written to a new mode-600 file
  and never printed. An existing file is never overwritten.

**Changes**
- **Gates:** every change needs `--yes`.
- **Confirmation:** hard power-off, hard reboot, reinstall, password reset,
  reverse-DNS clear and webhook deletion also need `--confirm` with the exact
  hostname, IP or ID.
- **Limits:** these gates stop accidents, not a person who intends harm.
  Scope your tokens.

## Reporting

Please report vulnerabilities privately to the maintainers, not in a public
issue.
