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
- **Retries:** retries rate-limited reads only. A power, deploy or reinstall
  request is never retried.
- **Errors:** never contain the token.

**Secrets**
- **Sources:** tokens, webhook secrets, sink URLs and Matrix tokens are read
  only from files.
- **Permissions:** files that other users can read are refused.
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
