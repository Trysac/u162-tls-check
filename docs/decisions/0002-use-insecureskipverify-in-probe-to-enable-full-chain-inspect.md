# Use InsecureSkipVerify in Probe to enable full chain inspection

Status: accepted (generated, pending human review)

## Context

Probing endpoints with expired, untrusted, or self-signed certificates must yield actionable findings rather than failing immediately during the TLS handshake.

## Decision

Configure the TLS dialer with InsecureSkipVerify: true to obtain the raw peer certificates, and subsequently run x509 path verification in software, reporting TLS010 on failure.

## Consequences

Allows inspection of broken TLS endpoints in CI and monitoring environments without masking the underlying certificate errors.
