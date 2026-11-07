# Security Model

## Threat Model

`tlscheck.Probe` is designed to analyze potentially malicious or misconfigured endpoints. It sets `InsecureSkipVerify: true` during the `tls.Client` handshake. This is intentional to ensure the library can capture and inspect expired, untrusted, or self-signed certificates that would otherwise abort the connection. The security of the connection is then rigorously validated by the library itself:

- **Chain Validation**: `TLS010` performs explicit path verification using `x509.Certificate.Verify` against the configured root pool, ensuring trust is strictly verified regardless of the initial handshake settings.
- **DoS Mitigations**: All network operations respect the `context.Context` provided to `Probe`. Read and write deadlines are enforced on the underlying connection, ensuring the process does not hang indefinitely on malicious servers.

## Limits
- The library trusts the system's root pool if `Options.Roots` is nil.
- The library does not enforce certificate pinning natively unless provided via a custom `Roots` pool.