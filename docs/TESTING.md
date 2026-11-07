# Testing

## Strategy
Testing uses table-driven unit tests that build `x509.Certificate` structs directly. This allows verification of edge cases without generating valid cryptographic keys.

## Test Coverage
- **Chain Inspection**: Verifies `TLS001` through `TLS010` against static certificate mocks, ensuring finding codes, severities, and messages match the specification exactly (e.g., expiry windows, validity length, weak keys, hostname mismatch).
- **Network Probing**: Uses `httptest.NewTLSServer` to verify the `Probe` function against local loopback listeners. Validates `Report` construction, version detection, and error handling (e.g., `ErrProbe` handling for timeouts or connection failures).