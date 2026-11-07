# Architecture

## Purpose

`tlscheck` provides lightweight, fast, and dependency-free TLS inspection for certificate chains and live network endpoints.

## Design

- **InspectChain**: A pure inspection function taking `[]*x509.Certificate`, target hostname, reference timestamp, and options. Performs validation checks TLS001-TLS008 without performing I/O.
- **Probe**: Establishes a TLS connection using `net.Dialer` (or caller-supplied `Dial` option) with `InsecureSkipVerify: true` and `MinVersion: tls.VersionTLS10` so invalid, expired, or self-signed peer certificates can still be captured and thoroughly analyzed. It then performs chain inspection and validates TLS version (TLS009) and path verification (TLS010).
- **Deterministic Sorting**: Findings are always sorted deterministically by finding code.
- **Zero External Dependencies**: Built entirely on standard library packages `crypto/tls`, `crypto/x509`, `net`, and `time`.
