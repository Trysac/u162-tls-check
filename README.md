# tls-check

Inspect TLS certificate chains and live handshakes: expiry, hostname, weak keys and signatures, validity length, trust, and protocol version, with stable finding codes.

## Overview

Expired or misissued certificates cause critical outages. Ad hoc scripts often check only expiry, missing hostname mismatches, weak keys, SHA-1 signatures, or invalid chains. Full scanners (like `testssl.sh`) are large, slow, and do far more than a continuous monitoring check needs. `tls-check` is a pure Go package (standard library only) designed for CI pipelines, health probes, and continuous certificate monitoring that provides a sorted, actionable list of findings.

### Installation

```bash
go get github.com/Trysac/u162-tls-check
```

### Usage

```go
package main

import (
	"context"
	"fmt"
	"time"
	"github.com/Trysac/u162-tls-check"
)

func main() {
	rep, err := tlscheck.Probe(context.Background(), "example.com:443", "example.com", time.Now(), tlscheck.Options{})
	if err == nil {
		for _, f := range rep.Findings {
			fmt.Printf("%s [%s]: %s\n", f.Code, f.Severity, f.Message)
		}
	}
}
```

## Public API

- `type Finding struct { Code string; Severity string; Message string }`
- `type Options struct { WarnDays int; MaxValidityDays int; Roots *x509.CertPool; Dial func(ctx context.Context, network, addr string) (net.Conn, error) }`
- `func InspectChain(chain []*x509.Certificate, host string, now time.Time, opts Options) ([]Finding, error)`
- `func Probe(ctx context.Context, addr, serverName string, now time.Time, opts Options) (Report, error)`
- `type Report struct { Version string; CipherSuite string; Findings []Finding }`

### Errors
- `ErrEmptyChain`: Returned if the provided certificate chain is nil or empty.
- `ErrProbe`: Wrapped with errors.Is, returned when dial or handshake operations fail.

## Why not testssl.sh?

`testssl.sh` is an external dependency that is slow and designed for one-off manual audits. `tls-check` is a embeddable Go library that enables automated, programmatic inspection with stable, machine-readable finding codes in CI/CD pipelines.

See [docs/SECURITY.md](docs/SECURITY.md) for security considerations.