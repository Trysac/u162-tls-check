// Package tlscheck is a small, dependency-free Go library: Inspect TLS certificate chains and handshakes: expiry, hostname, weak keys and signatures, validity length, trust and protocol version, with stable finding codes
//
// The public API is every exported identifier of this root package. Functions are pure: they do
// no I/O, keep no global mutable state and report invalid input through returned errors.
package tlscheck
