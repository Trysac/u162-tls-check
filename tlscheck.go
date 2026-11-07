package tlscheck

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"net"
	"sort"
	"time"
)

// ErrEmptyChain is returned when InspectChain receives an empty or nil certificate chain.
var ErrEmptyChain = errors.New("tlscheck: certificate chain is empty")

// ErrProbe is returned when probing a TLS endpoint fails during dial or handshake.
var ErrProbe = errors.New("tlscheck: probe failed")

// Finding represents a single finding detected during certificate or handshake inspection.
type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// Options configure chain inspection and probe behavior.
type Options struct {
	// WarnDays specifies how many days before expiration a warning (TLS003) is raised.
	// Defaults to 30 when 0 or negative.
	WarnDays int

	// MaxValidityDays specifies the maximum allowed validity duration for certificates
	// issued after 2020-09-01 according to CA/Browser Forum Baseline Requirements.
	// Defaults to 398 when 0 or negative.
	MaxValidityDays int

	// Roots is the trusted root CA pool for verification. If nil, the system root pool is used.
	Roots *x509.CertPool

	// Dial is an optional custom dial function. Defaults to a standard net.Dialer.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Report contains the result of a live TLS probe.
type Report struct {
	Version     string              `json:"version"`
	CipherSuite string              `json:"cipher_suite"`
	Chain       []*x509.Certificate `json:"-"`
	Findings    []Finding           `json:"findings"`
}

const (
	defaultWarnDays        = 30
	defaultMaxValidityDays = 398
)

// CabForumLimitDate marks 2020-09-01T00:00:00Z when the 398-day validity limit began.
var cabForumLimitDate = time.Date(2020, time.September, 1, 0, 0, 0, 0, time.UTC)

// isIssuerEqualSubject returns true if issuer equals subject.
func isIssuerEqualSubject(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	if len(cert.RawIssuer) > 0 && len(cert.RawSubject) > 0 {
		return bytes.Equal(cert.RawIssuer, cert.RawSubject)
	}
	return cert.Issuer.String() == cert.Subject.String()
}

// InspectChain inspects a certificate chain (where chain[0] is the leaf) against
// host, verification time now, and provided options. It returns findings sorted by Code.
func InspectChain(chain []*x509.Certificate, host string, now time.Time, opts Options) ([]Finding, error) {
	if len(chain) == 0 {
		return nil, ErrEmptyChain
	}

	warnDays := opts.WarnDays
	if warnDays <= 0 {
		warnDays = defaultWarnDays
	}

	maxValidityDays := opts.MaxValidityDays
	if maxValidityDays <= 0 {
		maxValidityDays = defaultMaxValidityDays
	}

	var findings []Finding
	leaf := chain[0]

	// TLS001: leaf expired (now after NotAfter)
	if now.After(leaf.NotAfter) {
		findings = append(findings, Finding{
			Code:     "TLS001",
			Severity: "high",
			Message:  fmt.Sprintf("leaf certificate expired on %s", leaf.NotAfter.UTC().Format("2006-01-02")),
		})
	}

	// TLS002: leaf not yet valid
	if now.Before(leaf.NotBefore) {
		findings = append(findings, Finding{
			Code:     "TLS002",
			Severity: "high",
			Message:  fmt.Sprintf("leaf certificate is not valid before %s", leaf.NotBefore.UTC().Format("2006-01-02")),
		})
	}

	// TLS003: leaf expires within WarnDays
	if !now.After(leaf.NotAfter) {
		daysDiff := math.Floor(leaf.NotAfter.Sub(now).Hours() / 24.0)
		days := int(daysDiff)
		if days <= warnDays {
			findings = append(findings, Finding{
				Code:     "TLS003",
				Severity: "medium",
				Message:  fmt.Sprintf("leaf certificate expires in %d days (%s)", days, leaf.NotAfter.UTC().Format("2006-01-02")),
			})
		}
	}

	// TLS004: leaf hostname mismatch
	if host != "" {
		if err := leaf.VerifyHostname(host); err != nil {
			findings = append(findings, Finding{
				Code:     "TLS004",
				Severity: "high",
				Message:  fmt.Sprintf("leaf certificate does not match host %q", host),
			})
		}
	}

	// TLS005: single self-signed certificate
	if len(chain) == 1 && isIssuerEqualSubject(leaf) {
		findings = append(findings, Finding{
			Code:     "TLS005",
			Severity: "medium",
			Message:  "server presents a single self-signed certificate",
		})
	}

	// TLS006: RSA key under 2048 bits or ECDSA curve other than P-256, P-384, P-521
	hasWeakKey := false
	for _, cert := range chain {
		if cert == nil {
			continue
		}
		switch pub := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			if pub.N != nil && pub.N.BitLen() < 2048 {
				hasWeakKey = true
			}
		case *ecdsa.PublicKey:
			if pub.Curve != nil {
				cName := pub.Curve.Params().Name
				if cName != elliptic.P256().Params().Name &&
					cName != elliptic.P384().Params().Name &&
					cName != elliptic.P521().Params().Name {
					hasWeakKey = true
				}
			}
		}
		if hasWeakKey {
			break
		}
	}
	if hasWeakKey {
		findings = append(findings, Finding{
			Code:     "TLS006",
			Severity: "high",
			Message:  "chain contains weak public key (RSA < 2048 bits or unsupported ECDSA curve)",
		})
	}

	// TLS007: signature MD5WithRSA, SHA1WithRSA or ECDSAWithSHA1 on any certificate
	// except a last certificate whose issuer equals its subject
	hasWeakSig := false
	for i, cert := range chain {
		if cert == nil {
			continue
		}
		isLastSelfSigned := (i == len(chain)-1) && isIssuerEqualSubject(cert)
		if isLastSelfSigned {
			continue
		}
		switch cert.SignatureAlgorithm {
		case x509.MD5WithRSA, x509.SHA1WithRSA, x509.ECDSAWithSHA1:
			hasWeakSig = true
		}
		if hasWeakSig {
			break
		}
	}
	if hasWeakSig {
		findings = append(findings, Finding{
			Code:     "TLS007",
			Severity: "high",
			Message:  "chain contains certificate with weak signature algorithm (MD5 or SHA-1)",
		})
	}

	// TLS008: leaf validity longer than MaxValidityDays for certs issued since 2020-09-01
	if !leaf.NotBefore.Before(cabForumLimitDate) {
		durDays := math.Floor(leaf.NotAfter.Sub(leaf.NotBefore).Hours() / 24.0)
		if int(durDays) > maxValidityDays {
			findings = append(findings, Finding{
				Code:     "TLS008",
				Severity: "medium",
				Message:  fmt.Sprintf("leaf certificate validity duration exceeds %d days", maxValidityDays),
			})
		}
	}

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Code < findings[j].Code
	})

	return findings, nil
}

// Probe establishes a TLS connection to addr using serverName, inspects the chain
// and handshake parameters, and returns a Report.
func Probe(ctx context.Context, addr, serverName string, now time.Time, opts Options) (Report, error) {
	dialFunc := opts.Dial
	if dialFunc == nil {
		dialer := &net.Dialer{}
		dialFunc = dialer.DialContext
	}

	rawConn, err := dialFunc(ctx, "tcp", addr)
	if err != nil {
		return Report{}, fmt.Errorf("%w: dial %s: %v", ErrProbe, addr, err)
	}
	defer rawConn.Close()

	// Propagate deadline from context to connection
	if deadline, ok := ctx.Deadline(); ok {
		_ = rawConn.SetDeadline(deadline)
	}

	tlsConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // Allow inspecting invalid, expired or self-signed chains
		MinVersion:         tls.VersionTLS10,
	}

	tlsConn := tls.Client(rawConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return Report{}, fmt.Errorf("%w: handshake: %v", ErrProbe, err)
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	chain := state.PeerCertificates
	if len(chain) == 0 {
		return Report{}, fmt.Errorf("%w: no peer certificates received", ErrProbe)
	}

	findings, err := InspectChain(chain, serverName, now, opts)
	if err != nil {
		return Report{}, fmt.Errorf("%w: %v", ErrProbe, err)
	}

	// TLS009: negotiated version below TLS 1.2
	if state.Version < tls.VersionTLS12 {
		findings = append(findings, Finding{
			Code:     "TLS009",
			Severity: "medium",
			Message:  fmt.Sprintf("negotiated TLS version is below TLS 1.2 (%s)", tls.VersionName(state.Version)),
		})
	}

	// TLS010: chain does not verify
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	verifyOpts := x509.VerifyOptions{
		Roots:         opts.Roots,
		Intermediates: intermediates,
		CurrentTime:   now,
	}
	if _, err := chain[0].Verify(verifyOpts); err != nil {
		findings = append(findings, Finding{
			Code:     "TLS010",
			Severity: "high",
			Message:  fmt.Sprintf("certificate chain failed x509 verification: %v", err),
		})
	}

	sort.Slice(findings, func(i, j int) bool {
		return findings[i].Code < findings[j].Code
	})

	rep := Report{
		Version:     tls.VersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		Chain:       chain,
		Findings:    findings,
	}
	return rep, nil
}
