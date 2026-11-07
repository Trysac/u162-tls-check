package tlscheck_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Trysac/u162-tls-check"
)

func makeSelfSignedCert(t *testing.T, notBefore, notAfter time.Time, dnsNames []string, isCA bool) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test Cert",
		},
		Issuer: pkix.Name{
			CommonName: "Test Cert",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		DNSNames:              dnsNames,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}
	return cert, priv
}

func hasFinding(findings []tlscheck.Finding, code string) (tlscheck.Finding, bool) {
	for _, f := range findings {
		if f.Code == code {
			return f, true
		}
	}
	return tlscheck.Finding{}, false
}

// Acceptance item 1:
// InspectChain with a leaf whose NotAfter is 2026-12-01T00:00:00Z at now 2026-11-06T00:00:00Z and WarnDays 30
// returns TLS003 "medium" with message "leaf certificate expires in 25 days (2026-12-01)",
// and at now 2026-12-02T00:00:00Z returns TLS001 "high" and no TLS003
func TestAcceptance1_ExpiryAndWarning(t *testing.T) {
	notBefore := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2026, time.December, 1, 0, 0, 0, 0, time.UTC)
	leaf := &x509.Certificate{
		NotBefore: notBefore,
		NotAfter:  notAfter,
		Subject:   pkix.Name{CommonName: "example.com"},
		Issuer:    pkix.Name{CommonName: "Issuer CA"},
	}
	chain := []*x509.Certificate{leaf}

	// Test at now 2026-11-06T00:00:00Z
	nowWarning := time.Date(2026, time.November, 6, 0, 0, 0, 0, time.UTC)
	findings, err := tlscheck.InspectChain(chain, "", nowWarning, tlscheck.Options{WarnDays: 30})
	if err != nil {
		t.Fatalf("InspectChain error: %v", err)
	}
	f, found := hasFinding(findings, "TLS003")
	if !found {
		t.Fatalf("expected TLS003 finding, got %+v", findings)
	}
	if f.Severity != "medium" {
		t.Errorf("TLS003 severity = %q, want %q", f.Severity, "medium")
	}
	wantMsg := "leaf certificate expires in 25 days (2026-12-01)"
	if f.Message != wantMsg {
		t.Errorf("TLS003 message = %q, want %q", f.Message, wantMsg)
	}
	if _, found001 := hasFinding(findings, "TLS001"); found001 {
		t.Errorf("expected no TLS001 at warning time")
	}

	// Test at now 2026-12-02T00:00:00Z
	nowExpired := time.Date(2026, time.December, 2, 0, 0, 0, 0, time.UTC)
	findingsExpired, err := tlscheck.InspectChain(chain, "", nowExpired, tlscheck.Options{WarnDays: 30})
	if err != nil {
		t.Fatalf("InspectChain error: %v", err)
	}
	f001, found001 := hasFinding(findingsExpired, "TLS001")
	if !found001 {
		t.Fatalf("expected TLS001 finding, got %+v", findingsExpired)
	}
	if f001.Severity != "high" {
		t.Errorf("TLS001 severity = %q, want %q", f001.Severity, "high")
	}
	if _, found003 := hasFinding(findingsExpired, "TLS003"); found003 {
		t.Errorf("expected no TLS003 when expired, got %+v", findingsExpired)
	}
}

// Acceptance item 2:
// A leaf with NotBefore after now returns TLS002; a validity from 2026-01-01 to 2027-02-03 (398 days)
// returns no TLS008, while 2026-01-01 to 2027-02-04 (399 days) returns TLS008
func TestAcceptance2_NotYetValidAndMaxValidity(t *testing.T) {
	now := time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC)

	// Not yet valid
	futureCert := &x509.Certificate{
		NotBefore: time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2026, time.August, 1, 0, 0, 0, 0, time.UTC),
		Subject:   pkix.Name{CommonName: "future.com"},
		Issuer:    pkix.Name{CommonName: "Issuer CA"},
	}
	findings, err := tlscheck.InspectChain([]*x509.Certificate{futureCert}, "", now, tlscheck.Options{})
	if err != nil {
		t.Fatalf("InspectChain error: %v", err)
	}
	if f, found := hasFinding(findings, "TLS002"); !found || f.Severity != "high" {
		t.Fatalf("expected TLS002 high, got %v (found: %v)", f, found)
	}

	// Exactly 398 days validity: 2026-01-01 to 2027-02-03
	valid398 := &x509.Certificate{
		NotBefore: time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2027, time.February, 3, 0, 0, 0, 0, time.UTC),
		Subject:   pkix.Name{CommonName: "test.com"},
		Issuer:    pkix.Name{CommonName: "Issuer CA"},
	}
	findings398, err := tlscheck.InspectChain([]*x509.Certificate{valid398}, "", now, tlscheck.Options{})
	if err != nil {
		t.Fatalf("InspectChain error: %v", err)
	}
	if _, found := hasFinding(findings398, "TLS008"); found {
		t.Fatalf("expected no TLS008 for 398 days, got %+v", findings398)
	}

	// 399 days validity: 2026-01-01 to 2027-02-04
	valid399 := &x509.Certificate{
		NotBefore: time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2027, time.February, 4, 0, 0, 0, 0, time.UTC),
		Subject:   pkix.Name{CommonName: "test.com"},
		Issuer:    pkix.Name{CommonName: "Issuer CA"},
	}
	findings399, err := tlscheck.InspectChain([]*x509.Certificate{valid399}, "", now, tlscheck.Options{})
	if err != nil {
		t.Fatalf("InspectChain error: %v", err)
	}
	if f, found := hasFinding(findings399, "TLS008"); !found || f.Severity != "medium" {
		t.Fatalf("expected TLS008 medium for 399 days, got %v (found: %v)", f, found)
	}
}

// Acceptance item 3:
// A leaf with DNSNames []string{"*.example.com"} has no TLS004 for host "a.example.com"
// and has TLS004 for "a.b.example.com" and for "example.com"
func TestAcceptance3_WildcardHostnameVerification(t *testing.T) {
	now := time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC)
	leaf := &x509.Certificate{
		NotBefore: time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2026, time.December, 31, 0, 0, 0, 0, time.UTC),
		DNSNames:  []string{"*.example.com"},
		Subject:   pkix.Name{CommonName: "Wildcard"},
		Issuer:    pkix.Name{CommonName: "Issuer CA"},
	}
	chain := []*x509.Certificate{leaf}

	// Host "a.example.com" -> match (no TLS004)
	fA, err := tlscheck.InspectChain(chain, "a.example.com", now, tlscheck.Options{})
	if err != nil {
		t.Fatalf("InspectChain error: %v", err)
	}
	if _, found := hasFinding(fA, "TLS004"); found {
		t.Errorf("expected no TLS004 for a.example.com, got %+v", fA)
	}

	// Host "a.b.example.com" -> mismatch (TLS004)
	fAB, err := tlscheck.InspectChain(chain, "a.b.example.com", now, tlscheck.Options{})
	if err != nil {
		t.Fatalf("InspectChain error: %v", err)
	}
	if _, found := hasFinding(fAB, "TLS004"); !found {
		t.Errorf("expected TLS004 for a.b.example.com, got %+v", fAB)
	}

	// Host "example.com" -> mismatch (TLS004)
	fApex, err := tlscheck.InspectChain(chain, "example.com", now, tlscheck.Options{})
	if err != nil {
		t.Fatalf("InspectChain error: %v", err)
	}
	if _, found := hasFinding(fApex, "TLS004"); !found {
		t.Errorf("expected TLS004 for example.com, got %+v", fApex)
	}
}

// Acceptance item 4:
// A leaf with an RSA public key of 1024 bits returns TLS006 and one of 2048 bits does not;
// a leaf with SignatureAlgorithm x509.SHA1WithRSA returns TLS007, while the same algorithm
// on the last certificate of a 2-certificate chain whose issuer equals its subject returns no TLS007
func TestAcceptance4_WeakKeyAndSignatureAlgorithm(t *testing.T) {
	now := time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC)

	key1024 := &rsa.PublicKey{N: new(big.Int).SetBytes(make([]byte, 128))} // 128 bytes = 1024 bits
	cert1024 := &x509.Certificate{
		PublicKey: key1024,
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
		Subject:   pkix.Name{CommonName: "1024"},
		Issuer:    pkix.Name{CommonName: "Issuer CA"},
	}
	f1024, err := tlscheck.InspectChain([]*x509.Certificate{cert1024}, "", now, tlscheck.Options{})
	if err != nil {
		t.Fatalf("InspectChain error: %v", err)
	}
	if _, found := hasFinding(f1024, "TLS006"); !found {
		t.Errorf("expected TLS006 for 1024 bit key, got %+v", f1024)
	}

	key2048 := &rsa.PublicKey{N: new(big.Int).Lsh(big.NewInt(1), 2048), E: 65537} // 256 bytes = 2048 bits
	cert2048 := &x509.Certificate{
		PublicKey: key2048,
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
		Subject:   pkix.Name{CommonName: "2048"},
		Issuer:    pkix.Name{CommonName: "Issuer CA"},
	}
	f2048, err := tlscheck.InspectChain([]*x509.Certificate{cert2048}, "", now, tlscheck.Options{})
	if err != nil {
		t.Fatalf("InspectChain error: %v", err)
	}
	if _, found := hasFinding(f2048, "TLS006"); found {
		t.Errorf("expected no TLS006 for 2048 bit key, got %+v", f2048)
	}

	// Leaf with SignatureAlgorithm SHA1WithRSA -> TLS007
	leafSha1 := &x509.Certificate{
		SignatureAlgorithm: x509.SHA1WithRSA,
		NotBefore:          time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
		Subject:            pkix.Name{CommonName: "Leaf"},
		Issuer:             pkix.Name{CommonName: "Issuer CA"},
	}
	fSha1, err := tlscheck.InspectChain([]*x509.Certificate{leafSha1}, "", now, tlscheck.Options{})
	if err != nil {
		t.Fatalf("InspectChain error: %v", err)
	}
	if _, found := hasFinding(fSha1, "TLS007"); !found {
		t.Errorf("expected TLS007 for leaf SHA1WithRSA, got %+v", fSha1)
	}

	// 2-cert chain: leaf has SHA256WithRSA, root has SHA1WithRSA and Issuer == Subject -> no TLS007
	leafSha256 := &x509.Certificate{
		SignatureAlgorithm: x509.SHA256WithRSA,
		NotBefore:          time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
		Subject:            pkix.Name{CommonName: "Leaf"},
		Issuer:             pkix.Name{CommonName: "Root CA"},
	}
	rootSha1 := &x509.Certificate{
		SignatureAlgorithm: x509.SHA1WithRSA,
		NotBefore:          time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
		Subject:            pkix.Name{CommonName: "Root CA"},
		Issuer:             pkix.Name{CommonName: "Root CA"},
	}
	twoCertChain := []*x509.Certificate{leafSha256, rootSha1}
	fTwo, err := tlscheck.InspectChain(twoCertChain, "", now, tlscheck.Options{})
	if err != nil {
		t.Fatalf("InspectChain error: %v", err)
	}
	if _, found := hasFinding(fTwo, "TLS007"); found {
		t.Errorf("expected no TLS007 for root self-signed SHA1WithRSA in 2-cert chain, got %+v", fTwo)
	}
}

// Acceptance item 5:
// Probe against httptest.NewTLSServer with serverName "example.com" and Roots containing
// server.Certificate() returns Report.Version "TLS 1.3" and no TLS004 or TLS010;
// with Roots x509.NewCertPool() it returns TLS010 and TLS005
func TestAcceptance5_ProbeTLSServer(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	serverCert := ts.Certificate()
	now := serverCert.NotBefore.Add(24 * time.Hour)

	// 1. Probe with Roots containing server.Certificate() and serverName "example.com"
	// Note: httptest default cert SAN includes "example.com"
	rootsValid := x509.NewCertPool()
	rootsValid.AddCert(serverCert)

	rep, err := tlscheck.Probe(context.Background(), ts.Listener.Addr().String(), "example.com", now, tlscheck.Options{
		Roots: rootsValid,
	})
	if err != nil {
		t.Fatalf("Probe failed: %v", err)
	}
	if rep.Version != "TLS 1.3" {
		t.Errorf("Report.Version = %q, want TLS 1.3", rep.Version)
	}
	if _, found := hasFinding(rep.Findings, "TLS004"); found {
		t.Errorf("expected no TLS004, got %+v", rep.Findings)
	}
	if _, found := hasFinding(rep.Findings, "TLS010"); found {
		t.Errorf("expected no TLS010, got %+v", rep.Findings)
	}

	// 2. Probe with empty Roots x509.NewCertPool()
	rootsEmpty := x509.NewCertPool()
	repUntrusted, err := tlscheck.Probe(context.Background(), ts.Listener.Addr().String(), "example.com", now, tlscheck.Options{
		Roots: rootsEmpty,
	})
	if err != nil {
		t.Fatalf("Probe failed with empty roots: %v", err)
	}
	if _, found := hasFinding(repUntrusted.Findings, "TLS010"); !found {
		t.Errorf("expected TLS010 with untrusted roots, got %+v", repUntrusted.Findings)
	}
	if _, found := hasFinding(repUntrusted.Findings, "TLS005"); !found {
		t.Errorf("expected TLS005 for single self-signed cert, got %+v", repUntrusted.Findings)
	}
}

// Acceptance item 6:
// Probe with a Dial returning an error returns an error matching ErrProbe with errors.Is;
// against a listener that accepts but never answers, a ctx with a 20 ms deadline makes
// Probe return ErrProbe in under 1 s
func TestAcceptance6_ProbeErrorsAndTimeout(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	// Dial returning an error
	failDialOpts := tlscheck.Options{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, errors.New("dial connection refused simulation")
		},
	}
	_, err := tlscheck.Probe(ctx, "127.0.0.1:0", "example.com", now, failDialOpts)
	if !errors.Is(err, tlscheck.ErrProbe) {
		t.Fatalf("expected errors.Is(err, ErrProbe), got %v", err)
	}

	// Listener accepts but never writes
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer l.Close()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			// Hold connection open without sending TLS server handshake data
			go func(c net.Conn) {
				buf := make([]byte, 1024)
				for {
					if _, err := c.Read(buf); err != nil {
						_ = c.Close()
						return
					}
				}
			}(conn)
		}
	}()

	timeoutCtx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, probeErr := tlscheck.Probe(timeoutCtx, l.Addr().String(), "example.com", now, tlscheck.Options{})
	elapsed := time.Since(start)

	if !errors.Is(probeErr, tlscheck.ErrProbe) {
		t.Fatalf("expected ErrProbe on timeout, got %v", probeErr)
	}
	if elapsed > 1*time.Second {
		t.Fatalf("Probe took %v, expected under 1s", elapsed)
	}
}

// Acceptance item 7:
// InspectChain(nil, ...) returns an error matching ErrEmptyChain;
// findings are sorted by Code and marshal with JSON keys "code", "severity" and "message"
func TestAcceptance7_EmptyChainAndJSONFormatting(t *testing.T) {
	now := time.Now()
	_, err := tlscheck.InspectChain(nil, "example.com", now, tlscheck.Options{})
	if !errors.Is(err, tlscheck.ErrEmptyChain) {
		t.Fatalf("InspectChain(nil) err = %v, want ErrEmptyChain", err)
	}

	_, errEmpty := tlscheck.InspectChain([]*x509.Certificate{}, "example.com", now, tlscheck.Options{})
	if !errors.Is(errEmpty, tlscheck.ErrEmptyChain) {
		t.Fatalf("InspectChain([]*x509.Certificate{}) err = %v, want ErrEmptyChain", errEmpty)
	}

	// Create multiple findings to verify sorting and JSON marshaling
	leaf := &x509.Certificate{
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
		DNSNames:  []string{"other.com"},
		Subject:   pkix.Name{CommonName: "self"},
		Issuer:    pkix.Name{CommonName: "self"},
	}
	findings, err := tlscheck.InspectChain([]*x509.Certificate{leaf}, "example.com", time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), tlscheck.Options{})
	if err != nil {
		t.Fatalf("InspectChain error: %v", err)
	}

	// Verify sorted order
	for i := 0; i < len(findings)-1; i++ {
		if findings[i].Code >= findings[i+1].Code {
			t.Fatalf("findings not sorted: %s >= %s", findings[i].Code, findings[i+1].Code)
		}
	}

	// Verify JSON marshaling
	b, err := json.Marshal(findings)
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}
	jsonStr := string(b)
	for _, key := range []string{"code", "severity", "message"} {
		if !strings.Contains(jsonStr, key) {
			t.Errorf("JSON output missing key %s: %s", key, jsonStr)
		}
	}
}

func TestAdditionalCoverage(t *testing.T) {
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	// ECDSA curve checks: P256 (supported) vs secp256k1 (or unsupported)
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa P256: %v", err)
	}
	certP256 := &x509.Certificate{
		PublicKey: &p256Key.PublicKey,
		NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:  time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
		Subject:   pkix.Name{CommonName: "P256"},
		Issuer:    pkix.Name{CommonName: "Issuer CA"},
	}
	fP256, err := tlscheck.InspectChain([]*x509.Certificate{certP256}, "", now, tlscheck.Options{})
	if err != nil {
		t.Fatalf("InspectChain error: %v", err)
	}
	if _, found := hasFinding(fP256, "TLS006"); found {
		t.Errorf("P-256 should not trigger TLS006")
	}

	// Other weak signatures: MD5WithRSA, ECDSAWithSHA1
	certMD5 := &x509.Certificate{
		SignatureAlgorithm: x509.MD5WithRSA,
		NotBefore:          time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
		Subject:            pkix.Name{CommonName: "MD5"},
		Issuer:             pkix.Name{CommonName: "Issuer CA"},
	}
	fMD5, _ := tlscheck.InspectChain([]*x509.Certificate{certMD5}, "", now, tlscheck.Options{})
	if _, found := hasFinding(fMD5, "TLS007"); !found {
		t.Errorf("MD5WithRSA should trigger TLS007")
	}

	certEcdsaSha1 := &x509.Certificate{
		SignatureAlgorithm: x509.ECDSAWithSHA1,
		NotBefore:          time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:           time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
		Subject:            pkix.Name{CommonName: "ECDSA-SHA1"},
		Issuer:             pkix.Name{CommonName: "Issuer CA"},
	}
	fEcdsaSha1, _ := tlscheck.InspectChain([]*x509.Certificate{certEcdsaSha1}, "", now, tlscheck.Options{})
	if _, found := hasFinding(fEcdsaSha1, "TLS007"); !found {
		t.Errorf("ECDSAWithSHA1 should trigger TLS007")
	}

	// Test Probe with TLS 1.2 maximum server
	ts12 := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	ts12.TLS = &tls.Config{
		MaxVersion: tls.VersionTLS12,
	}
	ts12.StartTLS()
	defer ts12.Close()

	pool := x509.NewCertPool()
	pool.AddCert(ts12.Certificate())
	rep12, err := tlscheck.Probe(context.Background(), ts12.Listener.Addr().String(), "example.com", ts12.Certificate().NotBefore.Add(time.Hour), tlscheck.Options{
		Roots: pool,
	})
	if err != nil {
		t.Fatalf("Probe TLS 1.2 failed: %v", err)
	}
	if rep12.Version != "TLS 1.2" {
		t.Errorf("Version = %q, want TLS 1.2", rep12.Version)
	}
	if rep12.CipherSuite == "" {
		t.Errorf("CipherSuite is empty")
	}
}

func ExampleInspectChain() {
	notBefore := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2026, time.December, 1, 0, 0, 0, 0, time.UTC)
	leaf := &x509.Certificate{
		NotBefore: notBefore,
		NotAfter:  notAfter,
		Subject:   pkix.Name{CommonName: "example.com"},
		Issuer:    pkix.Name{CommonName: "Example CA"},
	}

	now := time.Date(2026, time.November, 6, 0, 0, 0, 0, time.UTC)
	findings, _ := tlscheck.InspectChain([]*x509.Certificate{leaf}, "", now, tlscheck.Options{WarnDays: 30})
	for _, f := range findings {
		fmt.Printf("%s [%s]: %s\n", f.Code, f.Severity, f.Message)
	}
	// Output:
	// TLS003 [medium]: leaf certificate expires in 25 days (2026-12-01)
}
