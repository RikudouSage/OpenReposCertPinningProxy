package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const certificateUpdateDebounce = 5 * time.Minute

type certificateTrackingTransport struct {
	base       *http.Transport
	targetHost string
	certPath   string
	debounce   time.Duration
	now        func() time.Time

	mu                sync.Mutex
	lastUpdate        time.Time
	trustExpiredUntil time.Time
}

func newCertificateTrackingTransport(targetHost string, certPath string) http.RoundTripper {
	baseTransport := http.DefaultTransport.(*http.Transport).Clone()

	return &certificateTrackingTransport{
		base:       baseTransport,
		targetHost: targetHost,
		certPath:   certPath,
		debounce:   certificateUpdateDebounce,
		now:        time.Now,
	}
}

func (transport *certificateTrackingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if transport.shouldTrustExpiredCertificate() {
		return transport.retryExpiredCertificate(request)
	}

	response, err := transport.base.RoundTrip(request)
	if debugExpired && err == nil {
		err = errors.New("debug error")
	}
	if err == nil {
		transport.updateCertificateFingerprint(response)
		return response, nil
	}
	if !isExpiredCertificateError(err) {
		return nil, err
	}

	response, retryErr := transport.retryExpiredCertificate(request)
	if retryErr != nil {
		return nil, err
	}

	transport.cacheExpiredCertificateTrust()
	return response, nil
}

func (transport *certificateTrackingTransport) shouldTrustExpiredCertificate() bool {
	transport.mu.Lock()
	defer transport.mu.Unlock()

	return transport.now().Before(transport.trustExpiredUntil)
}

func (transport *certificateTrackingTransport) cacheExpiredCertificateTrust() {
	transport.mu.Lock()
	defer transport.mu.Unlock()

	transport.trustExpiredUntil = transport.now().Add(transport.debounce)
}

func (transport *certificateTrackingTransport) updateCertificateFingerprint(response *http.Response) {
	if response == nil || response.TLS == nil || len(response.TLS.PeerCertificates) == 0 {
		return
	}

	transport.mu.Lock()
	defer transport.mu.Unlock()

	now := transport.now()
	if !transport.lastUpdate.IsZero() && now.Sub(transport.lastUpdate) < transport.debounce {
		return
	}

	fingerprint := certificateFingerprint(response.TLS.PeerCertificates[0])
	if err := writeCertificateFingerprint(transport.certPath, fingerprint); err != nil {
		log.Printf("could not update certificate fingerprint: %v", err)
		return
	}

	transport.lastUpdate = now
}

func (transport *certificateTrackingTransport) retryExpiredCertificate(request *http.Request) (*http.Response, error) {
	storedFingerprint, err := readCertificateFingerprint(transport.certPath)
	if err != nil {
		return nil, err
	}

	retryTransport := transport.base.Clone()
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         transport.targetHost,
		VerifyConnection: func(connectionState tls.ConnectionState) error {
			if len(connectionState.PeerCertificates) == 0 {
				return errors.New("server did not provide a certificate")
			}

			certificate := connectionState.PeerCertificates[0]
			if transport.now().Before(certificate.NotAfter) && !debugExpired {
				return errors.New("certificate is not expired")
			}
			if err := certificate.VerifyHostname(transport.targetHost); err != nil {
				return err
			}
			if certificateFingerprint(certificate) != storedFingerprint {
				return errors.New("expired certificate fingerprint does not match stored fingerprint")
			}

			return nil
		},
	}
	if retryTransport.TLSClientConfig != nil {
		tlsConfig.NextProtos = retryTransport.TLSClientConfig.NextProtos
	}
	retryTransport.TLSClientConfig = tlsConfig

	return retryTransport.RoundTrip(request.Clone(request.Context()))
}

func isExpiredCertificateError(err error) bool {
	if debugExpired {
		return !debugExpiredErr
	}

	var certificateError x509.CertificateInvalidError
	return errors.As(err, &certificateError) && certificateError.Reason == x509.Expired
}

func certificateFingerprint(certificate *x509.Certificate) string {
	fingerprint := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(fingerprint[:])
}

func readCertificateFingerprint(certPath string) (string, error) {
	content, err := os.ReadFile(certPath)
	if err != nil {
		return "", err
	}

	fingerprint := strings.TrimSpace(string(content))
	if fingerprint == "" {
		return "", errors.New("stored certificate fingerprint is empty")
	}

	return fingerprint, nil
}

func writeCertificateFingerprint(certPath string, fingerprint string) error {
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return err
	}

	temporaryPath := certPath + ".tmp"
	if err := os.WriteFile(temporaryPath, []byte(fingerprint+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, certPath); err != nil {
		return fmt.Errorf("replace certificate fingerprint: %w", err)
	}

	return nil
}
