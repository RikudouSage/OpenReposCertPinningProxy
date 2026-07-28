package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRobotsHandler(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	recorder := httptest.NewRecorder()

	robotsHandler(recorder, request)

	response := recorder.Result()
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status: %d", response.StatusCode)
	}
	if got := response.Header.Get("Content-Type"); got != "text/plain; charset=utf-8" {
		t.Fatalf("unexpected content type: %q", got)
	}
	if got := response.Header.Get("X-Robots-Tag"); got != robotsHeaderValue {
		t.Fatalf("unexpected X-Robots-Tag: %q", got)
	}
	if got := recorder.Body.String(); got != "User-agent: *\nDisallow: /" {
		t.Fatalf("unexpected robots.txt body: %q", got)
	}
}

func TestNoIndexHandler(t *testing.T) {
	handler := noIndexHandler(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodGet, "/anything", nil)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	response := recorder.Result()
	defer response.Body.Close()

	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected status: %d", response.StatusCode)
	}
	if got := response.Header.Get("X-Robots-Tag"); got != robotsHeaderValue {
		t.Fatalf("unexpected X-Robots-Tag: %q", got)
	}
}

func TestPrependInfoHeaderForHTMLResponse(t *testing.T) {
	response := &http.Response{
		Header: http.Header{
			"Content-Type": {"text/html; charset=utf-8"},
		},
		Body: io.NopCloser(strings.NewReader("<html><body class=\"page\"><main>Content</main></body></html>")),
	}

	if err := prependInfoHeader(response); err != nil {
		t.Fatal(err)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(body), "<body class=\"page\"><div") {
		t.Fatalf("info header was not inserted after body tag: %s", body)
	}
	if !strings.Contains(string(body), "https://openrepos.net/") {
		t.Fatalf("canonical link missing from info header: %s", body)
	}
	if got := response.Header.Get("Content-Length"); got == "" {
		t.Fatal("expected Content-Length to be updated")
	}
}

func TestPrependInfoHeaderSkipsJSONResponse(t *testing.T) {
	originalBody := `{"ok":true}`
	response := &http.Response{
		Header: http.Header{
			"Content-Type": {"application/json"},
		},
		Body: io.NopCloser(strings.NewReader(originalBody)),
	}

	if err := prependInfoHeader(response); err != nil {
		t.Fatal(err)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != originalBody {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestPrependInfoHeaderSkipsCompressedResponse(t *testing.T) {
	originalBody := "<html><body>compressed</body></html>"
	response := &http.Response{
		Header: http.Header{
			"Content-Type":     {"text/html"},
			"Content-Encoding": {"gzip"},
		},
		Body: io.NopCloser(strings.NewReader(originalBody)),
	}

	if err := prependInfoHeader(response); err != nil {
		t.Fatal(err)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != originalBody {
		t.Fatalf("unexpected body: %s", body)
	}
	if got := response.Header.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("unexpected Content-Encoding: %q", got)
	}
}

func TestInsertAfterBodyTagSkipsBodylessHTML(t *testing.T) {
	originalBody := []byte("<html><main>Content</main></html>")
	if got := insertAfterBodyTag(originalBody, []byte("header")); !bytes.Equal(got, originalBody) {
		t.Fatalf("unexpected body: %s", got)
	}
}

func TestRewriteRequestHeadersForUpstream(t *testing.T) {
	targetURL := mustParseURL(t, "https://openrepos.net")
	inboundRequest, err := http.NewRequest(http.MethodPost, "http://localhost:8080/user/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	inboundRequest.Host = "localhost:8080"
	inboundRequest.Header.Set("Origin", "http://localhost:8080")
	inboundRequest.Header.Set("Referer", "http://localhost:8080/user/login")
	inboundRequest.Header.Set("Cookie", "SESSabc=123")
	inboundRequest.Header.Set("Accept-Encoding", "gzip")

	outboundRequest := inboundRequest.Clone(inboundRequest.Context())
	request := &httputil.ProxyRequest{
		In:  inboundRequest,
		Out: outboundRequest,
	}

	rewriteRequestHeaders(request, targetURL)

	if got := outboundRequest.Header.Get("Origin"); got != "https://openrepos.net" {
		t.Fatalf("unexpected Origin: %q", got)
	}
	if got := outboundRequest.Header.Get("Referer"); got != "https://openrepos.net/user/login" {
		t.Fatalf("unexpected Referer: %q", got)
	}
	if got := outboundRequest.Header.Get("Cookie"); got != "SESSabc=123" {
		t.Fatalf("unexpected Cookie: %q", got)
	}
	if got := outboundRequest.Header.Get("Accept-Encoding"); got != "" {
		t.Fatalf("unexpected Accept-Encoding: %q", got)
	}
}

func TestProxyRewriteUsesUpstreamForwardedHostAndStoresProxyOrigin(t *testing.T) {
	targetURL := mustParseURL(t, "https://openrepos.net")
	proxy := newProxy(targetURL, t.TempDir()+"/cert")
	inboundRequest, err := http.NewRequest(http.MethodGet, "http://localhost:8080/user/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	inboundRequest.Host = "localhost:8080"

	outboundRequest := inboundRequest.Clone(inboundRequest.Context())
	request := &httputil.ProxyRequest{
		In:  inboundRequest,
		Out: outboundRequest,
	}

	proxy.Rewrite(request)

	if got := request.Out.URL.Scheme; got != "https" {
		t.Fatalf("unexpected upstream scheme: %q", got)
	}
	if got := request.Out.URL.Host; got != "openrepos.net" {
		t.Fatalf("unexpected upstream host: %q", got)
	}
	if got := request.Out.Header.Get("X-Forwarded-Host"); got != "openrepos.net" {
		t.Fatalf("unexpected X-Forwarded-Host: %q", got)
	}
	if got := request.Out.Header.Get("X-Forwarded-Proto"); got != "https" {
		t.Fatalf("unexpected X-Forwarded-Proto: %q", got)
	}
	if got := proxyHost(request.Out); got != "localhost:8080" {
		t.Fatalf("unexpected proxy host context: %q", got)
	}
	if got := proxyScheme(request.Out); got != "http" {
		t.Fatalf("unexpected proxy scheme context: %q", got)
	}
}

func TestProxyRewriteUsesForwardedProtoFromTLSProxy(t *testing.T) {
	targetURL := mustParseURL(t, "https://openrepos.net")
	proxy := newProxy(targetURL, t.TempDir()+"/cert")
	inboundRequest, err := http.NewRequest(http.MethodGet, "http://localhost:8080/user/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	inboundRequest.Host = "proxy.example"
	inboundRequest.RemoteAddr = "127.0.0.1:12345"
	inboundRequest.Header.Set("X-Forwarded-Proto", "https")

	request := &httputil.ProxyRequest{
		In:  inboundRequest,
		Out: inboundRequest.Clone(inboundRequest.Context()),
	}

	proxy.Rewrite(request)

	if got := proxyScheme(request.Out); got != "https" {
		t.Fatalf("unexpected proxy scheme context: %q", got)
	}
}

func TestProxyRewriteIgnoresForwardedProtoFromUntrustedRemote(t *testing.T) {
	targetURL := mustParseURL(t, "https://openrepos.net")
	proxy := newProxy(targetURL, t.TempDir()+"/cert")
	inboundRequest, err := http.NewRequest(http.MethodGet, "http://localhost:8080/user/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	inboundRequest.Host = "proxy.example"
	inboundRequest.RemoteAddr = "203.0.113.10:12345"
	inboundRequest.Header.Set("X-Forwarded-Proto", "https")

	request := &httputil.ProxyRequest{
		In:  inboundRequest,
		Out: inboundRequest.Clone(inboundRequest.Context()),
	}

	proxy.Rewrite(request)

	if got := proxyScheme(request.Out); got != "http" {
		t.Fatalf("unexpected proxy scheme context: %q", got)
	}
}

func TestIsAllowedProxySupportsCIDR(t *testing.T) {
	originalAllowedProxies := allowedProxies
	allowedProxies = []string{"10.0.0.0/8"}
	t.Cleanup(func() {
		allowedProxies = originalAllowedProxies
	})

	if !isAllowedProxy("10.1.2.3:12345") {
		t.Fatal("expected CIDR proxy match")
	}
	if isAllowedProxy("192.0.2.1:12345") {
		t.Fatal("expected non-matching proxy to be rejected")
	}
}

func TestSplitTrustedProxies(t *testing.T) {
	proxies := splitTrustedProxies("127.0.0.1, 192.168.48.0/20,, ::1 ")

	if len(proxies) != 3 {
		t.Fatalf("expected 3 proxies, got %d: %#v", len(proxies), proxies)
	}
	if proxies[0] != "127.0.0.1" || proxies[1] != "192.168.48.0/20" || proxies[2] != "::1" {
		t.Fatalf("unexpected proxies: %#v", proxies)
	}
}

func TestRewriteCookiesForLocalHTTPProxy(t *testing.T) {
	targetURL := mustParseURL(t, "https://openrepos.net")
	request, err := http.NewRequest(http.MethodGet, "https://openrepos.net/user/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	request = request.WithContext(context.WithValue(request.Context(), proxySchemeContextKey, "http"))

	response := &http.Response{
		Header: http.Header{
			"Set-Cookie": {
				"SESSabc=123; Path=/; Domain=.openrepos.net; Secure; SameSite=None; Partitioned; HttpOnly",
			},
		},
		Request: request,
	}

	rewriteCookies(response, targetURL)

	cookies := response.Header.Values("Set-Cookie")
	if len(cookies) != 1 {
		t.Fatalf("expected 1 Set-Cookie header, got %d", len(cookies))
	}
	if cookies[0] != "SESSabc=123; Path=/; HttpOnly; SameSite=Lax" {
		t.Fatalf("unexpected Set-Cookie header: %q", cookies[0])
	}
}

func TestRewriteCookiesPreservesSecureSameSiteNoneForHTTPSProxy(t *testing.T) {
	targetURL := mustParseURL(t, "https://openrepos.net")
	request, err := http.NewRequest(http.MethodGet, "https://openrepos.net/user/login", nil)
	if err != nil {
		t.Fatal(err)
	}
	request = request.WithContext(context.WithValue(request.Context(), proxySchemeContextKey, "https"))

	response := &http.Response{
		Header: http.Header{
			"Set-Cookie": {
				"SESSabc=123; Path=/; Domain=.openrepos.net; Secure; SameSite=None; HttpOnly",
			},
		},
		Request: request,
	}

	rewriteCookies(response, targetURL)

	cookies := response.Header.Values("Set-Cookie")
	if len(cookies) != 1 {
		t.Fatalf("expected 1 Set-Cookie header, got %d", len(cookies))
	}
	if cookies[0] != "SESSabc=123; Path=/; HttpOnly; Secure; SameSite=None" {
		t.Fatalf("unexpected Set-Cookie header: %q", cookies[0])
	}
}

func TestCertificateTrackingTransportRetriesMatchingExpiredCertificate(t *testing.T) {
	expiredCertificate, certificatePool := newExpiredLocalhostCertificate(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{expiredCertificate}}
	server.StartTLS()
	defer server.Close()

	certPath := t.TempDir() + "/openrepos-cert"
	if err := os.WriteFile(certPath, []byte(certificateFingerprint(expiredCertificate.Leaf)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	baseTransport.TLSClientConfig = &tls.Config{
		RootCAs:    certificatePool,
		ServerName: "127.0.0.1",
	}
	transport := &certificateTrackingTransport{
		base:       baseTransport,
		targetHost: "127.0.0.1",
		certPath:   certPath,
		debounce:   certificateUpdateDebounce,
		now:        time.Now,
	}
	client := &http.Client{Transport: transport}

	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected status: %d", response.StatusCode)
	}
}

func TestCertificateTrackingTransportCachesExpiredCertificateTrust(t *testing.T) {
	expiredCertificate, certificatePool := newExpiredLocalhostCertificate(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{expiredCertificate}}
	server.StartTLS()
	defer server.Close()

	certPath := t.TempDir() + "/openrepos-cert"
	if err := os.WriteFile(certPath, []byte(certificateFingerprint(expiredCertificate.Leaf)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	baseTransport.TLSClientConfig = &tls.Config{
		RootCAs:    certificatePool,
		ServerName: "127.0.0.1",
	}
	var dialCount int64
	dialer := &net.Dialer{}
	baseTransport.DialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
		atomic.AddInt64(&dialCount, 1)
		return dialer.DialContext(ctx, network, address)
	}
	transport := &certificateTrackingTransport{
		base:       baseTransport,
		targetHost: "127.0.0.1",
		certPath:   certPath,
		debounce:   certificateUpdateDebounce,
		now:        time.Now,
	}
	client := &http.Client{Transport: transport}

	response, err := client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if got := atomic.LoadInt64(&dialCount); got != 2 {
		t.Fatalf("expected first request to use verified attempt and retry, got %d dials", got)
	}

	response, err = client.Get(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if got := atomic.LoadInt64(&dialCount); got != 3 {
		t.Fatalf("expected second request to go straight to expired-cert path, got %d total dials", got)
	}
}

func TestCertificateTrackingTransportRejectsMismatchedExpiredCertificate(t *testing.T) {
	expiredCertificate, certificatePool := newExpiredLocalhostCertificate(t)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{expiredCertificate}}
	server.StartTLS()
	defer server.Close()

	certPath := t.TempDir() + "/openrepos-cert"
	if err := os.WriteFile(certPath, []byte("not-the-certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	baseTransport.TLSClientConfig = &tls.Config{
		RootCAs:    certificatePool,
		ServerName: "127.0.0.1",
	}
	transport := &certificateTrackingTransport{
		base:       baseTransport,
		targetHost: "127.0.0.1",
		certPath:   certPath,
		debounce:   certificateUpdateDebounce,
		now:        time.Now,
	}
	client := &http.Client{Transport: transport}

	response, err := client.Get(server.URL)
	if err == nil {
		response.Body.Close()
		t.Fatal("expected request to fail")
	}
}

func mustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}

	return parsedURL
}

func newExpiredLocalhostCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     time.Now().Add(-time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCertificate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCertificate, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	certificatePool := x509.NewCertPool()
	certificatePool.AddCert(caCertificate)

	return tls.Certificate{
		Certificate: [][]byte{leafDER, caDER},
		PrivateKey:  leafKey,
		Leaf:        leafCertificate,
	}, certificatePool
}
