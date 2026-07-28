package main

import (
	"context"
	"net/http"
	"net/http/httputil"
	"net/url"
	"testing"
)

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
}

func TestProxyRewriteUsesUpstreamForwardedHostAndStoresProxyOrigin(t *testing.T) {
	targetURL := mustParseURL(t, "https://openrepos.net")
	proxy := newProxy(targetURL)
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
	proxy := newProxy(targetURL)
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
	proxy := newProxy(targetURL)
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

func mustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}

	return parsedURL
}
