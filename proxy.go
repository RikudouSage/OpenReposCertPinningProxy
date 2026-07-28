package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
)

type proxyContextKey string

const (
	proxyHostContextKey   proxyContextKey = "proxyHost"
	proxySchemeContextKey proxyContextKey = "proxyScheme"
)

func newProxy(targetURL *url.URL, certPath string) *httputil.ReverseProxy {
	proxy := &httputil.ReverseProxy{}
	proxy.Transport = newCertificateTrackingTransport(targetURL.Hostname(), certPath)
	proxy.Rewrite = func(request *httputil.ProxyRequest) {
		proxyScheme := forwardedScheme(request.In)

		request.SetURL(targetURL)
		request.Out = request.Out.WithContext(context.WithValue(request.Out.Context(), proxyHostContextKey, request.In.Host))
		request.Out = request.Out.WithContext(context.WithValue(request.Out.Context(), proxySchemeContextKey, proxyScheme))
		request.SetXForwarded()
		request.Out.Header.Set("X-Forwarded-Host", targetURL.Host)
		request.Out.Header.Set("X-Forwarded-Proto", targetURL.Scheme)
		rewriteRequestHeaders(request, targetURL)
	}

	proxy.ModifyResponse = func(response *http.Response) error {
		response.Header.Set("X-Robots-Tag", robotsHeaderValue)
		rewriteCookies(response, targetURL)

		location := response.Header.Get("Location")
		if location != "" {
			redirectURL, err := url.Parse(location)
			if err == nil && strings.EqualFold(redirectURL.Host, targetURL.Host) {
				redirectURL.Scheme = proxyScheme(response.Request)
				if redirectURL.Scheme == "" {
					redirectURL.Scheme = "http"
				}
				redirectURL.Host = proxyHost(response.Request)
				if redirectURL.Host == "" {
					redirectURL.Host = response.Request.Host
				}

				response.Header.Set("Location", redirectURL.String())
			}
		}

		return nil
	}

	return proxy
}

func forwardedScheme(request *http.Request) string {
	if scheme := request.Header.Get("X-Forwarded-Proto"); isAllowedProxy(request.RemoteAddr) && (scheme == "http" || scheme == "https") {
		return scheme
	}
	if request.TLS != nil {
		return "https"
	}

	return "http"
}

func isAllowedProxy(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}

	remoteIP, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}

	for _, allowedProxy := range allowedProxies {
		if allowedProxy == "" {
			continue
		}

		if allowedPrefix, err := netip.ParsePrefix(allowedProxy); err == nil {
			if allowedPrefix.Contains(remoteIP) {
				return true
			}
			continue
		}

		allowedIP, err := netip.ParseAddr(allowedProxy)
		if err == nil && allowedIP == remoteIP {
			return true
		}
	}

	return false
}

func rewriteRequestHeaders(request *httputil.ProxyRequest, targetURL *url.URL) {
	rewriteRequestURLHeader(request.Out.Header, "Origin", request.In, targetURL)
	rewriteRequestURLHeader(request.Out.Header, "Referer", request.In, targetURL)

	if cookie := request.In.Header.Get("Cookie"); cookie != "" {
		request.Out.Header.Set("Cookie", cookie)
	}
}

func rewriteRequestURLHeader(header http.Header, name string, inboundRequest *http.Request, targetURL *url.URL) {
	value := header.Get(name)
	if value == "" {
		return
	}

	headerURL, err := url.Parse(value)
	if err != nil || headerURL.Host != inboundRequest.Host {
		return
	}

	headerURL.Scheme = targetURL.Scheme
	headerURL.Host = targetURL.Host
	header.Set(name, headerURL.String())
}

func rewriteCookies(response *http.Response, targetURL *url.URL) {
	cookies := response.Cookies()
	if len(cookies) == 0 {
		return
	}

	response.Header.Del("Set-Cookie")
	for _, cookie := range cookies {
		if strings.EqualFold(strings.TrimPrefix(cookie.Domain, "."), targetURL.Host) {
			cookie.Domain = ""
		}
		if proxyScheme(response.Request) == "http" {
			cookie.Secure = false
			if cookie.SameSite == http.SameSiteNoneMode {
				cookie.SameSite = http.SameSiteLaxMode
			}
			cookie.Partitioned = false
		}

		response.Header.Add("Set-Cookie", cookie.String())
	}
}

func proxyHost(request *http.Request) string {
	host, _ := request.Context().Value(proxyHostContextKey).(string)
	return host
}

func proxyScheme(request *http.Request) string {
	scheme, _ := request.Context().Value(proxySchemeContextKey).(string)
	return scheme
}
