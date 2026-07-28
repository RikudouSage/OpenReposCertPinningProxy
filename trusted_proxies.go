package main

import (
	"os"
	"strings"
)

var allowedProxies []string

func init() {
	allowedProxies = []string{
		"127.0.0.1",
		"::1",
	}

	trustedProxies := strings.TrimSpace(os.Getenv("TRUSTED_PROXIES"))
	if trustedProxies == "" {
		return
	}

	allowedProxies = splitTrustedProxies(trustedProxies)
}

func splitTrustedProxies(trustedProxies string) []string {
	parts := strings.Split(trustedProxies, ",")
	proxies := make([]string, 0, len(parts))
	for _, part := range parts {
		proxy := strings.TrimSpace(part)
		if proxy != "" {
			proxies = append(proxies, proxy)
		}
	}

	return proxies
}
