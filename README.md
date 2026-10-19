# OpenRepos Cert Pinning Proxy

Small reverse proxy for [openrepos.net](https://openrepos.net/). It exists as a backup path when the upstream TLS certificate expires.

Live instance: [openrepos.rikudou.dev](https://openrepos.rikudou.dev/).

## What it does

- Proxies all requests to `https://openrepos.net`.
- Serves its own blocking `robots.txt`.
- Adds `X-Robots-Tag: noindex, nofollow, noarchive, nosnippet, noimageindex`.
- Inserts a fixed warning banner into HTML responses.
- Rewrites upstream-origin URLs in HTML, CSS, JavaScript, JSON, XML, SVG and other text responses, as well as redirects and URL-bearing response headers. Other origins and binary content are left alone.
- Records the upstream certificate fingerprint and can temporarily accept the same expired certificate.

## How it works

1. [`main.go`](main.go) builds one `httputil.ReverseProxy` targeting `https://openrepos.net`.
2. [`proxy.go`](proxy.go) rewrites outbound proxy headers and cookies; [`response_urls.go`](response_urls.go) rewrites upstream URLs to the proxy origin.
3. [`info_header.go`](info_header.go) reads [`assets/info_header.html`](assets/info_header.html) and inserts it immediately after the opening `<body>` tag.
4. [`certificate_transport.go`](certificate_transport.go) stores a SHA-256 fingerprint for the current upstream cert and only falls back to an expired cert when that fingerprint still matches.

## Run

```sh
CERT_PATH=/path/to/openrepos-cert-fingerprint PROXY_ADDR=:8080 go run .
```

`CERT_PATH` is required. `PROXY_ADDR` defaults to `:8080`.

## Review points

- Response URL rewriting: [`rewriteResponseURLs`](response_urls.go). Partial responses, content encodings other than gzip, and UTF-16/UTF-32 text are passed through unchanged.
- Proxy request/response rewriting: [`newProxy`](proxy.go).
- No-index behavior: [`robots_header.go`](robots_header.go), [`robots.go`](robots.go), and [`assets/robots.txt`](assets/robots.txt).
- Expired-certificate fallback rules: [`retryExpiredCertificate`](certificate_transport.go).
