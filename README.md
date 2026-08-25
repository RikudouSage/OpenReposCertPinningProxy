# OpenRepos Cert Pinning Proxy

Small reverse proxy for [openrepos.net](https://openrepos.net/). It exists as a backup path when the upstream TLS certificate expires.

Live instance: [openrepos.rikudou.dev](https://openrepos.rikudou.dev/).

## What it does

- Proxies all requests to `https://openrepos.net`.
- Serves its own blocking `robots.txt`.
- Adds `X-Robots-Tag: noindex, nofollow, noarchive, nosnippet, noimageindex`.
- Inserts a fixed warning banner into HTML responses.
- Keeps the upstream body unchanged otherwise.
- Records the upstream certificate fingerprint and can temporarily accept the same expired certificate.

## How it works

1. [`main.go`](main.go) builds one `httputil.ReverseProxy` targeting `https://openrepos.net`.
2. [`proxy.go`](proxy.go) rewrites outbound proxy headers, cookies, and upstream redirects so the proxy origin still works.
3. [`info_header.go`](info_header.go) reads [`assets/info_header.html`](assets/info_header.html) and inserts it immediately after the opening `<body>` tag.
4. [`certificate_transport.go`](certificate_transport.go) stores a SHA-256 fingerprint for the current upstream cert and only falls back to an expired cert when that fingerprint still matches.

## Run

```sh
CERT_PATH=/path/to/openrepos-cert-fingerprint PROXY_ADDR=:8080 go run .
```

`CERT_PATH` is required. `PROXY_ADDR` defaults to `:8080`.

## Review points

- Banner-only body change: [`prependInfoHeader`](info_header.go) and [`insertAfterBodyTag`](info_header.go).
- Tests proving JSON and compressed responses are not rewritten: [`TestPrependInfoHeaderSkipsJSONResponse`](main_test.go) and [`TestPrependInfoHeaderSkipsCompressedResponse`](main_test.go).
- Proxy request/response rewriting: [`newProxy`](proxy.go).
- No-index behavior: [`robots_header.go`](robots_header.go), [`robots.go`](robots.go), and [`assets/robots.txt`](assets/robots.txt).
- Expired-certificate fallback rules: [`retryExpiredCertificate`](certificate_transport.go).
