package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestURLRewriter(t *testing.T) {
	rewrite := newURLRewriter("openrepos.net", "http://proxy.example:8080")
	input := `https://openrepos.net/a http://OPENREPOS.NET/b //openrepos.net/c https:\/\/openrepos.net\/d //openrepos.net.evil/a https://openrepos.net@evil/a https://openrepos.net:8443/a ftp://openrepos.net/file https://other.example/a`
	want := `http://proxy.example:8080/a http://proxy.example:8080/b http://proxy.example:8080/c http:\/\/proxy.example:8080\/d //openrepos.net.evil/a https://openrepos.net@evil/a https://openrepos.net:8443/a ftp://openrepos.net/file https://other.example/a`
	if got := rewrite(input); got != want {
		t.Fatalf("unexpected URLs:\n got: %s\nwant: %s", got, want)
	}
}

func TestProxyRewritesResponses(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"original"`)
		w.Header().Set("Content-Digest", "original")
		w.Header().Set("Link", `<http://`+r.Host+`/style.css>; rel=preload`)
		w.Header().Set("Location", "http://"+r.Host+"/next")
		switch r.URL.Path {
		case "/html":
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, `<body><link href="http://`+r.Host+`/style.css"><a href="https://other.example/">other</a></body>`)
		case "/css":
			w.Header().Set("Content-Type", "text/css")
			w.Header().Set("Content-Encoding", "gzip")
			compressed := gzip.NewWriter(w)
			io.WriteString(compressed, `a{background:url("http://`+r.Host+`/image.png")}`)
			compressed.Close()
		case "/json":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"url":"http:\/\/`+r.Host+`\/file"}`)
		case "/binary":
			w.Header().Set("Content-Type", "application/octet-stream")
			io.WriteString(w, "http://"+r.Host+"/file")
		}
	}))
	defer upstream.Close()
	target := mustParseURL(t, upstream.URL)
	proxy := newProxy(target, t.TempDir()+"/cert")

	for _, tc := range []struct {
		path, expected string
		modified       bool
	}{
		{"/html", `href="https://proxy.example/style.css"`, true},
		{"/css", `url("https://proxy.example/image.png")`, true},
		{"/json", `https:\/\/proxy.example\/file`, true},
		{"/binary", upstream.URL + "/file", false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "https://proxy.example"+tc.path, nil)
			recorder := httptest.NewRecorder()
			proxy.ServeHTTP(recorder, request)
			response := recorder.Result()
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusOK || !strings.Contains(string(body), tc.expected) {
				t.Fatalf("status %d, unexpected body: %s", response.StatusCode, body)
			}
			if got := response.Header.Get("Location"); got != "https://proxy.example/next" {
				t.Errorf("unexpected Location: %q", got)
			}
			if got := response.Header.Get("Link"); got != `<https://proxy.example/style.css>; rel=preload` {
				t.Errorf("unexpected Link: %q", got)
			}
			if tc.modified && (response.Header.Get("ETag") != "" || response.Header.Get("Content-Digest") != "") {
				t.Error("modified response retained upstream validators")
			}
			if tc.modified && response.ContentLength != int64(len(body)) {
				t.Errorf("unexpected content length: %d, body length %d", response.ContentLength, len(body))
			}
			if tc.path == "/css" && response.Header.Get("Content-Encoding") != "" {
				t.Error("decoded CSS retained Content-Encoding")
			}
			if tc.path == "/html" && (!bytes.Contains(body, []byte("backup proxy")) || !bytes.Contains(body, []byte(`href="https://other.example/"`))) {
				t.Errorf("banner or external link missing: %s", body)
			}
		})
	}
}

func TestRewriteResponseLeavesPartialAndUnsupportedContentAlone(t *testing.T) {
	target := mustParseURL(t, "https://openrepos.net")
	request := httptest.NewRequest(http.MethodGet, "https://openrepos.net/file", nil)
	request = request.WithContext(context.WithValue(request.Context(), proxyHostContextKey, "proxy.example"))
	for _, tc := range []struct {
		name, encoding, contentType string
		status                      int
	}{
		{"partial", "", "text/html", http.StatusPartialContent},
		{"unsupported encoding", "br", "text/css", http.StatusOK},
		{"wide charset", "", "text/html; charset=utf-16", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := "https://openrepos.net/file"
			response := &http.Response{Request: request, StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{"Content-Type": {tc.contentType}, "Content-Encoding": {tc.encoding}}}
			if err := rewriteResponseURLs(response, target); err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(response.Body)
			if err != nil || string(got) != body {
				t.Fatalf("unexpected body %q, error %v", got, err)
			}
		})
	}
}
