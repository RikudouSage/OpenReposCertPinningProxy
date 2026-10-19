package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// rewriteResponseURLs changes only URLs whose authority is the upstream host.
// Relative URLs already resolve against the proxy and need no changes.
func rewriteResponseURLs(response *http.Response, target *url.URL) error {
	if response.Request == nil || proxyHost(response.Request) == "" {
		return nil
	}

	scheme := proxyScheme(response.Request)
	if scheme == "" {
		scheme = "http"
	}

	origin := scheme + "://" + proxyHost(response.Request)
	rewriter := newURLRewriter(target.Host, origin)

	for _, name := range []string{"Location", "Content-Location", "Link", "Refresh"} {
		for i, value := range response.Header.Values(name) {
			response.Header[name][i] = rewriter(value)
		}
	}

	if response.Body == nil || response.Request.Method == http.MethodHead || response.StatusCode == http.StatusPartialContent || !isTextualResponse(response.Header.Get("Content-Type")) {
		return nil
	}

	var reader io.Reader = response.Body
	encoding := strings.TrimSpace(response.Header.Get("Content-Encoding"))
	if encoding != "" && !strings.EqualFold(encoding, "identity") {
		if !strings.EqualFold(encoding, "gzip") {
			return nil
		}

		gzipReader, err := gzip.NewReader(response.Body)
		if err != nil {
			return fmt.Errorf("decode upstream gzip response: %w", err)
		}
		defer gzipReader.Close()

		reader = gzipReader
	}

	body, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("read upstream response: %w", err)
	}
	if err := response.Body.Close(); err != nil {
		return err
	}

	rewritten := []byte(rewriter(string(body)))
	response.Body = io.NopCloser(bytes.NewReader(rewritten))
	if !bytes.Equal(body, rewritten) || (encoding != "" && !strings.EqualFold(encoding, "identity")) {
		response.Header.Del("Content-Encoding")
		setModifiedBodyHeaders(response, len(rewritten))
	}

	return nil
}

func isTextualResponse(contentType string) bool {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	charset := strings.ToLower(params["charset"])
	if strings.HasPrefix(charset, "utf-16") || strings.HasPrefix(charset, "utf-32") {
		return false
	}
	return strings.HasPrefix(mediaType, "text/") ||
		strings.HasSuffix(mediaType, "+json") || strings.HasSuffix(mediaType, "+xml") ||
		mediaType == "application/json" || mediaType == "application/javascript" ||
		mediaType == "application/x-javascript" || mediaType == "application/xml" ||
		mediaType == "application/xhtml+xml" || mediaType == "image/svg+xml"
}

func newURLRewriter(upstreamHost, proxyOrigin string) func(string) string {
	// JSON and JavaScript can also escape the slashes in a URL.
	pattern := regexp.MustCompile(`(?i)(?:https?:)?(?://|\\/\\/)` + regexp.QuoteMeta(upstreamHost))

	return func(value string) string {
		matches := pattern.FindAllStringIndex(value, -1)
		var result strings.Builder
		last := 0

		for _, match := range matches {
			start, end := match[0], match[1]
			// Reject other schemes and hostnames which merely start with our host.
			if (start > 0 && value[start-1] == ':') || (end < len(value) && !urlHostEnd(value[end])) {
				continue
			}

			result.WriteString(value[last:start])
			replacement := proxyOrigin
			if strings.Contains(value[start:end], `\/`) {
				replacement = strings.ReplaceAll(replacement, "/", `\/`)
			}

			result.WriteString(replacement)
			last = end
		}

		if last == 0 {
			return value
		}
		result.WriteString(value[last:])

		return result.String()
	}
}

func urlHostEnd(b byte) bool {
	switch b {
	case '/', '\\', '?', '#', ' ', '\t', '\r', '\n', '"', '\'', '<', '>', ')', ']', '}', ',', ';':
		return true
	default:
		return false
	}
}

func setModifiedBodyHeaders(response *http.Response, length int) {
	response.ContentLength = int64(length)
	response.Header.Set("Content-Length", strconv.Itoa(length))
	clearModifiedBodyValidators(response)
}

func clearModifiedBodyValidators(response *http.Response) {
	for _, name := range []string{"ETag", "Last-Modified", "Content-MD5", "Content-Digest", "Repr-Digest", "Digest", "Accept-Ranges"} {
		response.Header.Del(name)
	}
}
