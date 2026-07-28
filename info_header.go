package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"OpenreposProxy/assets"
)

var bodyTagStart = []byte("<body")

func prependInfoHeader(response *http.Response) error {
	contentType := response.Header.Get("Content-Type")
	if !strings.Contains(strings.ToLower(contentType), "text/html") {
		return nil
	}
	if response.Body == nil {
		return nil
	}
	if response.Header.Get("Content-Encoding") != "" {
		return nil
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if err := response.Body.Close(); err != nil {
		return err
	}

	infoHeader, err := assets.Assets.ReadFile("info_header.html")
	if err != nil {
		return fmt.Errorf("read info header: %w", err)
	}

	rewrittenBody := insertAfterBodyTag(body, infoHeader)
	response.Body = io.NopCloser(bytes.NewReader(rewrittenBody))
	response.ContentLength = int64(len(rewrittenBody))
	response.Header.Set("Content-Length", strconv.Itoa(len(rewrittenBody)))
	response.Header.Del("Content-Encoding")

	return nil
}

func insertAfterBodyTag(body []byte, infoHeader []byte) []byte {
	bodyTagIndex := bytes.Index(bytes.ToLower(body), bodyTagStart)
	if bodyTagIndex == -1 {
		return body
	}

	bodyTagEndOffset := bytes.IndexByte(body[bodyTagIndex:], '>')
	if bodyTagEndOffset == -1 {
		return body
	}

	insertIndex := bodyTagIndex + bodyTagEndOffset + 1
	rewrittenBody := make([]byte, 0, len(body)+len(infoHeader))
	rewrittenBody = append(rewrittenBody, body[:insertIndex]...)
	rewrittenBody = append(rewrittenBody, infoHeader...)
	rewrittenBody = append(rewrittenBody, body[insertIndex:]...)

	return rewrittenBody
}
