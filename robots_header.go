package main

import "net/http"

const robotsHeaderValue = "noindex, nofollow, noarchive, nosnippet, noimageindex"

func noIndexHandler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Robots-Tag", robotsHeaderValue)
		handler.ServeHTTP(writer, request)
	})
}
