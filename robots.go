package main

import (
	"net/http"

	"OpenreposProxy/assets"
)

func robotsHandler(writer http.ResponseWriter, request *http.Request) {
	robots, err := assets.Assets.ReadFile("robots.txt")
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.Header().Set("X-Robots-Tag", robotsHeaderValue)
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(robots)
}
