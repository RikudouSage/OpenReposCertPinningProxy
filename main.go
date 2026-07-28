package main

import (
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const baseURL = "https://openrepos.net"
const defaultProxyAddr = ":8080"

var allowedProxies = []string{
	"127.0.0.1",
	"::1",
}

func main() {
	gracefulShutdown := make(chan os.Signal, 1)
	signal.Notify(gracefulShutdown, syscall.SIGINT, syscall.SIGTERM)

	targetURL, err := url.Parse(baseURL)
	if err != nil {
		panic(err)
	}

	certPath := strings.TrimSpace(os.Getenv("CERT_PATH"))
	if certPath == "" {
		log.Fatal("CERT_PATH must be set")
	}

	proxy := newProxy(targetURL, certPath)

	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", robotsHandler)
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		proxy.ServeHTTP(writer, request)
	})

	go func() {
		proxyAddr := os.Getenv("PROXY_ADDR")
		if proxyAddr == "" {
			proxyAddr = defaultProxyAddr
		}

		server := &http.Server{
			Addr:              proxyAddr,
			Handler:           noIndexHandler(mux),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       60 * time.Second,
		}

		log.Printf("Starting server on %s, proxying %s", proxyAddr, baseURL)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}()

	<-gracefulShutdown
	log.Println("Shutdown requested, shutting down")
}
