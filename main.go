package main

import (
	"har-scraper/internal/certificate"
	"har-scraper/internal/config"
	"har-scraper/internal/proxy"

	"fmt"
	"log"
	"net/http"
)

var cfg config.Configuration

func main() {
	// Load configuration
	if err := cfg.Load("config.json"); err != nil {
		log.Fatal("Failed to load config:", err)
	}

	// Load existing valid or generate new certificate
	ca, err := certificate.Setup("certs/ca.crt", "certs/ca.key")
	if err != nil {
		log.Fatal("Failed to setup CA:", err)
	}

	// Initialize proxy and http server
	p := proxy.New(&cfg, ca)

	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", cfg.Host, cfg.ProxyPort),
		Handler: http.HandlerFunc(p.HandleProxy),
	}

	log.Printf("Proxy server listening on: %s:%d", cfg.Host, cfg.ProxyPort)
	log.Fatal(server.ListenAndServe())
}
