package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/time/rate"
)

// Rate limiter
var limiter = rate.NewLimiter(1, 5) // 1 request per second with a burst of 5

// Rate limit middleware
func rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow() {
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Middlewares
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

// logs
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgent := r.Header.Get("User-Agent")
		log.Printf("%s %s %s %s\n", r.RemoteAddr, r.Method, r.URL, userAgent)
		next.ServeHTTP(w, r)
	})
}

// 404 Handler
func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "./static/not-found.html")
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	cookie := http.Cookie{
		Name:     "session_token",
		Value:    "some_session_token",
		Secure:   true,
		HttpOnly: true,
	}
	http.SetCookie(w, &cookie)
	fmt.Fprintf(w, "Hello, HTTPS world!")
}

func main() {
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/static/", http.StripPrefix("/static/", fs))

	http.HandleFunc("/hello", helloHandler)

	// 404 handler
	http.HandleFunc("/", notFoundHandler)

	mainHandler := http.NewServeMux()
	mainHandler.Handle("/static/", http.StripPrefix("/static/", fs))
	mainHandler.HandleFunc("/hello", helloHandler)
	mainHandler.HandleFunc("/", helloHandler)
	handler := rateLimitMiddleware(securityHeadersMiddleware(loggingMiddleware(mainHandler)))

	//  TLS configuration
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites: true,
		NextProtos:               []string{"h2"},
	}

	//  HTTP/2 support
	server := &http.Server{
		Addr:         ":443",
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
		TLSConfig:    tlsConfig,
	}
	http2.ConfigureServer(server, &http2.Server{})

	// server start
	go func() {
		log.Println("Starting server on https://localhost:443")
		if err := server.ListenAndServeTLS("keys/cert.pem", "keys/key.pem"); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server failed to start: %v", err)
		}
	}()

	// shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exiting")
}
