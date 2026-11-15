// Copyright 2026 Arduino Cloud Agent contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func TestLoopbackHostGuard(t *testing.T) {
	for _, tc := range []struct {
		name, bind, host, origin string
		want                     int
	}{
		{"numeric loopback", "127.0.0.1", "127.0.0.1:8991", "", http.StatusOK},
		{"localhost", "127.0.0.1", "localhost:8991", "", http.StatusOK},
		{"localhost case and dot", "localhost", "LOCALHOST.:8991", "", http.StatusOK},
		{"localhost without port", "localhost.", "localhost", "", http.StatusOK},
		{"IPv6 loopback", "[::1]", "[::1]:8991", "", http.StatusOK},
		{"IPv6 without port", "::1", "[::1]", "", http.StatusOK},
		{"mapped IPv4 loopback", "127.0.0.1", "[::ffff:127.0.0.1]:8991", "", http.StatusOK},
		{"legitimate Arduino origin", "127.0.0.1", "localhost:8991", "https://app.arduino.cc", http.StatusOK},
		{"untrusted external origin", "127.0.0.1", "localhost:8991", "https://attacker.invalid", http.StatusForbidden},
		{"matching malicious origin and host", "127.0.0.1", "attacker.invalid:8991", "http://attacker.invalid:8991", http.StatusForbidden},
		{"malicious host without origin", "127.0.0.1", "attacker.invalid:8991", "", http.StatusForbidden},
		{"non-loopback numeric host", "127.0.0.1", "192.0.2.1:8991", "", http.StatusForbidden},
		{"hostname suffix", "127.0.0.1", "localhost.attacker.invalid:8991", "", http.StatusForbidden},
		{"userinfo", "127.0.0.1", "user@localhost:8991", "", http.StatusForbidden},
		{"empty port", "127.0.0.1", "localhost:", "", http.StatusForbidden},
		{"non-numeric port", "127.0.0.1", "localhost:port", "", http.StatusForbidden},
		{"signed port", "127.0.0.1", "localhost:+8991", "", http.StatusForbidden},
		{"out-of-range port", "127.0.0.1", "localhost:65536", "", http.StatusForbidden},
		{"zero port", "127.0.0.1", "localhost:0", "", http.StatusForbidden},
		{"bare IPv6", "127.0.0.1", "::1", "", http.StatusForbidden},
		{"bracketed hostname", "127.0.0.1", "[localhost]:8991", "", http.StatusForbidden},
		{"bracketed IPv4", "127.0.0.1", "[127.0.0.1]", "", http.StatusForbidden},
		{"whitespace", "127.0.0.1", " localhost:8991", "", http.StatusForbidden},
		{"path suffix", "127.0.0.1", "localhost/path", "", http.StatusForbidden},
		{"extra trailing dot", "127.0.0.1", "localhost..:8991", "", http.StatusForbidden},
		{"explicit remote bind preserved", "192.0.2.1", "agent.example:8991", "", http.StatusOK},
		{"wildcard bind preserved", "0.0.0.0", "agent.example:8991", "", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			router := gin.New()
			router.Use(loopbackHostGuard(tc.bind))
			router.Use(cors.New(cors.Config{
				AllowOrigins: []string{"https://app.arduino.cc"},
				AllowMethods: []string{http.MethodGet},
			}))
			router.GET("/info", func(c *gin.Context) { c.Status(http.StatusOK) })
			request := httptest.NewRequest(http.MethodGet, "http://localhost:8991/info", nil)
			request.Host = tc.host
			if tc.origin != "" {
				request.Header.Set("Origin", tc.origin)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != tc.want {
				t.Fatalf("status = %d; want %d", response.Code, tc.want)
			}
		})
	}
}
