// Copyright 2026 Arduino Cloud Agent contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	log "github.com/sirupsen/logrus"
)

func TestConfigureProxies(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://inherited-http.invalid:8080")
	t.Setenv("HTTPS_PROXY", "http://inherited-https.invalid:8080")
	var output bytes.Buffer
	previousOutput := log.StandardLogger().Out
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(previousOutput) })

	if err := configureProxies("", ""); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("HTTP_PROXY"); got != "http://inherited-http.invalid:8080" {
		t.Fatalf("empty setting changed inherited HTTP_PROXY: %q", got)
	}
	if got := os.Getenv("HTTPS_PROXY"); got != "http://inherited-https.invalid:8080" {
		t.Fatalf("empty setting changed inherited HTTPS_PROXY: %q", got)
	}

	httpProxy := "http://http-user:http-test-password@http-proxy.invalid:8080"
	httpsProxy := "http://https-user:https-test-password@https-proxy.invalid:8443"
	if err := configureProxies(httpProxy, httpsProxy); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("HTTP_PROXY"); got != httpProxy {
		t.Error("HTTP_PROXY did not receive its own configured value")
	}
	if got := os.Getenv("HTTPS_PROXY"); got != httpsProxy {
		t.Error("HTTPS_PROXY did not receive its own configured value")
	}
	for _, sensitive := range []string{httpProxy, httpsProxy, "test-password", "http-user", "https-user"} {
		if strings.Contains(output.String(), sensitive) {
			t.Error("proxy configuration logged URL or credential data")
		}
	}
}

func TestConfigureProxiesRejectsInvalidEnvironmentValue(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://inherited.invalid:8080")
	err := configureProxies("http://test-user:test-password@proxy.invalid\x00", "")
	if err == nil {
		t.Fatal("expected invalid environment value to be rejected")
	}
	if strings.Contains(err.Error(), "test-password") {
		t.Error("proxy error exposed credential data")
	}
	if got := os.Getenv("HTTP_PROXY"); got != "http://inherited.invalid:8080" {
		t.Error("invalid configuration changed inherited HTTP_PROXY")
	}
}
