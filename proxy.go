// Copyright 2026 Arduino Cloud Agent contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
)

// configureProxies applies explicit settings without clearing inherited proxy
// variables. Proxy URLs may contain credentials, so log only variable names.
func configureProxies(httpValue, httpsValue string) error {
	for _, setting := range []struct{ name, value string }{
		{"HTTP_PROXY", httpValue},
		{"HTTPS_PROXY", httpsValue},
	} {
		if setting.value == "" {
			continue
		}
		if err := os.Setenv(setting.name, setting.value); err != nil {
			return fmt.Errorf("configure %s: %w", setting.name, err)
		}
		log.Infof("Configured %s from agent settings", setting.name)
	}
	return nil
}
