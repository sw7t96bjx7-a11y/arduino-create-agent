// Copyright 2026 Arduino Cloud Agent contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigDirOverrideIsolatesConfiguration(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "isolated", "config")
	t.Setenv("ARDUINO_CREATE_AGENT_CONFIG_DIR", directory)
	if got := GetDefaultConfigDir().String(); got != directory {
		t.Fatalf("config directory = %q, want %q", got, directory)
	}
	if info, err := os.Stat(directory); err != nil || !info.IsDir() {
		t.Fatalf("config directory was not created: %v", err)
	}
}

func TestConfigDirOverrideRejectsEmptyAndRelativePaths(t *testing.T) {
	for _, value := range []string{"", "relative", filepath.Join("relative", "config")} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("ARDUINO_CREATE_AGENT_CONFIG_DIR", value)
			defer func() {
				if recover() == nil {
					t.Fatal("invalid config directory override did not panic")
				}
			}()
			GetDefaultConfigDir()
		})
	}
}

func TestConfigDirDefaultPathWithoutCreatingHomeFiles(t *testing.T) {
	t.Setenv("ARDUINO_CREATE_AGENT_CONFIG_DIR", "removed-before-resolution")
	if err := os.Unsetenv("ARDUINO_CREATE_AGENT_CONFIG_DIR"); err != nil {
		t.Fatal(err)
	}
	userDirectory, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := configDirPath().String(), filepath.Join(userDirectory, "ArduinoCreateAgent"); got != want {
		t.Fatalf("default config directory = %q, want %q", got, want)
	}
}

func TestConfigDirOverridePreservesCreationFailure(t *testing.T) {
	file := filepath.Join(t.TempDir(), "existing-file")
	if err := os.WriteFile(file, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARDUINO_CREATE_AGENT_CONFIG_DIR", file)
	defer func() {
		if recover() == nil {
			t.Fatal("config directory creation failure did not panic")
		}
	}()
	GetDefaultConfigDir()
}
