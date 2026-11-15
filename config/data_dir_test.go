// Copyright 2026 Arduino Cloud Agent contributors
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDataDirOverrideIsolatesDataCertificatesAndLogs(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "isolated", "data")
	t.Setenv("ARDUINO_CREATE_AGENT_DATA_DIR", directory)
	if got := GetDataDir().String(); got != directory {
		t.Fatalf("data directory = %q, want %q", got, directory)
	}
	if info, err := os.Stat(directory); err != nil || !info.IsDir() {
		t.Fatalf("data directory was not created: %v", err)
	}
	if got := GetCertificatesDir().String(); got != directory {
		t.Fatalf("certificate directory escaped isolation: %q", got)
	}
	if got := GetLogsDir().String(); got != filepath.Join(directory, "logs") {
		t.Fatalf("log directory escaped isolation: %q", got)
	}
}

func TestDataDirOverrideRejectsEmptyAndRelativePaths(t *testing.T) {
	for _, value := range []string{"", "relative", filepath.Join("relative", "data")} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("ARDUINO_CREATE_AGENT_DATA_DIR", value)
			defer func() {
				if recover() == nil {
					t.Fatal("invalid data directory override did not panic")
				}
			}()
			GetDataDir()
		})
	}
}

func TestDataDirDefaultPathWithoutCreatingHomeFiles(t *testing.T) {
	t.Setenv("ARDUINO_CREATE_AGENT_DATA_DIR", "removed-before-resolution")
	if err := os.Unsetenv("ARDUINO_CREATE_AGENT_DATA_DIR"); err != nil {
		t.Fatal(err)
	}
	userDirectory, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := dataDirPath().String(), filepath.Join(userDirectory, ".arduino-create"); got != want {
		t.Fatalf("default data directory = %q, want %q", got, want)
	}
}

func TestDataDirOverridePreservesCreationFailure(t *testing.T) {
	file := filepath.Join(t.TempDir(), "existing-file")
	if err := os.WriteFile(file, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARDUINO_CREATE_AGENT_DATA_DIR", file)
	defer func() {
		if recover() == nil {
			t.Fatal("data directory creation failure did not panic")
		}
	}()
	GetDataDir()
}
