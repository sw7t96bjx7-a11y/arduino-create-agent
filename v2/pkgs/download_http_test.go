package pkgs

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInstallHTTPResponse(t *testing.T) {
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	file, err := writer.Create("tool/executable")
	require.NoError(t, err)
	_, err = file.Write([]byte("new version"))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	checksum := fmt.Sprintf("SHA-256:%x", sha256.Sum256(archive.Bytes()))

	for _, tc := range []struct {
		name        string
		status      int
		badChecksum bool
		wantError   string
	}{
		{name: "ok", status: http.StatusOK},
		{name: "forbidden", status: http.StatusForbidden, wantError: "403 Forbidden"},
		{name: "not found", status: http.StatusNotFound, wantError: "404 Not Found"},
		{name: "server error", status: http.StatusInternalServerError, wantError: "500 Internal Server Error"},
		{name: "partial response", status: http.StatusPartialContent, wantError: "206 Partial Content"},
		{name: "bad checksum", status: http.StatusOK, badChecksum: true, wantError: "checksum of downloaded file doesn't match"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				// Even a valid, checksum-matching archive must not be installed
				// when the download returned an HTTP error or partial response.
				_, _ = w.Write(archive.Bytes())
			}))
			defer server.Close()

			folder := t.TempDir()
			toolPath := filepath.Join("packager", "tool", "1.0.0")
			oldFile := filepath.Join(folder, toolPath, "old-version")
			require.NoError(t, os.MkdirAll(filepath.Dir(oldFile), 0755))
			require.NoError(t, os.WriteFile(oldFile, []byte("keep existing installation"), 0644))
			metadata := []byte(`{"existing-tool":"keep-me"}`)
			metadataPath := filepath.Join(folder, "installed.json")
			require.NoError(t, os.WriteFile(metadataPath, metadata, 0644))
			service := New(nil, folder, "replace", nil)
			wantChecksum := checksum
			if tc.badChecksum {
				wantChecksum = "SHA-256:" + strings.Repeat("0", 64)
			}

			operation, err := service.install(context.Background(), toolPath, server.URL, wantChecksum)
			if tc.wantError == "" {
				require.NoError(t, err)
				require.Equal(t, "ok", operation.Status)
				require.FileExists(t, filepath.Join(folder, toolPath, "executable"))
				return
			}
			require.ErrorContains(t, err, tc.wantError)
			require.Nil(t, operation)
			contents, err := os.ReadFile(oldFile)
			require.NoError(t, err)
			require.Equal(t, "keep existing installation", string(contents))
			contents, err = os.ReadFile(metadataPath)
			require.NoError(t, err)
			require.Equal(t, metadata, contents)
			require.NoFileExists(t, filepath.Join(folder, toolPath, "executable"))
		})
	}
}
