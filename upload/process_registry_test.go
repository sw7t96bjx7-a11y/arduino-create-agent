// Copyright 2026 Arduino Cloud Agent contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

package upload

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type killBeforeStartLogger struct{}

func (killBeforeStartLogger) Debug(...any) {}
func (killBeforeStartLogger) Info(...any)  { Kill() }

func TestProgramFailedStartDoesNotRegister(t *testing.T) {
	// The command log is emitted before Start. A stop request at this point
	// previously dereferenced the command's nil Process and panicked.
	err := program(filepath.Join(t.TempDir(), "missing-uploader"), nil, killBeforeStartLogger{})
	if err == nil {
		t.Fatal("expected an error starting a missing uploader")
	}
	cmdsMu.Lock()
	count := len(cmds)
	cmdsMu.Unlock()
	if count != 0 {
		t.Fatalf("failed upload left %d registered processes", count)
	}
}

type readyLogger struct {
	ready chan<- struct{}
}

func (readyLogger) Debug(...any) {}
func (l readyLogger) Info(args ...any) {
	if fmt.Sprint(args...) == "upload-process-ready" {
		l.ready <- struct{}{}
	}
}

func TestUploadProcessHelper(t *testing.T) {
	if os.Args[len(os.Args)-1] != "upload-process-helper" {
		return
	}
	fmt.Fprintln(os.Stdout, "upload-process-ready")
	// The parent test terminates this process. A timer avoids the runtime's
	// deadlock detector while providing a finite fallback lifetime.
	time.Sleep(time.Minute)
	os.Exit(0)
}

func TestKillStopsConcurrentUploads(t *testing.T) {
	const uploads = 4
	ready := make(chan struct{}, uploads)
	results := make(chan error, uploads)
	var running sync.WaitGroup
	for range uploads {
		running.Go(func() {
			results <- program(os.Args[0], []string{
				"-test.run=^TestUploadProcessHelper$", "--", "upload-process-helper",
			}, readyLogger{ready: ready})
		})
	}
	t.Cleanup(func() {
		Kill()
		running.Wait()
	})
	deadline := time.After(15 * time.Second)
	for range uploads {
		select {
		case <-ready:
		case err := <-results:
			t.Fatalf("upload helper exited before it was ready: %v", err)
		case <-deadline:
			t.Fatal("timed out waiting for upload helpers")
		}
	}

	// Stop commands race with one another and with process cleanup. Running
	// this test with -race also checks registry synchronization.
	var stopping sync.WaitGroup
	for range uploads * 2 {
		stopping.Go(func() {
			Kill()
		})
	}
	stopping.Wait()
	for range uploads {
		select {
		case err := <-results:
			if err == nil {
				t.Error("upload helper was expected to be interrupted")
			}
		case <-deadline:
			t.Fatal("timed out stopping upload helpers")
		}
	}
	cmdsMu.Lock()
	count := len(cmds)
	cmdsMu.Unlock()
	if count != 0 {
		t.Fatalf("completed uploads left %d registered processes", count)
	}
}
