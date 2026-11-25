package main

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestBackupRestoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "etc")
	os.MkdirAll(filepath.Join(src, "tunnels"), 0o700)
	os.WriteFile(filepath.Join(src, "config.json"), []byte(`{"main":1}`), 0o600)
	os.WriteFile(filepath.Join(src, "tunnels", "de.json"), []byte(`{"de":1}`), 0o600)
	bk := filepath.Join(dir, "b.tar.gz")
	if err := writeBackup(src, bk); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(src, "config.json"), []byte(`{"changed":1}`), 0o600)
	os.Remove(filepath.Join(src, "tunnels", "de.json"))
	if err := restoreBackup(bk, src); err != nil {
		t.Fatal(err)
	}
	for f, want := range map[string]string{"config.json": `{"main":1}`, "tunnels/de.json": `{"de":1}`} {
		b, err := os.ReadFile(filepath.Join(src, f))
		if err != nil || string(b) != want {
			t.Fatalf("%s: %q %v", f, b, err)
		}
	}
	old, _ := filepath.Glob(src + ".before-restore-*")
	if len(old) != 1 {
		t.Fatalf("previous settings not kept: %v", old)
	}
}

func TestRestoreRejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	bk := filepath.Join(dir, "evil.tar.gz")
	f, _ := os.Create(bk)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, n := range []string{"config.json", "../../evil"} {
		tw.WriteHeader(&tar.Header{Name: n, Mode: 0o600, Size: 1, Typeflag: tar.TypeReg})
		tw.Write([]byte("x"))
	}
	tw.Close()
	gz.Close()
	f.Close()
	if err := restoreBackup(bk, filepath.Join(dir, "etc")); err == nil {
		t.Fatal("path traversal accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "evil")); err == nil {
		t.Fatal("file written outside the target")
	}
}
