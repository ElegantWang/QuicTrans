package quicxfer

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestResolveRemotePathRejectsRootEscape(t *testing.T) {
	root := t.TempDir()

	if _, err := ResolveRemotePath(root, "../secret.txt"); err == nil {
		t.Fatal("expected parent directory traversal to be rejected")
	}

	if _, err := ResolveRemotePath(root, "/etc/passwd"); err == nil {
		t.Fatal("expected absolute paths to be rejected")
	}

	got, err := ResolveRemotePath(root, "nested/file.txt")
	if err != nil {
		t.Fatalf("expected safe relative path: %v", err)
	}

	want := filepath.Join(root, "nested", "file.txt")
	if got != want {
		t.Fatalf("resolved path mismatch: got %q, want %q", got, want)
	}
}

func TestPullFileDownloadsFileFromServerRoot(t *testing.T) {
	root := t.TempDir()
	outDir := t.TempDir()
	content := []byte("pulled over quic\n")

	if err := os.MkdirAll(filepath.Join(root, "release"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "release", "asset.txt"), content, 0644); err != nil {
		t.Fatal(err)
	}

	serverTLS, _, err := GenerateSelfSignedTLS()
	if err != nil {
		t.Fatal(err)
	}

	addr := freeUDPAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- RunFileServer(ctx, addr, serverTLS, root)
	}()
	time.Sleep(200 * time.Millisecond)

	clientTLS := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-file-xfer"},
	}
	savedPath, err := PullFile(context.Background(), addr, clientTLS, "release/asset.txt", outDir)
	if err != nil {
		t.Fatalf("pull file: %v", err)
	}

	got, err := os.ReadFile(savedPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("downloaded content mismatch: got %q, want %q", got, content)
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil && err != context.Canceled {
			t.Fatalf("server returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not stop after context cancellation")
	}
}

func freeUDPAddr(t *testing.T) string {
	t.Helper()

	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.LocalAddr().String()
}
