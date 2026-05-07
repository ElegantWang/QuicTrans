package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"quictrans/pkg/quicxfer"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:4242", "server address (host:port)")
	remote := flag.String("remote", "", "remote file path relative to the server root")
	out := flag.String("out", ".", "local output directory")
	timeout := flag.Duration("timeout", 30*time.Second, "dial + pull timeout")
	insecure := flag.Bool("insecure", false, "skip TLS verification (insecure)")
	fingerprint := flag.String("fingerprint", "", "expected server SHA256 fingerprint (hex)")
	flag.Parse()

	if *remote == "" {
		log.Fatal("missing --remote")
	}

	clientTLS := &tls.Config{
		InsecureSkipVerify: *insecure,
		NextProtos:         []string{"quic-file-xfer"},
	}

	if *fingerprint != "" {
		expected := strings.ToLower(strings.ReplaceAll(*fingerprint, ":", ""))
		clientTLS.InsecureSkipVerify = true
		clientTLS.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no server certificates")
			}
			sum := sha256.Sum256(rawCerts[0])
			got := hex.EncodeToString(sum[:])
			if got != expected {
				return fmt.Errorf("server certificate fingerprint mismatch: got %s, expected %s", got, expected)
			}
			return nil
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	savedPath, err := quicxfer.PullFile(ctx, *addr, clientTLS, *remote, *out)
	if err != nil {
		log.Fatalf("pull failed: %v", err)
	}
	log.Printf("saved to %s", savedPath)
}
