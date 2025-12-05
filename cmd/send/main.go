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
	"os"
	"strings"
	"time"

	"quictrans/pkg/quicxfer"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:4242", "server address (host:port)")
	file := flag.String("file", "", "file to send (use for single file; you can also pass multiple paths as args)")
	timeout := flag.Duration("timeout", 30*time.Second, "dial + send timeout")
	insecure := flag.Bool("insecure", false, "skip TLS verification (insecure)")
	fingerprint := flag.String("fingerprint", "", "expected server SHA256 fingerprint (hex)")
	parallel := flag.Int("parallel", 4, "number of parallel streams for batch send")
	flag.Parse()

	// gather file list
	var files []string
	if *file != "" {
		files = append(files, *file)
	}
	if len(flag.Args()) > 0 {
		files = append(files, flag.Args()...)
	}
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "no files specified: provide --file or file paths as arguments")
		flag.Usage()
		os.Exit(2)
	}

	// Client TLS config: for quick testing you can use --insecure to skip verification.
	clientTLS := &tls.Config{
		InsecureSkipVerify: *insecure,
		NextProtos:         []string{"quic-file-xfer"},
	}

	if *fingerprint != "" {
		// normalize fingerprint (remove colons, lower-case)
		expected := *fingerprint
		expected = strings.ToLower(expected)
		expected = strings.ReplaceAll(expected, ":", "")
		clientTLS.InsecureSkipVerify = true // we'll verify in callback
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

	if len(files) == 1 {
		if err := quicxfer.SendFile(ctx, *addr, clientTLS, files[0]); err != nil {
			log.Fatalf("send failed: %v", err)
		}
		log.Println("send finished")
		return
	}

	if err := quicxfer.SendFiles(ctx, *addr, clientTLS, files, *parallel); err != nil {
		log.Fatalf("batch send failed: %v", err)
	}
	log.Println("batch send finished")
}
