package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"quictrans/pkg/quicxfer"
)

func main() {
	listen := flag.String("listen", ":4242", "listen address (host:port). Default :4242 listens on all interfaces")
	root := flag.String("root", ".", "root directory that clients are allowed to pull from")
	certPath := flag.String("cert", "", "path to server cert (PEM). If empty a self-signed cert will be generated and saved to disk")
	keyPath := flag.String("key", "", "path to server private key (PEM). If empty a self-signed key will be generated and saved to disk")
	flag.Parse()

	if err := os.MkdirAll(*root, 0755); err != nil {
		log.Fatalf("create root: %v", err)
	}

	var tlsConf *tls.Config
	var fp string
	var err error
	if *certPath != "" && *keyPath != "" {
		tlsConf, fp, err = quicxfer.LoadTLSFromFiles(*certPath, *keyPath)
		if err != nil {
			log.Fatalf("load cert/key: %v", err)
		}
	} else {
		tlsConf, fp, err = quicxfer.GenerateSelfSignedTLS()
		if err != nil {
			log.Fatalf("generate tls: %v", err)
		}
		certOut := "server_cert.pem"
		keyOut := "server_key.pem"
		if *certPath != "" {
			certOut = *certPath
		}
		if *keyPath != "" {
			keyOut = *keyPath
		}
		if err := quicxfer.SaveTLSCertAndKey(certOut, keyOut, tlsConf); err != nil {
			log.Printf("warning: failed to save cert/key: %v", err)
		} else {
			fmt.Printf("Generated self-signed cert saved to %s and %s\n", certOut, keyOut)
		}
	}

	fmt.Printf("File server listening on %s\n", *listen)
	fmt.Printf("Server certificate SHA256 fingerprint: %s\n", fp)
	fmt.Printf("Serving files from %s\n", filepath.Clean(*root))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		fmt.Println("shutting down...")
		cancel()
	}()

	if err := quicxfer.RunFileServer(ctx, *listen, tlsConf, *root); err != nil && ctx.Err() == nil {
		log.Fatalf("file server error: %v", err)
	}

	time.Sleep(200 * time.Millisecond)
	fmt.Println("file server stopped")
}
