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
	outdir := flag.String("outdir", ".", "output directory for received files")
	certPath := flag.String("cert", "", "path to server cert (PEM). If empty a self-signed cert will be generated and saved to disk")
	keyPath := flag.String("key", "", "path to server private key (PEM). If empty a self-signed key will be generated and saved to disk")
	flag.Parse()

	// Ensure outdir exists (default is current directory)
	if err := os.MkdirAll(*outdir, 0755); err != nil {
		log.Fatalf("create outdir: %v", err)
	}

	var tlsConf *tls.Config
	var fp string
	var err error
	if *certPath != "" && *keyPath != "" {
		// load provided cert/key
		tlsConf, fp, err = quicxfer.LoadTLSFromFiles(*certPath, *keyPath)
		if err != nil {
			log.Fatalf("load cert/key: %v", err)
		}
	} else {
		// generate and save to disk
		tlsConf, fp, err = quicxfer.GenerateSelfSignedTLS()
		if err != nil {
			log.Fatalf("generate tls: %v", err)
		}
		// save to default files if not provided
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

	fmt.Printf("Server listening on %s\n", *listen)
	fmt.Printf("Server certificate SHA256 fingerprint: %s\n", fp)
	fmt.Printf("Saving received files to %s\n", filepath.Clean(*outdir))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// handle signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-stop
		fmt.Println("shutting down...")
		cancel()
	}()

	if err := quicxfer.RunReceiver(ctx, *listen, tlsConf, *outdir); err != nil && ctx.Err() == nil {
		// if error and not due to context cancellation
		log.Fatalf("receiver error: %v", err)
	}

	// give a moment to shutdown cleanly
	time.Sleep(200 * time.Millisecond)
	fmt.Println("receiver stopped")
}
