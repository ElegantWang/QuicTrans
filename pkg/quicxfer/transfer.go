package quicxfer

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/quic-go/quic-go"
)

type FileMeta struct {
	Name string      `json:"name"`
	Size int64       `json:"size"`
	Mode os.FileMode `json:"mode"`
}

func GenerateSelfSignedTLS() (*tls.Config, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"quictrans"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, "", err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  key,
	}

	conf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"quic-file-xfer"},
	}

	// fingerprint SHA256 of cert DER
	sum := sha256.Sum256(derBytes)
	fp := hex.EncodeToString(sum[:])

	return conf, fp, nil
}

// SendFile dials addr and sends one file. tlsConf is the client TLS config (may set InsecureSkipVerify).
func SendFile(ctx context.Context, addr string, tlsConf *tls.Config, localPath string) error {
	if tlsConf == nil {
		return errors.New("tls config required")
	}

	clientTLS := tlsConf.Clone()
	clientTLS.NextProtos = []string{"quic-file-xfer"}

	session, err := quic.DialAddr(ctx, addr, clientTLS, nil)
	if err != nil {
		return err
	}

	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		return err
	}
	defer stream.Close()

	fi, err := os.Stat(localPath)
	if err != nil {
		return err
	}
	meta := FileMeta{
		Name: filepath.Base(localPath),
		Size: fi.Size(),
		Mode: fi.Mode(),
	}
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return err
	}

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(metaBytes)))

	// Write header length + header JSON
	if _, err := stream.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := stream.Write(metaBytes); err != nil {
		return err
	}

	// Write file contents
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// progress bar using pb
	var bar *pb.ProgressBar
	if fi.Size() > 0 {
		bar = pb.Full.Start64(fi.Size())
		defer bar.Finish()
	}

	if bar != nil {
		pw := bar.NewProxyWriter(stream)
		_, err = io.Copy(pw, f)
	} else {
		_, err = io.Copy(stream, f)
	}
	if err != nil {
		_ = stream.Close()
		_ = session.CloseWithError(1, "transfer error")
		return err
	}

	// close the stream to signal EOF to the receiver
	_ = stream.Close()

	return nil
}

// SendFiles sends multiple files over a single QUIC session using up to 'parallel' concurrent streams.
func SendFiles(ctx context.Context, addr string, tlsConf *tls.Config, paths []string, parallel int) error {
	if tlsConf == nil {
		return errors.New("tls config required")
	}

	clientTLS := tlsConf.Clone()
	clientTLS.NextProtos = []string{"quic-file-xfer"}

	session, err := quic.DialAddr(ctx, addr, clientTLS, nil)
	if err != nil {
		return err
	}
	defer session.CloseWithError(0, "client done")

	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error

	for _, p := range paths {
		wg.Add(1)
		sem <- struct{}{}
		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()

			// open stream per file
			stream, err := session.OpenStreamSync(ctx)
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}

			fi, err := os.Stat(p)
			if err != nil {
				_ = stream.Close()
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}

			meta := FileMeta{
				Name: filepath.Base(p),
				Size: fi.Size(),
				Mode: fi.Mode(),
			}
			metaBytes, err := json.Marshal(meta)
			if err != nil {
				_ = stream.Close()
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}
			var lenBuf [4]byte
			binary.BigEndian.PutUint32(lenBuf[:], uint32(len(metaBytes)))
			if _, err := stream.Write(lenBuf[:]); err != nil {
				_ = stream.Close()
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}
			if _, err := stream.Write(metaBytes); err != nil {
				_ = stream.Close()
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}

			f, err := os.Open(p)
			if err != nil {
				_ = stream.Close()
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
				return
			}
			defer f.Close()

			// per-file progress bar
			var bar *pb.ProgressBar
			if fi.Size() > 0 {
				bar = pb.Full.Start64(fi.Size())
				defer bar.Finish()
			}
			if bar != nil {
				pw := bar.NewProxyWriter(stream)
				if _, err := io.Copy(pw, f); err != nil {
					_ = stream.Close()
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
					return
				}
			} else {
				if _, err := io.Copy(stream, f); err != nil {
					_ = stream.Close()
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
					return
				}
			}

			_ = stream.Close()
		}(p)
	}

	wg.Wait()
	if firstErr != nil {
		return firstErr
	}
	return nil
}

// RunReceiver runs a server listening on addr and saves incoming files to outDir.
// It runs until ctx is cancelled. tlsConf must be provided.
func RunReceiver(ctx context.Context, addr string, tlsConf *tls.Config, outDir string) error {
	if tlsConf == nil {
		return errors.New("tls config required")
	}

	listener, err := quic.ListenAddr(addr, tlsConf, nil)
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		// check context
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		session, err := listener.Accept(ctx)
		if err != nil {
			// If context cancelled, return
			if ctx.Err() != nil {
				return ctx.Err()
			}
			fmt.Fprintf(os.Stderr, "accept session error: %v\n", err)
			continue
		}

		// handle session in goroutine
		go func() {
			defer session.CloseWithError(0, "session done")
			for {
				stream, err := session.AcceptStream(ctx)
				if err != nil {
					// session closed
					return
				}
				go handleStream(stream, outDir)
			}
		}()
	}
}

func handleStream(stream *quic.Stream, outDir string) {
	defer stream.Close()

	var lenBuf [4]byte
	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		fmt.Fprintf(os.Stderr, "read header len error: %v\n", err)
		return
	}
	headerLen := binary.BigEndian.Uint32(lenBuf[:])
	header := make([]byte, headerLen)
	if _, err := io.ReadFull(stream, header); err != nil {
		fmt.Fprintf(os.Stderr, "read header error: %v\n", err)
		return
	}

	var meta FileMeta
	if err := json.Unmarshal(header, &meta); err != nil {
		fmt.Fprintf(os.Stderr, "unmarshal header error: %v\n", err)
		return
	}

	outPath := filepath.Join(outDir, meta.Name)
	// Ensure unique file if exists
	outFile, err := os.Create(outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create file error: %v\n", err)
		return
	}
	defer outFile.Close()

	// Copy exact size if available
	var copied int64
	if meta.Size > 0 {
		// progress bar
		bar := pb.Full.Start64(meta.Size)
		defer bar.Finish()
		pw := bar.NewProxyWriter(outFile)
		copied, err = io.CopyN(pw, stream, meta.Size)
		if err != nil && err != io.EOF {
			fmt.Fprintf(os.Stderr, "copy file error: %v\n", err)
			return
		}
	} else {
		// fallback to copy until stream EOF
		copied, err = io.Copy(outFile, stream)
		if err != nil && err != io.EOF {
			fmt.Fprintf(os.Stderr, "copy file error: %v\n", err)
			return
		}
	}

	if err := outFile.Chmod(meta.Mode); err != nil {
		// ignore on platforms that don't support
	}

	fmt.Printf("Saved %s (%d bytes)\n", outPath, copied)
}

// SaveTLSCertAndKey writes the certificate and private key from tls.Config to files in PEM format.
func SaveTLSCertAndKey(certPath, keyPath string, conf *tls.Config) error {
	if conf == nil || len(conf.Certificates) == 0 {
		return errors.New("no certificate in tls config")
	}
	certDER := conf.Certificates[0].Certificate[0]
	key := conf.Certificates[0].PrivateKey

	// write cert PEM
	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}

	// write key PEM (support rsa.PrivateKey)
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return errors.New("private key is not RSA")
	}
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	keyBytes := x509.MarshalPKCS1PrivateKey(rsaKey)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return err
	}
	return nil
}

// LoadTLSFromFiles loads a certificate and key from PEM files and returns a tls.Config and fingerprint.
func LoadTLSFromFiles(certPath, keyPath string) (*tls.Config, string, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, "", err
	}
	if len(cert.Certificate) == 0 {
		return nil, "", errors.New("no certificate data")
	}
	sum := sha256.Sum256(cert.Certificate[0])
	fp := hex.EncodeToString(sum[:])
	conf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"quic-file-xfer"},
	}
	return conf, fp, nil
}
