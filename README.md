# quictrans (CLI prototype)

Prototype CLI tool to send/receive files over QUIC using `quic-go`.

## Requirements

- Go 1.20+
- UDP port allowed (QUIC uses UDP)
- `github.com/quic-go/quic-go` (module dependency is in `go.mod`)

## Build

```bash
go mod tidy
go build -o bin/recv ./cmd/recv
go build -o bin/send ./cmd/send
```

## Run (local test)

1. Start receiver:
```bash
# listen on default 4242 and save to /tmp
./bin/recv --listen 127.0.0.1:4242 --outdir /tmp
```
The receiver prints the server certificate fingerprint (SHA256). For simple local testing you can use `--insecure` on the client to skip verification.

2. In another terminal, send a file:
```bash
./bin/send --addr 127.0.0.1:4242 --file ./largefile.bin --insecure
```

## Notes & next steps

- Current prototype generates self-signed certs for the server for quick testing.
- Server certificate persistence
- You can provide your own certificate and key with `--cert /path/to/cert.pem --key /path/to/key.pem` when starting `recv`.
- If you don't provide `--cert`/`--key`, the server generates a self-signed certificate and saves it to `server_cert.pem` and `server_key.pem` in the current directory (printed at startup). Use the printed SHA256 fingerprint with the client's `--fingerprint` flag to validate the server certificate.
- For production: persist server certificate, let client verify fingerprint or provide CA.
- Future improvements: multiple-file batch transfer, progress reporting, parallel streams, resume support, GUI/web UI.

## Batch send

The `send` CLI supports sending multiple files in one command. Example:

```bash
# send multiple files concurrently using up to 4 streams
./bin/send --addr 1.2.3.4:4242 --parallel 4 file1.bin file2.bin file3.bin
```

Each file will be sent on its own QUIC stream concurrently (up to the `--parallel` limit). Use `--fingerprint` to validate the server certificate instead of `--insecure`.
