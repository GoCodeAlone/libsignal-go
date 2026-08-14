module github.com/GoCodeAlone/libsignal-go

go 1.26

toolchain go1.26.4

require golang.org/x/crypto v0.54.0

require (
	filippo.io/edwards25519 v1.2.0
	github.com/cloudflare/circl v1.6.5
	github.com/gtank/ristretto255 v0.2.0
	google.golang.org/protobuf v1.36.11
)

require golang.org/x/sys v0.47.0 // indirect
