// Package proto contains the Signal protocol wire, storage, service, sealed
// sender, and fingerprint message definitions, ported verbatim (field numbers
// and types) from upstream libsignal's rust/protocol/src/proto/*.proto.
//
// The generated *.pb.go files are committed to the repository; CI does not run
// code generation. To regenerate after editing a .proto file, install the
// pinned tools (see README.md) and run `go generate ./proto/...`.
package proto

// Regeneration uses buf (which embeds the protobuf compiler) driving the
// protoc-gen-go plugin; no system protoc binary is required. See README.md for
// the pinned tool versions.
//
//go:generate buf generate
