# proto

Signal protocol message definitions, ported verbatim from upstream libsignal
(`rust/protocol/src/proto/*.proto`). Field numbers and wire types are copied
exactly — including `SignalMessage.pq_ratchet = 5` and
`SessionStructure.pq_ratchet_state = 15` — so this package is wire-compatible
with upstream.

The five `.proto` files map 1:1 to the upstream sources:

| file | upstream | proto syntax | proto package |
|------|----------|--------------|---------------|
| `wire.proto` | `wire.proto` | proto2 | `signal.proto.wire` |
| `service.proto` | `service.proto` | proto2 | `signalservice` |
| `storage.proto` | `storage.proto` | proto3 | `signal.proto.storage` |
| `sealed_sender.proto` | `sealed_sender.proto` | proto2 | `signal.proto.sealed_sender` |
| `fingerprint.proto` | `fingerprint.proto` | proto2 | `signal.proto.fingerprint` |

All five set `option go_package = "github.com/GoCodeAlone/libsignal-go/proto";`
so the generated Go types share this single package. The upstream proto
`package` declarations are preserved unchanged.

## Generated code is committed

The `*.pb.go` files are committed; CI does not run protobuf code generation.
Regenerate only when a `.proto` changes.

## Regenerating

Generation uses [`buf`](https://buf.build), which embeds the protobuf compiler,
driving the `protoc-gen-go` plugin. No system `protoc` binary is required.

Pinned tool versions (the ones used to generate the committed code):

| tool | version | install |
|------|---------|---------|
| Go | 1.26.4 | — |
| buf | 1.50.0 | `go install github.com/bufbuild/buf/cmd/buf@v1.50.0` |
| protoc-gen-go | v1.36.6 | `go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.6` |
| `google.golang.org/protobuf` (runtime) | v1.36.11 | `go.mod` require |

With those installed and on `PATH`:

```sh
go generate ./proto/...   # runs `buf generate` (see generate.go)
```

`buf generate` reads `buf.yaml` (module config) and `buf.gen.yaml` (plugin
config: `protoc-gen-go` with `paths=source_relative`).

## Field-number identity check

To confirm a ported `.proto` still matches its upstream source field-for-field:

```sh
for f in wire service storage sealed_sender fingerprint; do
  diff <(grep -E '=[ ]*[0-9]+' ../rust/protocol/src/proto/$f.proto) \
       <(grep -E '=[ ]*[0-9]+' $f.proto) && echo "$f: identical"
done
```

Note: upstream `service.proto` contains a non-breaking space (U+00A0) inside the
`NullMessage` comment; it is preserved verbatim here so the byte comparison is
exact.
