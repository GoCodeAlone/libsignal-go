#!/usr/bin/env bash
#
# Copyright 2026 libsignal-go contributors.
# SPDX-License-Identifier: AGPL-3.0-only
#
# Update the compatibility harness to an upstream signalapp/libsignal release.
# The script intentionally updates only the Rust harness pin, lockfile, and
# generated compatibility vectors. Go protocol changes are still reviewed in the
# PR opened by CI when the generated checks fail or the diff is non-trivial.

set -euo pipefail

upstream_repo="${UPSTREAM_REPO:-signalapp/libsignal}"
requested_tag="${1:-${UPSTREAM_TAG:-}}"

if [ -z "$requested_tag" ]; then
	if ! command -v gh >/dev/null 2>&1; then
		echo "gh is required when no upstream tag is supplied" >&2
		exit 1
	fi
	requested_tag="$(gh release view --repo "$upstream_repo" --json tagName --jq .tagName)"
fi

case "$requested_tag" in
v[0-9]*.[0-9]*.[0-9]*) ;;
*)
	echo "unsupported upstream tag: $requested_tag" >&2
	exit 1
	;;
esac

current_tag="$(
	sed -nE 's/.*tag = "([^"]+)".*/\1/p' compat/rust-harness/Cargo.toml | head -n 1
)"

if [ -z "$current_tag" ]; then
	echo "could not find current compat harness tag" >&2
	exit 1
fi

if [ "$current_tag" = "$requested_tag" ]; then
	echo "compat harness already pinned to $requested_tag"
	exit 0
fi

echo "updating compat harness from $current_tag to $requested_tag"

export CURRENT_TAG="$current_tag"
export UPSTREAM_TAG="$requested_tag"

perl -0pi -e 's/\Q$ENV{CURRENT_TAG}\E/$ENV{UPSTREAM_TAG}/g' \
	README.md \
	compat/README.md \
	compat/rust-harness/README.md \
	compat/rust-harness/Cargo.toml \
	compat/session_interop_test.go \
	.github/workflows/compat.yml \
	.github/workflows/compat-drift.yml

(
	cd compat/rust-harness
	cargo update
	cargo build --release
)

harness="compat/rust-harness/target/release/rust-harness"
for domain in curve kem-decaps hkdf messages fingerprint sessions groups sealedsender; do
	"$harness" gen-vectors "$domain" > "compat/vectors/$domain.json"
done

go test ./compat/ -v
COMPAT_HARNESS_BIN="$PWD/$harness" go test ./compat/ -tags=interop -v

echo "compat harness updated to $requested_tag"
