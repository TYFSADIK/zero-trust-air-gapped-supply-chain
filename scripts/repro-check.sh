#!/bin/sh
# Reproducible-build check: build twice in clean, different directories and compare digests.
# Identical digests mean the binary is a pure function of the source, so the low side can rebuild and compare.
set -eu
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct 2>/dev/null || echo 0)
export CGO_ENABLED=0 GOFLAGS="-trimpath -buildvcs=false"
A=$(mktemp -d); B=$(mktemp -d)
cp -R . "$A/src"; cp -R . "$B/src"
(cd "$A/src" && go build -ldflags="-s -w -buildid=" -o "$A/airgap" ./cmd/airgap)
(cd "$B/src" && go build -ldflags="-s -w -buildid=" -o "$B/airgap" ./cmd/airgap)
HA=$(shasum -a 256 "$A/airgap" | cut -d' ' -f1); HB=$(shasum -a 256 "$B/airgap" | cut -d' ' -f1)
echo "build A: $HA"; echo "build B: $HB"
rm -rf "$A" "$B"
[ "$HA" = "$HB" ] && echo "REPRODUCIBLE" || { echo "NOT REPRODUCIBLE"; exit 1; }
