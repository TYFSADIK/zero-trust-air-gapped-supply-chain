#!/bin/sh
# Low side: after `airgap verify` ACCEPTs, load OCI image tarballs into the offline Harbor registry.
# Usage: ./harbor-offline-push.sh received/ harbor.low.local/library
set -eu
DIR=$1; REG=$2
for t in "$DIR"/*.oci.tar; do
  name=$(basename "$t" .oci.tar)
  crane push "$t" "$REG/$name"   # or: skopeo copy oci-archive:$t docker://$REG/$name
  cosign verify --key keys/high.pub --insecure-ignore-tlog=true "$REG/$name"
done
