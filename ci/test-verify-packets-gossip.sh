#!/usr/bin/env bash

set -e
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)

if ! git lfs --version &>/dev/null; then
  echo "Git LFS is not installed. Please install Git LFS to proceed."
  exit 1
fi

rm -rf "$here"/trezoa-packets
git clone https://github.com/trezoa-xyz/trezoa-packets.git "$here"/trezoa-packets
GOSSIP_WIRE_FORMAT_PACKETS="$here/trezoa-packets/GOSSIP_PACKETS" cargo test --package trezoa-gossip -- wire_format_tests::tests::test_gossip_wire_format --exact --show-output
