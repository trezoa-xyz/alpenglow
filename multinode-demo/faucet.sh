#!/usr/bin/env bash
#
# Starts an instance of trezoa-faucet
#
here=$(dirname "$0")

# shellcheck source=multinode-demo/common.sh
source "$here"/common.sh

[[ -f "$TREZOA_CONFIG_DIR"/faucet.json ]] || {
  echo "$TREZOA_CONFIG_DIR/faucet.json not found, create it by running:"
  echo
  echo "  ${here}/setup.sh"
  exit 1
}

set -x
# shellcheck disable=SC2086 # Don't want to double quote $trezoa_faucet
exec $trezoa_faucet --keypair "$TREZOA_CONFIG_DIR"/faucet.json "$@"
