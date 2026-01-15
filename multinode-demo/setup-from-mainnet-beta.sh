#!/usr/bin/env bash

here=$(dirname "$0")
# shellcheck source=multinode-demo/common.sh
source "$here"/common.sh

set -e

rm -rf "$TREZOA_CONFIG_DIR"/latest-mainnet-beta-snapshot
mkdir -p "$TREZOA_CONFIG_DIR"/latest-mainnet-beta-snapshot
(
  cd "$TREZOA_CONFIG_DIR"/latest-mainnet-beta-snapshot || exit 1
  set -x
  wget http://api.mainnet-beta.trezoa.com/genesis.tar.bz2
  wget --trust-server-names http://api.mainnet-beta.trezoa.com/snapshot.tar.bz2
)

snapshot=$(ls "$TREZOA_CONFIG_DIR"/latest-mainnet-beta-snapshot/snapshot-[0-9]*-*.tar.zst)
if [[ -z $snapshot ]]; then
  echo Error: Unable to find latest snapshot
  exit 1
fi

if [[ ! $snapshot =~ snapshot-([0-9]*)-.*.tar.zst ]]; then
  echo Error: Unable to determine snapshot slot for "$snapshot"
  exit 1
fi

snapshot_slot="${BASH_REMATCH[1]}"

rm -rf "$TREZOA_CONFIG_DIR"/bootstrap-validator
mkdir -p "$TREZOA_CONFIG_DIR"/bootstrap-validator


# Create genesis ledger
if [[ -r $FAUCET_KEYPAIR ]]; then
  cp -f "$FAUCET_KEYPAIR" "$TREZOA_CONFIG_DIR"/faucet.json
else
  $trezoa_keygen new --no-passphrase -fso "$TREZOA_CONFIG_DIR"/faucet.json
fi

if [[ -f $BOOTSTRAP_VALIDATOR_IDENTITY_KEYPAIR ]]; then
  cp -f "$BOOTSTRAP_VALIDATOR_IDENTITY_KEYPAIR" "$TREZOA_CONFIG_DIR"/bootstrap-validator/identity.json
else
  $trezoa_keygen new --no-passphrase -so "$TREZOA_CONFIG_DIR"/bootstrap-validator/identity.json
fi

$trezoa_keygen new --no-passphrase -so "$TREZOA_CONFIG_DIR"/bootstrap-validator/vote-account.json
$trezoa_keygen new --no-passphrase -so "$TREZOA_CONFIG_DIR"/bootstrap-validator/stake-account.json

$trezoa_ledger_tool create-snapshot \
  --ledger "$TREZOA_CONFIG_DIR"/latest-mainnet-beta-snapshot \
  --faucet-pubkey "$TREZOA_CONFIG_DIR"/faucet.json \
  --faucet-lamports 500000000000000000 \
  --bootstrap-validator "$TREZOA_CONFIG_DIR"/bootstrap-validator/identity.json \
                        "$TREZOA_CONFIG_DIR"/bootstrap-validator/vote-account.json \
                        "$TREZOA_CONFIG_DIR"/bootstrap-validator/stake-account.json \
  --hashes-per-tick sleep \
  "$snapshot_slot" "$TREZOA_CONFIG_DIR"/bootstrap-validator

$trezoa_ledger_tool modify-genesis \
  --ledger "$TREZOA_CONFIG_DIR"/latest-mainnet-beta-snapshot \
  --hashes-per-tick sleep \
  "$TREZOA_CONFIG_DIR"/bootstrap-validator
