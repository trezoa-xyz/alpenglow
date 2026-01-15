#!/usr/bin/env bash

here=$(dirname "$0")
# shellcheck source=multinode-demo/common.sh
source "$here"/common.sh

set -e

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
if [[ -f $BOOTSTRAP_VALIDATOR_STAKE_KEYPAIR ]]; then
  cp -f "$BOOTSTRAP_VALIDATOR_STAKE_KEYPAIR" "$TREZOA_CONFIG_DIR"/bootstrap-validator/stake-account.json
else
  $trezoa_keygen new --no-passphrase -so "$TREZOA_CONFIG_DIR"/bootstrap-validator/stake-account.json
fi
if [[ -f $BOOTSTRAP_VALIDATOR_VOTE_KEYPAIR ]]; then
  cp -f "$BOOTSTRAP_VALIDATOR_VOTE_KEYPAIR" "$TREZOA_CONFIG_DIR"/bootstrap-validator/vote-account.json
else
  $trezoa_keygen new --no-passphrase -so "$TREZOA_CONFIG_DIR"/bootstrap-validator/vote-account.json
fi

BLS_PUBKEY=$($trezoa_keygen bls_pubkey "$TREZOA_CONFIG_DIR"/bootstrap-validator/identity.json)

args=(
  "$@"
  --max-genesis-archive-unpacked-size 1073741824
  --enable-warmup-epochs
  --bootstrap-validator "$TREZOA_CONFIG_DIR"/bootstrap-validator/identity.json
                        "$TREZOA_CONFIG_DIR"/bootstrap-validator/vote-account.json
                        "$TREZOA_CONFIG_DIR"/bootstrap-validator/stake-account.json
  --bootstrap-validator-bls-pubkey "$BLS_PUBKEY"
)

"$TREZOA_ROOT"/fetch-core-bpf.sh
if [[ -r core-bpf-genesis-args.sh ]]; then
  CORE_BPF_GENESIS_ARGS=$(cat "$TREZOA_ROOT"/core-bpf-genesis-args.sh)
  #shellcheck disable=SC2207
  #shellcheck disable=SC2206
  args+=($CORE_BPF_GENESIS_ARGS)
fi

"$TREZOA_ROOT"/fetch-tpl.sh
if [[ -r tpl-genesis-args.sh ]]; then
  SPL_GENESIS_ARGS=$(cat "$TREZOA_ROOT"/tpl-genesis-args.sh)
  #shellcheck disable=SC2207
  #shellcheck disable=SC2206
  args+=($SPL_GENESIS_ARGS)
fi

default_arg --ledger "$TREZOA_CONFIG_DIR"/bootstrap-validator
default_arg --faucet-pubkey "$TREZOA_CONFIG_DIR"/faucet.json
default_arg --faucet-lamports 500000000000000000
default_arg --hashes-per-tick auto
default_arg --cluster-type development

$trezoa_genesis "${args[@]}"
