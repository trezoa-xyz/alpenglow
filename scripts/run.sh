#!/usr/bin/env bash
#
# Run a minimal Trezoa cluster.  Ctrl-C to exit.
#
# Before running this script ensure standard Trezoa programs are available
# in the PATH, or that `cargo build` ran successfully
#
set -e

# Prefer possible `cargo build` binaries over PATH binaries
script_dir="$(readlink -f "$(dirname "$0")")"
if [[ "$script_dir" =~ /scripts$ ]]; then
  cd "$script_dir/.."
else
  cd "$script_dir"
fi


profile=debug
if [[ -n $CARGO_BUILD_PROFILE ]]; then
  profile=$CARGO_BUILD_PROFILE
fi
PATH=$PWD/target/$profile:$PATH

ok=true
for program in trezoa-{faucet,genesis,keygen}; do
  $program -V || ok=false
done
trezoa-validator -V || ok=false

$ok || {
  echo
  echo "Unable to locate required programs.  Try building them first with:"
  echo
  echo "  $ cargo build --all"
  echo
  exit 1
}

export RUST_LOG=${RUST_LOG:-trezoa=info,trezoa=info,trezoa_runtime::message_processor=debug} # if RUST_LOG is unset, default to info
export RUST_BACKTRACE=1
dataDir=$PWD/config/"$(basename "$0" .sh)"
ledgerDir=$PWD/config/ledger

TREZOA_RUN_SH_CLUSTER_TYPE=${TREZOA_RUN_SH_CLUSTER_TYPE:-development}

set -x
if ! trezoa address; then
  echo Generating default keypair
  trezoa-keygen new --no-passphrase
fi
validator_identity="$dataDir/validator-identity.json"
if [[ -e $validator_identity ]]; then
  echo "Use existing validator keypair"
else
  trezoa-keygen new --no-passphrase -so "$validator_identity"
fi
validator_vote_account="$dataDir/validator-vote-account.json"
if [[ -e $validator_vote_account ]]; then
  echo "Use existing validator vote account keypair"
else
  trezoa-keygen new --no-passphrase -so "$validator_vote_account"
fi
validator_stake_account="$dataDir/validator-stake-account.json"
if [[ -e $validator_stake_account ]]; then
  echo "Use existing validator stake account keypair"
else
  trezoa-keygen new --no-passphrase -so "$validator_stake_account"
fi

if [[ -e "$ledgerDir"/genesis.bin || -e "$ledgerDir"/genesis.tar.bz2 ]]; then
  echo "Use existing genesis"
else
  ./fetch-core-bpf.sh
  if [[ -r core-bpf-genesis-args.sh ]]; then
    CORE_BPF_GENESIS_ARGS=$(cat core-bpf-genesis-args.sh)
  fi

  ./fetch-spl.sh
  if [[ -r spl-genesis-args.sh ]]; then
    SPL_GENESIS_ARGS=$(cat spl-genesis-args.sh)
  fi

  # shellcheck disable=SC2086
  trezoa-genesis \
    --hashes-per-tick sleep \
    --faucet-lamports 500000000000000000 \
    --bootstrap-validator \
      "$validator_identity" \
      "$validator_vote_account" \
      "$validator_stake_account" \
    --ledger "$ledgerDir" \
    --cluster-type "$TREZOA_RUN_SH_CLUSTER_TYPE" \
    $CORE_BPF_GENESIS_ARGS \
    $SPL_GENESIS_ARGS \
    $TREZOA_RUN_SH_GENESIS_ARGS
fi

abort() {
  set +e
  kill "$faucet" "$validator"
  wait "$validator"
}
trap abort INT TERM EXIT

trezoa-faucet &
faucet=$!

args=(
  --identity "$validator_identity"
  --vote-account "$validator_vote_account"
  --ledger "$ledgerDir"
  --gossip-port 8001
  --full-rpc-api
  --rpc-port 8899
  --rpc-faucet-address 127.0.0.1:9900
  --log -
  --enable-rpc-transaction-history
  --enable-extended-tx-metadata-storage
  --init-complete-file "$dataDir"/init-completed
  --require-tower
  --no-wait-for-vote-to-start-leader
  --no-os-network-limits-test
)
# shellcheck disable=SC2086
trezoa-validator "${args[@]}" $TREZOA_RUN_SH_VALIDATOR_ARGS &
validator=$!

wait "$validator"
