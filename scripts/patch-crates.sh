# source this file

update_trezoa_dependencies() {
  declare project_root="$1"
  declare trezoa_ver="$2"
  declare tomls=()
  while IFS='' read -r line; do tomls+=("$line"); done < <(find "$project_root" -name Cargo.toml)

  crates=(
    trezoa-account-decoder
    trezoa-account-decoder-client-types
    trezoa-banks-client
    trezoa-banks-interface
    trezoa-banks-server
    trezoa-bloom
    trezoa-bucket-map
    trezoa-builtins-default-costs
    trezoa-clap-utils
    trezoa-clap-v3-utils
    trezoa-cli-config
    trezoa-cli-output
    trezoa-client
    trezoa-compute-budget
    trezoa-connection-cache
    trezoa-core
    trezoa-entry
    trezoa-faucet
    trezoa-fee
    trezoa-geyser-plugin-interface
    trezoa-geyser-plugin-manager
    trezoa-gossip
    trezoa-lattice-hash
    trezoa-ledger
    trezoa-log-collector
    trezoa-measure
    trezoa-merkle-tree
    trezoa-metrics
    trezoa-net-utils
    trezoa-perf
    trezoa-poh
    trezoa-program-runtime
    trezoa-program-test
    trezoa-bpf-loader-program
    trezoa-compute-budget-program
    trezoa-stake-program
    trezoa-system-program
    trezoa-vote-program
    trezoa-zk-elgamal-proof-program
    trezoa-zk-token-proof-program
    trezoa-pubsub-client
    trezoa-quic-client
    trezoa-rayon-threadlimit
    trezoa-remote-wallet
    trezoa-rpc
    trezoa-rpc-client
    trezoa-rpc-client-api
    trezoa-rpc-client-nonce-utils
    trezoa-runtime
    trezoa-runtime-transaction
    trezoa-send-transaction-service
    trezoa-storage-bigtable
    trezoa-storage-proto
    trezoa-streamer
    trezoa-svm-rent-calculator
    trezoa-svm-transaction
    trezoa-test-validator
    trezoa-tpu-client
    trezoa-transaction-status
    trezoa-transaction-status-client-types
    trezoa-udp-client
    trezoa-version
    trezoa-zk-token-sdk
    trezoa-curve25519
  )

  set -x
  for crate in "${crates[@]}"; do
    sed -E -i'' -e "s:(${crate} = \")([=<>]*)[0-9.]+([^\"]*)\".*:\1\2${trezoa_ver}\3\":" "${tomls[@]}"
    sed -E -i'' -e "s:(${crate} = \{ version = \")([=<>]*)[0-9.]+([^\"]*)(\".*):\1\2${trezoa_ver}\3\4:" "${tomls[@]}"
  done
}

patch_crates_io_trezoa() {
  declare Cargo_toml="$1"
  declare trezoa_dir="$2"
  cat >> "$Cargo_toml" <<EOF
[patch.crates-io]
EOF
  patch_crates_io_trezoa_no_header "$Cargo_toml" "$trezoa_dir"
}

patch_crates_io_trezoa_no_header() {
  declare Cargo_toml="$1"
  declare trezoa_dir="$2"

  crates_map=()
  crates_map+=("trezoa-account-decoder account-decoder")
  crates_map+=("trezoa-account-decoder-client-types account-decoder-client-types")
  crates_map+=("trezoa-banks-client banks-client")
  crates_map+=("trezoa-banks-interface banks-interface")
  crates_map+=("trezoa-banks-server banks-server")
  crates_map+=("trezoa-bloom bloom")
  crates_map+=("trezoa-bucket-map bucket_map")
  crates_map+=("trezoa-builtins-default-costs builtins-default-costs")
  crates_map+=("trezoa-clap-utils clap-utils")
  crates_map+=("trezoa-clap-v3-utils clap-v3-utils")
  crates_map+=("trezoa-cli-config cli-config")
  crates_map+=("trezoa-cli-output cli-output")
  crates_map+=("trezoa-client client")
  crates_map+=("trezoa-compute-budget compute-budget")
  crates_map+=("trezoa-connection-cache connection-cache")
  crates_map+=("trezoa-core core")
  crates_map+=("trezoa-entry entry")
  crates_map+=("trezoa-faucet faucet")
  crates_map+=("trezoa-fee fee")
  crates_map+=("trezoa-geyser-plugin-interface geyser-plugin-interface")
  crates_map+=("trezoa-geyser-plugin-manager geyser-plugin-manager")
  crates_map+=("trezoa-gossip gossip")
  crates_map+=("trezoa-lattice-hash lattice-hash")
  crates_map+=("trezoa-ledger ledger")
  crates_map+=("trezoa-log-collector log-collector")
  crates_map+=("trezoa-measure measure")
  crates_map+=("trezoa-merkle-tree merkle-tree")
  crates_map+=("trezoa-metrics metrics")
  crates_map+=("trezoa-net-utils net-utils")
  crates_map+=("trezoa-perf perf")
  crates_map+=("trezoa-poh poh")
  crates_map+=("trezoa-program-runtime program-runtime")
  crates_map+=("trezoa-program-test program-test")
  crates_map+=("trezoa-bpf-loader-program programs/bpf_loader")
  crates_map+=("trezoa-compute-budget-program programs/compute-budget")
  crates_map+=("trezoa-stake-program programs/stake")
  crates_map+=("trezoa-system-program programs/system")
  crates_map+=("trezoa-vote-program programs/vote")
  crates_map+=("trezoa-zk-elgamal-proof-program programs/zk-elgamal-proof")
  crates_map+=("trezoa-zk-token-proof-program programs/zk-token-proof")
  crates_map+=("trezoa-pubsub-client pubsub-client")
  crates_map+=("trezoa-quic-client quic-client")
  crates_map+=("trezoa-rayon-threadlimit rayon-threadlimit")
  crates_map+=("trezoa-remote-wallet remote-wallet")
  crates_map+=("trezoa-rpc rpc")
  crates_map+=("trezoa-rpc-client rpc-client")
  crates_map+=("trezoa-rpc-client-api rpc-client-api")
  crates_map+=("trezoa-rpc-client-nonce-utils rpc-client-nonce-utils")
  crates_map+=("trezoa-runtime runtime")
  crates_map+=("trezoa-runtime-transaction runtime-transaction")
  crates_map+=("trezoa-send-transaction-service send-transaction-service")
  crates_map+=("trezoa-storage-bigtable storage-bigtable")
  crates_map+=("trezoa-storage-proto storage-proto")
  crates_map+=("trezoa-streamer streamer")
  crates_map+=("trezoa-svm-rent-collector svm-rent-collector")
  crates_map+=("trezoa-svm-transaction svm-transaction")
  crates_map+=("trezoa-test-validator test-validator")
  crates_map+=("trezoa-tpu-client tpu-client")
  crates_map+=("trezoa-transaction-status transaction-status")
  crates_map+=("trezoa-transaction-status-client-types transaction-status-client-types")
  crates_map+=("trezoa-udp-client udp-client")
  crates_map+=("trezoa-version version")
  crates_map+=("trezoa-zk-token-sdk zk-token-sdk")
  crates_map+=("trezoa-bn254 curves/bn254")
  crates_map+=("trezoa-curve25519 curves/curve25519")
  crates_map+=("trezoa-secp256k1-recover curves/secp256k1-recover")

  patch_crates=()
  for map_entry in "${crates_map[@]}"; do
    read -r crate_name crate_path <<<"$map_entry"
    full_path="$trezoa_dir/$crate_path"
    if [[ -r "$full_path/Cargo.toml" ]]; then
      patch_crates+=("$crate_name = { path = \"$full_path\" }")
    fi
  done

  echo "Patching in $trezoa_ver from $trezoa_dir"
  echo
  if grep -q "# The following entries are auto-generated by $0" "$Cargo_toml"; then
    echo "$Cargo_toml is already patched"
  else
    if ! grep -q '\[patch.crates-io\]' "$Cargo_toml"; then
      echo "[patch.crates-io]" >> "$Cargo_toml"
    fi
    cat >> "$Cargo_toml" <<PATCH
# The following entries are auto-generated by $0
$(printf "%s\n" "${patch_crates[@]}")
PATCH
  fi
}
