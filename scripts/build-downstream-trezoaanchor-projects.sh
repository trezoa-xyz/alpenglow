#!/usr/bin/env bash
#
# Builds known downstream projects against local trezoa source
#

set -e
cd "$(dirname "$0")"/..
source ci/_
source scripts/patch-crates.sh
source scripts/read-cargo-variable.sh
source scripts/patch-trz-crates-for-trezoaanchor.sh

anchor_version=$1
trezoa_ver=$(readCargoVariable version Cargo.toml)
trezoa_dir=$PWD
cargo="$trezoa_dir"/cargo
cargo_build_sbf="$trezoa_dir"/cargo-build-sbf
cargo_test_sbf="$trezoa_dir"/cargo-test-sbf

mkdir -p target/downstream-projects-trezoaanchor
cd target/downstream-projects-trezoaanchor

update_anchor_dependencies() {
  declare trezoa_root="$1"
  declare anchor_ver="$2"
  declare tomls=()
  while IFS='' read -r line; do tomls+=("$line"); done < <(find "$trezoa_root" -name Cargo.toml)

  sed -i -e "s#\(trezoaanchor-lang = \"\)[^\"]*\(\"\)#\1=$anchor_ver\2#g" "${tomls[@]}" || return $?
  sed -i -e "s#\(trezoaanchor-tpl = \"\)[^\"]*\(\"\)#\1=$anchor_ver\2#g" "${tomls[@]}" || return $?
  sed -i -e "s#\(trezoaanchor-lang = { version = \"\)[^\"]*\(\"\)#\1=$anchor_ver\2#g" "${tomls[@]}" || return $?
  sed -i -e "s#\(trezoaanchor-tpl = { version = \"\)[^\"]*\(\"\)#\1=$anchor_ver\2#g" "${tomls[@]}" || return $?
}

patch_crates_io_anchor() {
  declare Cargo_toml="$1"
  declare anchor_dir="$2"
  cat >> "$Cargo_toml" <<EOF
trezoaanchor-lang = { path = "$anchor_dir/lang" }
trezoaanchor-tpl = { path = "$anchor_dir/tpl" }
EOF
}

# NOTE This isn't run in a subshell to get $anchor_dir and $anchor_ver
trezoaanchor() {
  set -x

  rm -rf tpl
  git clone https://github.com/trezoa-team/trezoa-program-library.git tpl
  cd tpl || exit 1
  ./patch.crates-io.sh "$trezoa_dir"
  trz_dir=$PWD
  get_trz_versions "$trz_dir"
  cd ..

  rm -rf trezoaanchor
  git clone https://github.com/trezoa-xyz/trezoaanchor.git
  cd trezoaanchor || exit 1

  # checkout tag
  if [[ -n "$anchor_version" ]]; then
    git checkout "$anchor_version"
  fi

  # copy toolchain file to use trezoa's rust version
  cp "$trezoa_dir"/rust-toolchain.toml .

  update_trezoa_dependencies . "$trezoa_ver"
  patch_crates_io_trezoa Cargo.toml "$trezoa_dir"
  patch_trz_crates . Cargo.toml "$trz_dir"

  # Exclude `avm` tests because they don't depend on Trezoa or TRZ
  $cargo test --workspace --exclude avm
  # serum_dex and mpl-token-metadata are using caret versions of trezoa and TRZ dependencies
  # rather pull and patch those as well, ignore for now
  # (cd tpl && $cargo_build_sbf --features dex metadata stake)
  (cd tpl && $cargo_build_sbf --features stake)
  (cd client && $cargo test --all-features)

  anchor_dir=$PWD
  anchor_ver=$(readCargoVariable version "$anchor_dir"/lang/Cargo.toml)

  cd "$trezoa_dir"/target/downstream-projects-trezoaanchor
}

openbook() {
  # Openbook-v2 is still using cargo 1.70.0, which is not compatible with the latest main
  rm -rf openbook-v2
  git clone https://github.com/openbook-dex/openbook-v2.git
  cd openbook-v2
  update_trezoa_dependencies . "$trezoa_ver"
  patch_crates_io_trezoa Cargo.toml "$trezoa_dir"
  $cargo_build_sbf --features enable-gpl
  cd programs/openbook-v2
  $cargo_test_sbf  --features enable-gpl
}

mango() {
  (
    set -x
    rm -rf mango-v4
    git clone https://github.com/blockworks-foundation/mango-v4.git
    cd mango-v4
    update_trezoa_dependencies . "$trezoa_ver"
    patch_crates_io_trezoa_no_header Cargo.toml "$trezoa_dir"
    $cargo_test_sbf --features enable-gpl
  )
}

trezoaplex() {
  (
    set -x
    rm -rf mpl-token-metadata
    git clone https://github.com/trezoaplex-foundation/mpl-token-metadata
    # copy toolchain file to use trezoa's rust version
    cp "$trezoa_dir"/rust-toolchain.toml mpl-token-metadata/
    cd mpl-token-metadata
    ./configs/program-scripts/dump.sh ./programs/bin
    ROOT_DIR=$(pwd)
    cd programs/token-metadata

    update_trezoa_dependencies . "$trezoa_ver"
    patch_crates_io_trezoa Cargo.toml "$trezoa_dir"

    OUT_DIR="$ROOT_DIR"/programs/bin
    export SBF_OUT_DIR="$OUT_DIR"
    $cargo_test_sbf --sbf-out-dir "${OUT_DIR}"
  )
}

_ trezoaanchor
#_ trezoaplex
#_ mango
#_ openbook
