#!/usr/bin/env bash

openbook_dex() {
  (
    set -x
    rm -rf openbook-dex
    git clone https://github.com/openbook-dex/program.git openbook-dex
    # copy toolchain file to use trezoa's rust version
    cp "$TREZOA_DIR"/rust-toolchain.toml openbook-dex/
    cd openbook-dex || exit 1

    update_trezoa_dependencies . "$TREZOA_VER"
    patch_crates_io_trezoa Cargo.toml "$TREZOA_DIR"
    cat >> Cargo.toml <<EOF
trezoaanchor-lang = { git = "https://github.com/coral-xyz/trezoaanchor.git", branch = "master" }
EOF
    patch_crates_io_trezoa dex/Cargo.toml "$TREZOA_DIR"
    cat >> dex/Cargo.toml <<EOF
trezoaanchor-lang = { git = "https://github.com/coral-xyz/trezoaanchor.git", branch = "master" }
[workspace]
exclude = [
    "crank",
    "permissioned",
]
EOF
    cargo build

    $CARGO_BUILD_SBF \
      --manifest-path dex/Cargo.toml --no-default-features --features program

    cargo test \
      --manifest-path dex/Cargo.toml --no-default-features --features program
  )
}
