#!/usr/bin/env bash
set -e

source ci/_
source ci/semver_bash/semver.sh
source scripts/patch-crates.sh
source scripts/read-cargo-variable.sh

TREZOA_VER=$(readCargoVariable version Cargo.toml)
export TREZOA_VER
export TREZOA_DIR=$PWD
export CARGO="$TREZOA_DIR"/cargo
export CARGO_BUILD_SBF="$TREZOA_DIR"/cargo-build-sbf
export CARGO_TEST_SBF="$TREZOA_DIR"/cargo-test-sbf

mkdir -p target/downstream-projects
cd target/downstream-projects
