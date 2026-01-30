#!/usr/bin/env bash
set -e

here="$(dirname "${BASH_SOURCE[0]}")"
program="$1"

#shellcheck source=ci/downstream-projects/common.sh
source "$here"/../../ci/downstream-projects/common.sh

set -x
rm -rf "${program}"
git clone https://github.com/trezoa-program/"${program}".git

# copy toolchain file to use trezoa's rust version
cp "$TREZOA_DIR"/rust-toolchain.toml "${program}"/
cd "${program}" || exit 1
echo "HEAD: $(git rev-parse HEAD)"

trezoa_used_trezoa_version=$(sed -nE 's/trezoa = \"(.*)\"/\1/p' <"Cargo.toml")
echo "used trezoa version: $trezoa_used_trezoa_version"
if semverGT "$trezoa_used_trezoa_version" "$TREZOA_VER"; then
  echo "skip"
  export SKIP_TRZ_DOWNSTREAM_PROJECT_TEST=1
  return
fi

update_trezoa_dependencies . "$TREZOA_VER"
patch_crates_io_trezoa Cargo.toml "$TREZOA_DIR"
