# |source| this file
#
# Common utilities shared by other scripts in this directory
#
# The following directive disable complaints about unused variables in this
# file:
# shellcheck disable=2034
#

# shellcheck source=net/common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")"/.. || exit 1; pwd)"/net/common.sh

prebuild=
if [[ $1 = "--prebuild" ]]; then
  prebuild=true
fi

if [[ $(uname) != Linux ]]; then
  # Protect against unsupported configurations to prevent non-obvious errors
  # later. Arguably these should be fatal errors but for now prefer tolerance.
  if [[ -n $TREZOA_CUDA ]]; then
    echo "Warning: CUDA is not supported on $(uname)"
    TREZOA_CUDA=
  fi
fi

if [[ -n $USE_INSTALL || ! -f "$TREZOA_ROOT"/Cargo.toml ]]; then
  trezoa_program() {
    declare program="$1"
    if [[ -z $program ]]; then
      printf "trezoa"
    else
      if [[ $program == "validator" || $program == "ledger-tool" || $program == "watchtower" || $program == "install" ]]; then
        printf "trezoa-%s" "$program"
      else
        printf "trezoa-%s" "$program"
      fi
    fi
  }
else
  trezoa_program() {
    declare program="$1"
    declare crate="$program"
    if [[ -z $program ]]; then
      crate="cli"
      program="trezoa"
    elif [[ $program == "validator" || $program == "ledger-tool" || $program == "watchtower" || $program == "install" ]]; then
      program="trezoa-$program"
    else
      program="trezoa-$program"
    fi

    if [[ -n $CARGO_BUILD_PROFILE ]]; then
      profile_arg="--profile $CARGO_BUILD_PROFILE"
    fi

    # Prebuild binaries so that CI sanity check timeout doesn't include build time
    if [[ $prebuild ]]; then
      (
        set -x
        # shellcheck disable=SC2086 # Don't want to double quote
        cargo $CARGO_TOOLCHAIN build $profile_arg --bin $program
      )
    fi

    printf "cargo $CARGO_TOOLCHAIN run $profile_arg --bin %s %s -- " "$program"
  }
fi

trezoa_bench_tps=$(trezoa_program bench-tps)
trezoa_faucet=$(trezoa_program faucet)
trezoa_validator=$(trezoa_program validator)
trezoa_validator_cuda="$trezoa_validator --cuda"
trezoa_genesis=$(trezoa_program genesis)
trezoa_gossip=$(trezoa_program gossip)
trezoa_keygen=$(trezoa_program keygen)
trezoa_ledger_tool=$(trezoa_program ledger-tool)
trezoa_cli=$(trezoa_program)

export RUST_BACKTRACE=1

default_arg() {
  declare name=$1
  declare value=$2

  for arg in "${args[@]}"; do
    if [[ $arg = "$name" ]]; then
      return
    fi
  done

  if [[ -n $value ]]; then
    args+=("$name" "$value")
  else
    args+=("$name")
  fi
}

replace_arg() {
  declare name=$1
  declare value=$2

  default_arg "$name" "$value"

  declare index=0
  for arg in "${args[@]}"; do
    index=$((index + 1))
    if [[ $arg = "$name" ]]; then
      args[$index]="$value"
    fi
  done
}
