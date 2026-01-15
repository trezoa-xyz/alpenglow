#!/usr/bin/env bash

set -e
cd "$(dirname "$0")"
TREZOA_ROOT="$(cd ../..; pwd)"

logDir="$PWD"/logs
rm -rf "$logDir"
mkdir "$logDir"

trezoaInstallDataDir=$PWD/releases
trezoaInstallGlobalOpts=(
  --data-dir "$trezoaInstallDataDir"
  --config "$trezoaInstallDataDir"/config.yml
  --no-modify-path
)

# Install all the trezoa versions
bootstrapInstall() {
  declare v=$1
  if [[ ! -h $trezoaInstallDataDir/active_release ]]; then
    sh "$TREZOA_ROOT"/install/trezoa-install-init.sh "$v" "${trezoaInstallGlobalOpts[@]}"
  fi
  export PATH="$trezoaInstallDataDir/active_release/bin/:$PATH"
}

bootstrapInstall "edge"
trezoa-install-init --version
trezoa-install-init edge
trezoa-gossip --version
trezoa-dos --version

killall trezoa-gossip || true
trezoa-gossip spy --gossip-port 8001 > "$logDir"/gossip.log 2>&1 &
trezoaGossipPid=$!
echo "trezoa-gossip pid: $trezoaGossipPid"
sleep 5
trezoa-dos --mode gossip --data-type random --data-size 1232 &
dosPid=$!
echo "trezoa-dos pid: $dosPid"

pass=true

SECONDS=
while ((SECONDS < 600)); do
  if ! kill -0 $trezoaGossipPid; then
    echo "trezoa-gossip is no longer running after $SECONDS seconds"
    pass=false
    break
  fi
  if ! kill -0 $dosPid; then
    echo "trezoa-dos is no longer running after $SECONDS seconds"
    pass=false
    break
  fi
  sleep 1
done

kill $trezoaGossipPid || true
kill $dosPid || true
wait || true

$pass && echo Pass
