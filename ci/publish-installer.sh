#!/usr/bin/env bash
set -e

cd "$(dirname "$0")/.."

# check does it need to publish
if [[ -n $DO_NOT_PUBLISH_TAR ]]; then
  echo "Skipping publishing install wrapper"
  exit 0
fi

# check channel and tag
eval "$(ci/channel-info.sh)"

if [[ -n "$CI_TAG" ]]; then
  CHANNEL_OR_TAG=$CI_TAG
else
  CHANNEL_OR_TAG=$CHANNEL
fi

if [[ -z $CHANNEL_OR_TAG ]]; then
  echo +++ Unable to determine channel or tag to publish into, exiting.
  exit 0
fi

# upload install script
source ci/upload-ci-artifact.sh

cat >release.trezoa.xyz-install <<EOF
TREZOA_RELEASE=$CHANNEL_OR_TAG
TREZOA_INSTALL_INIT_ARGS=$CHANNEL_OR_TAG
TREZOA_DOWNLOAD_ROOT=https://release.trezoa.xyz
EOF
cat install/trezoa-install-init.sh >>release.trezoa.xyz-install

echo --- GCS: "install"
upload-gcs-artifact "/trezoa/release.trezoa.xyz-install" "gs://anza-release/$CHANNEL_OR_TAG/install"
echo Published to:
ci/format-url.sh https://release.trezoa.xyz/"$CHANNEL_OR_TAG"/install
