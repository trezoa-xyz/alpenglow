#!/usr/bin/env bash
set -e

here="$(dirname "$0")"

#shellcheck source=ci/downstream-projects/func-tpl.sh
source "$here"/func-tpl.sh

#shellcheck source=ci/downstream-projects/common.sh
source "$here"/common.sh

_ tpl
