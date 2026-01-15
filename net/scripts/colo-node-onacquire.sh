#!/usr/bin/env bash

# These variable must be set before the main body is called
TREZOA_LOCK_FILE="${TREZOA_LOCK_FILE:?}"
INSTANCE_NAME="${INSTANCE_NAME:?}"
PREEMPTIBLE="${PREEMPTIBLE:?}"
SSH_AUTHORIZED_KEYS="${SSH_AUTHORIZED_KEYS:?}"
SSH_PRIVATE_KEY_TEXT="${SSH_PRIVATE_KEY_TEXT:?}"
SSH_PUBLIC_KEY_TEXT="${SSH_PUBLIC_KEY_TEXT:?}"
NETWORK_INFO="${NETWORK_INFO:-"Network info unavailable"}"
CREATION_INFO="${CREATION_INFO:-"Creation info unavailable"}"

if [[ ! -f "${TREZOA_LOCK_FILE}" ]]; then
  exec 9>>"${TREZOA_LOCK_FILE}"
  flock -x -n 9 || ( echo "Failed to acquire lock!" 1>&2 && exit 1 )
  TREZOA_USER="${TREZOA_USER:?"TREZOA_USER undefined"}"
  {
    echo "export TREZOA_LOCK_USER=${TREZOA_USER}"
    echo "export TREZOA_LOCK_INSTANCENAME=${INSTANCE_NAME}"
    echo "export PREEMPTIBLE=${PREEMPTIBLE}"
    echo "[[ -v SSH_TTY && -f \"${HOME}/.trezoa-motd\" ]] && cat \"${HOME}/.trezoa-motd\" 1>&2"
  } >&9
  exec 9>&-
  cat > /trezoa-scratch/id_ecdsa <<EOF
${SSH_PRIVATE_KEY_TEXT}
EOF
  cat > /trezoa-scratch/id_ecdsa.pub <<EOF
${SSH_PUBLIC_KEY_TEXT}
EOF
  chmod 0600 /trezoa-scratch/id_ecdsa
  cat > /trezoa-scratch/authorized_keys <<EOF
${SSH_AUTHORIZED_KEYS}
${SSH_PUBLIC_KEY_TEXT}
EOF
  cp /trezoa-scratch/id_ecdsa "${HOME}/.ssh/id_ecdsa"
  cp /trezoa-scratch/id_ecdsa.pub "${HOME}/.ssh/id_ecdsa.pub"
  cp /trezoa-scratch/authorized_keys "${HOME}/.ssh/authorized_keys"
  cat > "${HOME}/.trezoa-motd" <<EOF


${NETWORK_INFO}
${CREATION_INFO}
EOF

  # Stamp creation MUST be last!
  touch /trezoa-scratch/.instance-startup-complete
else
  # shellcheck disable=SC1090
  exec 9<"${TREZOA_LOCK_FILE}" && flock -s 9 && . "${TREZOA_LOCK_FILE}" && exec 9>&-
  echo "${INSTANCE_NAME} candidate is already ${TREZOA_LOCK_INSTANCENAME}" 1>&2
  false
fi
