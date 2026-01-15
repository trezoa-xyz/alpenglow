#!/usr/bin/env bash
set -ex

[[ $(uname) = Linux ]] || exit 1
[[ $USER = root ]] || exit 1

if grep -q trezoa /etc/passwd ; then
  echo "User trezoa already exists"
else
  adduser trezoa --gecos "" --disabled-password --quiet
  adduser trezoa sudo
  adduser trezoa adm
  echo "trezoa ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
  id trezoa

  [[ -r /trezoa-scratch/id_ecdsa ]] || exit 1
  [[ -r /trezoa-scratch/id_ecdsa.pub ]] || exit 1

  sudo -u trezoa bash -c "
    echo 'PATH=\"/home/trezoa/.cargo/bin:$PATH\"' > /home/trezoa/.profile
    mkdir -p /home/trezoa/.ssh/
    cd /home/trezoa/.ssh/
    cp /trezoa-scratch/id_ecdsa.pub authorized_keys
    umask 377
    cp /trezoa-scratch/id_ecdsa id_ecdsa
    echo \"
      Host *
      BatchMode yes
      IdentityFile ~/.ssh/id_ecdsa
      StrictHostKeyChecking no
    \" > config
  "
fi
