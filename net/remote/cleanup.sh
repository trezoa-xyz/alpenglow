#!/usr/bin/env bash

set -x
! tmux list-sessions || tmux kill-session
declare sudo=
if sudo true; then
  sudo="sudo -n"
fi

echo "pwd: $(pwd)"
for pid in trezoa/*.pid; do
  pgid=$(ps opgid= "$(cat "$pid")" | tr -d '[:space:]')
  if [[ -n $pgid ]]; then
    $sudo kill -- -"$pgid"
  fi
done
if [[ -f trezoa/netem.cfg ]]; then
  trezoa/scripts/netem.sh delete < trezoa/netem.cfg
  rm -f trezoa/netem.cfg
fi
trezoa/scripts/net-shaper.sh cleanup
for pattern in validator.sh boostrap-leader.sh trezoa- remote- iftop validator client node; do
  echo "killing $pattern"
  pkill -f $pattern
done
