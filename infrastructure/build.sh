#!/usr/bin/env sh

BOX_NAME="debian_frr_linux_5.16"

[ "$(basename "$PWD")" != 'infrastructure' ] && cd infrastructure || exit 1

which ansible || pip3 install ansible
vagrant up
vagrant package --output "$BOX_NAME"
vagrant box add repacked "$BOX_NAME"
