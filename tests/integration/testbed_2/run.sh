#!/bin/bash -eux

function get_ha() {
    local machine="$1"
    local if_name="$2"
    vagrant ssh "${machine}" -c "ip -br link show ${if_name}" | awk '{ printf $3 }'
}

function install {
    for machine in $(vagrant status --machine-readable | grep state,running | cut -d ',' -f 2)
    do
        vagrant ssh "${machine}" -c 'cd ti-mfa-src && make install'
    done
}

function scenario_1 {
    local E_eth1_ha
    local C_eth3_ha
    local link_E_C

    E_eth1_ha="$(get_ha E eth1)"
    C_eth3_ha="$(get_ha C eth3)"
    link_E_C="${E_eth1_ha}-${C_eth3_ha}"

    vagrant ssh Z -c "ti-mfa-conf add ${link_E_C} 1400 eth1"
    vagrant ssh E -c "sudo ip link set eth1 down"
    vagrant ssh D -c "sudo ip link set eth2 down"
    vagrant ssh Z -c 'ping -c 1 10.200.200.3'
}

install
scenario_1
