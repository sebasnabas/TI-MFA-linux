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
    local link_e_r
    # local link_e_m

    # link_e_m="$(get_ha T eth2)-$(get_ha M eth2)"
    link_e_r="$(get_ha T eth3)-$(get_ha R eth2)"

    # vagrant ssh M -c "ti-mfa-conf add ${link_e_m} 1200 eth1"
    vagrant ssh R -c "ti-mfa-conf add ${link_e_r} 1200 eth1"
    vagrant ssh T -c "sudo ip link set eth1 down"
    vagrant ssh T -c "sudo ip link set eth2 down"
    vagrant ssh M -c "sudo ip link set eth2 down"
    vagrant ssh R -c "sudo ip link set eth2 down"
    vagrant ssh Z -c 'ping -c 1 10.200.200.1'
}

install
scenario_1
