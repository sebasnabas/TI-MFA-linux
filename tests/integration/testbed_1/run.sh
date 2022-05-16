#!/usr/bin/env bash

set -eux

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

function reset {
    for machine in $(vagrant status --machine-readable | grep state,running | cut -d ',' -f 2)
    do
        vagrant ssh "${machine}" -c "sudo rmmod ti_mfa || true"

        case "${machine}" in
            T )
                vagrant ssh T -c "sudo ip link set eth2 up"
                vagrant ssh T -c "sudo ip link set eth3 up"
                ;;
            M )
                vagrant ssh M -c "sudo ip link set eth2 up"
                ;;
            R )
                vagrant ssh R -c "sudo ip link set eth2 up"
                ;;
        esac
    done || exit 1

    # Fill neighbor caches
    ./setup.sh
}

function check_routes {

    destinations=(1 2 3 4)

    for machine in $(vagrant status --machine-readable | grep state,running | cut -d ',' -f 2)
    do
        for dest in "${destinations[@]}"
        do
            vagrant ssh "${machine}" -c "ping -c 1 -w 1 10.200.200.${dest}"
        done || exit 1
    done || exit 1
}

function prepare {
    pushd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

    reset || exit 1

    check_routes || exit 1

    install
}

function test_scenario_1 {
    local link_e_r

    link_e_r="$(get_ha T eth3)-$(get_ha R eth2)"

    vagrant ssh R -c "ti-mfa-conf add ${link_e_r} 1200 eth1"
    vagrant ssh T -c "sudo ip link set eth2 down"
    vagrant ssh T -c "sudo ip link set eth3 down"
    vagrant ssh M -c "sudo ip link set eth2 down"
    vagrant ssh R -c "sudo ip link set eth2 down"

    # Send 1 packet to 10.200.200.1
    # a response is not expected
    vagrant ssh M -c 'sleep 5 && ping -c 1 10.200.200.1' &
    check_pid=$!

    # Check if packet arrives at T
    output="$(vagrant ssh T -c 'sudo timeout 20 tcpdump -i eth1 -Q in mpls')"

    wait $check_pid || true

    echo "$output" | grep '1 packet captured'
}

prepare || exit 1
test_scenario_1
