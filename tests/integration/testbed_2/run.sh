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
            A )
                vagrant ssh A -c "sudo ip link set eth2 up"
                ;;
            B )
                vagrant ssh B -c "sudo ip link set eth2 up"
                ;;
            C )
                vagrant ssh C -c "sudo ip link set eth1 up"
                vagrant ssh C -c "sudo ip link set eth2 up"
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

function test_scenario_1_link_failure {
    echo "Setting up link failure e_m"

    if_A="eth2"
    if_C="eth1"
    link_A_C="$(get_ha A "$if_A")-$(get_ha C "$if_C")"

    vagrant ssh A -c "sudo ip link set $if_A down"
    vagrant ssh C -c "sudo ip link set $if_C down"

    vagrant ssh C -c "ti-mfa-conf add ${link_A_C} 1200 eth2"
}

function test_scenario_2_link_failures {
    test_scenario_1_link_failure || true

    echo "Setting up link failure B-C"

    if_B="eth2"
    if_C="eth2"
    link_B_C="$(get_ha B "$if_B")-$(get_ha C "$if_C")"

    vagrant ssh C -c "ti-mfa-conf add ${link_B_C} 1500 eth3"

    vagrant ssh B -c "sudo ip link set $if_B down"
    vagrant ssh C -c "sudo ip link set $if_C down"

}

function test_received_packet {
    vagrant ssh A -c 'ip route && ip -M route'

    # Send 1 packet to 10.200.200.1
    # and wait for response
    vagrant ssh Z -c 'ping -c 1 10.200.200.1'
}

function topo_test {
    case "$1" in
        1 )
            test_scenario_1_link_failure
            ;;
        2 )
            test_scenario_2_link_failures
            ;;
        * ) exit 1 ;;
    esac

    test_received_packet
}

prepare || exit 1

if [[ -z "$1" ]]
then
    exit
fi

topo_test "$1"
