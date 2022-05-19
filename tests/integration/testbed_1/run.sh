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

function test_scenario_1_link_failure {
    echo "Setting up link failure e_m"

    if_T="eth2"
    if_M="eth2"
    link_e_m="$(get_ha T "$if_T")-$(get_ha M "$if_M")"

    vagrant ssh T -c "sudo ip link set $if_T down"
    vagrant ssh M -c "sudo ip link set $if_M down"

    vagrant ssh M -c "ti-mfa-conf add ${link_e_m} 1300 eth3"
}

function test_scenario_2_link_failures {
    test_scenario_1_link_failure || true

    echo "Setting up link failure e_r"

    if_T="eth3"
    if_R="eth2"
    link_e_r="$(get_ha T "$if_T")-$(get_ha R "$if_R")"

    vagrant ssh T -c "sudo ip link set $if_T down"
    vagrant ssh R -c "sudo ip link set $if_R down"

    vagrant ssh R -c "ti-mfa-conf add ${link_e_r} 1200 eth1"
}

function test_received_packet {
    local listen_interface="$1"

    # Send 1 packet to 10.200.200.1
    # a response is not expected
    vagrant ssh M -c 'sleep 5 && ping -c 1 10.200.200.1' &
    check_pid=$!

    # Check if packet arrives at T
    vagrant ssh T -c 'sudo timeout 20 tcpdump -i '"$listen_interface"' -Q in -c 1 -vvv mpls'
    got_packet=$?

    wait $check_pid || true

    exit $got_packet
}

function topo_test {
    local listen_interface
    case "$1" in
        1 )
            test_scenario_1_link_failure
            listen_interface="eth1"
            ;;
        2 )
            test_scenario_2_link_failures
            listen_interface="eth1"
            ;;
        * ) exit 1 ;;
    esac

    test_received_packet "$listen_interface"
}

prepare || exit 1

if [[ -z "$1" ]]
then
    exit
fi

topo_test "$1"
