#!/usr/bin/bash -x

pushd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

vagrant up

machine_neighbor_pairs=$(jq -r '.Neighbours | to_entries | .[] | .key as $machine | .value | map($machine + "=" + .) | .[]' network_config.json)

for machine_neighbor_pair in $machine_neighbor_pairs
do
    machine=${machine_neighbor_pair%=*}
    neighbour=${machine_neighbor_pair#*=}
    vagrant ssh "$machine" -c "ping -c 1 $neighbour"
done

popd || exit 1
