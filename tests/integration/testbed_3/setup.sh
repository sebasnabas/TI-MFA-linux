#!/usr/bin/bash -x

pushd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

vagrant up "$1"

machine_neighbor_pairs=$(jq -r '.Neighbours | to_entries | .[] | .key as $machine | .value | map($machine + "=" + .) | .[]' network_config.json)

for machine_neighbor_pair in $machine_neighbor_pairs
do
    machine=${machine_neighbor_pair%=*}

    if [[ "${1:-null}" != null ]] && [[ "$machine" != "$1" ]]
    then
        continue
    fi

    neighbour=${machine_neighbor_pair#*=}
    vagrant ssh "$machine" -c "ping -c 1 $neighbour"
done

popd || exit 1
