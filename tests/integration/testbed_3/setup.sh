#!/usr/bin/bash -x

pushd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

vagrant up

while IFS='=' read -r machine neighbour
do
    vagrant ssh "$machine" -c "ping -c 1 $neighbour" >/dev/null &
done < <(jq -r '.Neighbours | to_entries | .[] | .key as $machine | .value | map($machine + "=" + .) | .[]' network_config.json)

popd || exit 1
