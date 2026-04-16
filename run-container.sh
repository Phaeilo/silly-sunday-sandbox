#!/bin/bash

jq --arg dir "$PWD" '.hook.path = $dir + "/firewall.sh"' "$PWD/hooks/firewall_hook.json.skel" > "$PWD/hooks/firewall_hook.json"

kitty_args=()
if [ "$TERM" = "xterm-kitty" ]; then
    kitty_args=(
        --volume "${TERMINFO}/x/xterm-kitty:/home/ubuntu/.terminfo/x/xterm-kitty:ro"
        --env TERM=xterm-kitty
    )
fi

podman \
    --hooks-dir "$PWD/hooks" \
    run --rm -it \
    --annotation firewall=yes \
    --network "pasta:--address,10.0.2.100,--netmask,255.255.255.0,--gateway,10.0.2.2,--map-host-loopback,10.0.2.2,--no-udp,--no-icmp,--no-ndp,--no-dhcpv6,--no-ra,--ipv4-only" \
    --volume ./shared:/shared \
    "${kitty_args[@]}" \
    --hostname sandbox \
    sandbox:latest
