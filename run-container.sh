#!/bin/bash

jq --arg dir "$PWD" '.hook.path = $dir + "/firewall.sh"' \
    "$PWD/hooks/firewall_hook.json" > "$PWD/hooks/firewall_hook.json.tmp" \
    && mv "$PWD/hooks/firewall_hook.json.tmp" "$PWD/hooks/firewall_hook.json"

podman \
    --hooks-dir "$PWD/hooks" \
    run --rm -it \
    --annotation firewall=yes \
    --network "pasta:--address,10.0.2.100,--netmask,255.255.255.0,--gateway,10.0.2.2,--map-host-loopback,10.0.2.2,--no-udp,--no-icmp,--no-ndp,--no-dhcpv6,--no-ra,--ipv4-only" \
    --volume ./shared:/shared \
    --volume /usr/lib/kitty/terminfo/x/xterm-kitty:/home/ubuntu/.terminfo/x/xterm-kitty:ro \
    --env TERM=xterm-kitty \
    --hostname sandbox \
    sandbox:latest
