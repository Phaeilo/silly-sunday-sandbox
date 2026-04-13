#!/bin/bash

podman \
    --hooks-dir /home/philip/Documents/Projects/sandbox/hooks \
    run --rm -it \
    --annotation myannotation=yes \
    --network "pasta:--address,10.0.2.100,--netmask,255.255.255.0,--gateway,10.0.2.2,--map-host-loopback,10.0.2.2,--no-udp,--no-icmp,--no-ndp,--no-dhcpv6,--no-ra,--ipv4-only" \
    --volume ./shared:/shared \
    --volume /usr/lib/kitty/terminfo/x/xterm-kitty:/home/ubuntu/.terminfo/x/xterm-kitty:ro \
    --env TERM=xterm-kitty \
    --hostname sandbox \
    sandbox:latest
