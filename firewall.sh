#!/bin/bash

/usr/bin/nft -f - <<EOF
table inet filter {
  chain output {
    type filter hook output priority filter; policy drop;
    iif lo accept
    ip daddr 10.0.2.2 tcp dport 31337 accept
  }
}
EOF
