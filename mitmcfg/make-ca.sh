#!/bin/bash
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -out ca.crt -addext keyUsage=critical,keyCertSign -days 1826 -subj '/CN=mitmproxy'
cat ca.key ca.crt > mitmproxy-ca.pem
