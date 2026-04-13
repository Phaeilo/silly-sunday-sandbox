#!/bin/bash

podman build \
    --tag sandbox:latest \
    --file Containerfile \
    .
