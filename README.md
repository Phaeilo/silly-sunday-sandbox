# silly-sunday-sandbox

A sandboxed Ubuntu container with locked down network egress for running Claude Code with `--dangerously-skip-permissions`.

> Built on a Sunday afternoon for a laugh. Use at your own risk.

## Usage

```sh
# First time only
cd mitmcfg && ./make-ca.sh && cd ..
./build-container.sh

# Every session
export ACTUAL_ANTHROPIC_API_KEY=sk-ant-...
./run-mitmproxy.sh
# (new terminal)
./run-container.sh

# Inside container
cd work/
danger-claude
# Go wild!
```

## Built with

- [Podman](https://podman.io/) container runtime
- [pasta](https://passt.top/) userspace networking
- [mitmproxy](https://mitmproxy.org/) TLS-intercepting proxy; `addon.py` enforces per-host policies and substitutes placeholder credentials with real ones
- [nftables](https://nftables.org/) container-side firewall; blocks all egress except the proxy
- [OCI hooks](https://github.com/opencontainers/runtime-spec/blob/v1.0.1/config.md#posix-platform-hooks) runs `firewall.sh` at container creation

Also requires: `openssl` and `jq`

## Hard-coded to my setup

A lot of this is deliberately specific rather than generic; adjust to taste:

- **Proxy port** — `31337` (in `mitmcfg/config.yaml`, `firewall.sh`, `Containerfile`)
- **Network range** — `10.0.2.0/24`, gateway `10.0.2.2` (pasta config in `run-container.sh`)
- **Allowed hosts and policies** — `POLICIES` list in `addon.py`
- **API key placeholders** — `PLACEHOLDER_API_KEY` / `PLACEHOLDER_AUTH_TOKEN` and the env var names they map to
- **Container mounts** — `./shared` and the kitty terminfo path in `run-container.sh`
- **Installed tooling** — compilers, RE tools, language runtimes in `Containerfile`
- **System prompt** — `sandbox_system_prompt.md` baked into the image

## License

MIT
