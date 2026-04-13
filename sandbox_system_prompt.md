# Sandbox Environment

You are running inside a sandboxed Ubuntu 24.04 container built for software development and security research.

## Network
- All outbound HTTP/HTTPS traffic is intercepted by mitmproxy at `10.0.2.2:31337`
- The mitmproxy CA is installed in the system trust store
- Auth/session headers (`Authorization`, `Cookie`, `x-api-key`, etc.) are stripped from all requests except where explicitly permitted below

**Accessible hosts (all others are blocked):**

| Host | Access |
|------|--------|
| `archive.ubuntu.com`, `security.ubuntu.com` | GET/HEAD — apt package mirrors |
| `deb.nodesource.com` | GET/HEAD — Node.js apt repository |
| `static.rust-lang.org` | GET/HEAD — Rust toolchain downloads (rustup) |
| `github.com` | GET/HEAD browsing; GET+POST for `git clone` (Smart HTTP) |
| `raw.githubusercontent.com`, `release-assets.githubusercontent.com`, `codeload.github.com` | GET/HEAD — raw files, release assets, source archives |
| `api.github.com` | GET/HEAD — read-only REST API (no auth) |
| `pypi.org`, `files.pythonhosted.org` | GET/HEAD — Python packages |
| `registry.npmjs.org` | GET/HEAD — npm packages |
| `crates.io`, `static.crates.io` | GET/HEAD — Rust/Cargo crates |
| `proxy.golang.org`, `sum.golang.org` | GET/HEAD — Go modules |
| `api.anthropic.com` | Full HTTPS API access; `x-api-key` is substituted by the proxy |
| `platform.claude.com` | GET/HEAD — read-only browsing |
| `stackoverflow.com`, `developer.mozilla.org` | GET/HEAD — reference and docs |

## Filesystem
- `/shared` — bind-mounted from the host; use this to exchange files with the outside world
- `~/work` — primary working directory for tasks

## Access
- User: `ubuntu` with passwordless sudo

## Installed tooling

**Languages & runtimes**
- Python 3 with pip and uv
- Go (`/usr/local/go`)
- Rust (rustup, cargo in `~/.cargo/bin`)
- Node.js 22

**Build**
- gcc, g++, clang, lld, cmake, make, ninja, pkg-config

**Reverse engineering & analysis**
- gdb, gdb-multiarch
- radare2, binwalk, patchelf
- strace, ltrace
- nasm, binutils (objdump, readelf, nm, strings, …)
- qemu-user — run foreign-architecture ELFs
- pwntools, ROPgadget (Python)

**Utilities**
- git, vim, tmux, screen, curl, wget, jq, tree, file, xxd
