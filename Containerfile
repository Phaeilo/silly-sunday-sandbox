FROM ubuntu:latest

COPY mitmcfg/mitmproxy-ca.pem /usr/local/share/ca-certificates/mitmproxy-ca-cert.crt

# ── Base packages ─────────────────────────────────────────────────────────────
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        # core build toolchain
        build-essential \
        gcc \
        g++ \
        clang \
        lld \
        make \
        cmake \
        ninja-build \
        pkg-config \
        # scripting / interpreted languages
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        # VCS / editors / multiplexers
        git \
        vim \
        screen \
        tmux \
        # download / network utils
        curl \
        wget \
        netcat-openbsd \
        net-tools \
        iputils-ping \
        iproute2 \
        bind9-dnsutils \
        libcap2-bin \
        iptables \
        ca-certificates \
        # file / system utils
        less \
        tree \
        jq \
        file \
        xxd \
        # archive / unpacking
        unzip \
        zip \
        p7zip-full \
        tar \
        gzip \
        bzip2 \
        xz-utils \
        zstd \
        lzop \
        cabextract \
        unrar-free \
        arj \
        lhasa \
        cpio \
        squashfs-tools \
        # reverse engineering + binary analysis
        gdb \
        gdb-multiarch \
        ltrace \
        strace \
        binutils \
        nasm \
        radare2 \
        patchelf \
        binwalk \
        qemu-user \
        qemu-user-static \
        sudo \
    && update-ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── Python RE / pwn tools (system-wide) ──────────────────────────────────────
RUN pip3 install --break-system-packages pwntools ROPgadget

# ── Go ────────────────────────────────────────────────────────────────────────
ARG GO_VERSION=1.24.2
RUN wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz \
    && rm go${GO_VERSION}.linux-amd64.tar.gz

# ── Node.js 22 LTS + Claude Code ─────────────────────────────────────────────
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g @anthropic-ai/claude-code

# ── ubuntu: passwordless sudo + bash as default shell ────────────────────────
RUN echo "ubuntu ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/ubuntu \
    && chmod 0440 /etc/sudoers.d/ubuntu \
    && chsh -s /bin/bash root \
    && chsh -s /bin/bash ubuntu

# ── Global proxy + CA trust (runtime only — proxy not available during build) ─
RUN { \
        echo 'http_proxy=http://10.0.2.2:31337'; \
        echo 'https_proxy=http://10.0.2.2:31337'; \
        echo 'HTTP_PROXY=http://10.0.2.2:31337'; \
        echo 'HTTPS_PROXY=http://10.0.2.2:31337'; \
        echo 'no_proxy=localhost,127.0.0.1'; \
        echo 'NO_PROXY=localhost,127.0.0.1'; \
        echo 'NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/mitmproxy-ca-cert.crt'; \
        echo 'REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt'; \
        echo 'SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt'; \
    } >> /etc/environment \
    && { \
        echo 'export http_proxy=http://10.0.2.2:31337'; \
        echo 'export https_proxy=http://10.0.2.2:31337'; \
        echo 'export HTTP_PROXY=http://10.0.2.2:31337'; \
        echo 'export HTTPS_PROXY=http://10.0.2.2:31337'; \
        echo 'export no_proxy=localhost,127.0.0.1'; \
        echo 'export NO_PROXY=localhost,127.0.0.1'; \
        echo 'export NODE_EXTRA_CA_CERTS=/usr/local/share/ca-certificates/mitmproxy-ca-cert.crt'; \
        echo 'export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt'; \
        echo 'export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt'; \
    } > /etc/profile.d/proxy.sh \
    && chmod 0755 /etc/profile.d/proxy.sh

# ══ Default to ubuntu user ════════════════════════════════════════════════════
USER ubuntu
WORKDIR /home/ubuntu

# ── Rust (per-user via rustup) ────────────────────────────────────────────────
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path

# ── uv (fast Python package / project manager) ───────────────────────────────
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

# ── work dir + helpers ────────────────────────────────────────────────────────
RUN mkdir -p ~/work \
    && { \
        echo ''; \
        echo '. /etc/profile.d/proxy.sh'; \
        echo 'alias danger-claude="claude --dangerously-skip-permissions"'; \
        echo 'export PATH=/home/ubuntu/.cargo/bin:/home/ubuntu/.local/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'; \
        echo 'export ANTHROPIC_API_KEY=PLACEHOLDER_API_KEY'; \
        echo 'export UV_NATIVE_TLS=1'; \
    } >> ~/.bashrc
COPY --chown=ubuntu:ubuntu sandbox_system_prompt.md /home/ubuntu/.claude/CLAUDE.md

