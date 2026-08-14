FROM ubuntu:22.04

ARG TARGETARCH=arm64

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/root/go/bin:/usr/local/go/bin:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    wget \
    iputils-ping \
    netcat-openbsd \
    dnsutils \
    nmap \
    nikto \
    hydra \
    python3 \
    python3-pip \
    iptables \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://go.dev/dl/go1.22.5.linux-${TARGETARCH}.tar.gz" | tar -C /usr/local -xz

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/OJ/gobuster/v3@latest

# Bake nuclei templates at build time — avoids re-download on every ephemeral container
RUN nuclei -update-templates > /dev/null 2>&1

# Download SecLists common wordlist for gobuster
RUN mkdir -p /usr/share/wordlists && \
    curl -fsSL -o /usr/share/wordlists/common.txt \
    https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt

# Quick test wordlists for hydra — small enough to finish in <1 minute
RUN printf '%s\n' root admin test user ubuntu pi vagrant guest > /usr/share/wordlists/hydra-quick-users.txt
RUN printf '%s\n' root admin password 123456 toor test user 12345 1234 123 abc123 password123 admin123 letmein welcome qwerty monkey dragon master passw0rd 1q2w3e 111111 000000 > /usr/share/wordlists/hydra-quick-passwords.txt

RUN pip3 install --no-cache-dir sqlmap

WORKDIR /output
