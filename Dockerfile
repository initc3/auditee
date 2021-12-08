FROM python:3 as dev

# SGX SDK
COPY --from=initc3/linux-sgx:2.14-ubuntu20.04 /opt/sgxsdk/bin /opt/sgxsdk/bin

# Docker CLI
# https://gabrieldemarmiesse.github.io/python-on-whales/docker_client/#the-docker-cli
# RUN python-on-whales download-cli
RUN set -ex; \
    \
    apt-get update; \
    apt-get install -y \
        apt-transport-https \
        ca-certificates \
        curl \
        gnupg \
        lsb-release; \
    curl -fsSL https://download.docker.com/linux/debian/gpg | \
        gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg; \
    echo \
        "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] \
        https://download.docker.com/linux/debian $(lsb_release -cs) stable" | \
        tee /etc/apt/sources.list.d/docker.list > /dev/null; \
    apt-get update; \
    apt-get install -y docker-ce-cli;
RUN apt-get update && apt-get install -y \
                vim \
        && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src

COPY LICENSE Makefile MANIFEST.in pyproject.toml setup.cfg setup.py ./
COPY auditee auditee

RUN pip install --upgrade pip
RUN pip install --editable .[dev,docs,test]

WORKDIR /usr/src
COPY docs docs
COPY tests tests
COPY examples examples

FROM dev as examples
# nix
ARG UID=1000
ARG GID=1000

ENV DEBIAN_FRONTEND "noninteractive"

RUN apt-get update && apt-get install -y git curl wget sudo xz-utils
RUN groupadd -g $GID -o nix \
    && useradd -m -u $UID -g $GID -o -s /bin/bash nix \
    && usermod -aG sudo nix \
    && echo "nix ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/nix

ENV USER nix
USER nix

WORKDIR /home/nix

#COPY --chown=nix:nix ./nix.conf /home/nix/.config/nix/nix.conf

RUN curl -L https://nixos.org/nix/install | sh

RUN . /home/nix/.nix-profile/etc/profile.d/nix.sh && \
  nix-channel --add https://nixos.org/channels/nixos-21.11 nixpkgs && \
  nix-channel --update

ENV NIX_PROFILES "/nix/var/nix/profiles/default /home/nix/.nix-profile"
ENV NIX_PATH /home/nix/.nix-defexpr/channels
ENV NIX_SSL_CERT_FILE /etc/ssl/certs/ca-certificates.crt
ENV PATH /home/nix/.nix-profile/bin:$PATH

#RUN echo "cd ~/nix-workshop && source ./scripts/setup.sh" >> /home/nix/.profile

WORKDIR /usr/src
COPY --chown=nix:nix examples examples
