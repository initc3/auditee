FROM python:3

COPY --from=initc3/linux-sgx:2.13-ubuntu20.04 /opt/sgxsdk/bin /opt/sgxsdk/bin

RUN apt-get update && apt-get install -y \
                vim \
        && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src

COPY . .

RUN pip install --upgrade pip
RUN pip install --editable .[dev,docs,test]

# download docker cli so it's already there,
# to avoid downloading it at runtime
# more information at:
# https://gabrieldemarmiesse.github.io/python-on-whales/docker_client/#the-docker-cli
#RUN python-on-whales download-cli

# docker cli
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
