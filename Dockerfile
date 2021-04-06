FROM python:3

COPY --from=initc3/linux-sgx:2.13-ubuntu20.04 /opt/sgxsdk/bin /opt/sgxsdk/bin

RUN apt-get update && apt-get install -y \
                vim \
        && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src

COPY . .

RUN pip install --upgrade pip
RUN pip install --editable .[dev,docs,test]
