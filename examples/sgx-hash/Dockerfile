FROM initc3/nix-sgx-sdk@sha256:509e4c8e5ab7aeea4d78d2f61df45caa388279036a0c8e984630321d783ea2d3 AS build-stage

WORKDIR /usr/src
COPY . .

RUN nix-build enclave.nix

FROM scratch AS export-stage
COPY --from=build-stage /usr/src/result/bin /
