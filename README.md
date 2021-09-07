# auditee

[![Join the chat at https://gitter.im/auditee/community](https://badges.gitter.im/auditee/community.svg)](https://gitter.im/auditee/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

**WORK IN PROGRESS** -- **Don't trust!**

`auditee` is a tool to help verifying the reproducibility of Intel SGX
enclave builds. This can be helpful to assess if a given signed enclave build
and/or remote attestation report correspond to some source code.

Although currently focused on Intel SGX, some concepts may be applicable to
other trusted execution environments (TEEs).

## Installation
In order to use all the functionalities that `auditee` can provide, the
Intel SGX SDK must be installed. If you don't want to bother with, the easiest
is to clone the repo and use the provided `Dockerfile` and
`docker-compose.yml`. The examples assume this setup for now. See below for
an alternative installation, without `docker`, in which the Intel SGX SDK
is installed.

Clone the GitHub repository:

```shell
git clone --recurse-submodules https://github.com/sbellem/auditee.git
```

Note the `--recurse-submodules` option to initialize the git submodules
used in the examples.


### Alternative installtion (without docker)

**IMPORTANT**: The Intel SGX SDK version 2.14 must be installed.

Create a virtual environment, e.g.:

```shell
python3.9 -m venv ~/.venvs/auditee
```

Enter the Wu-Tang (36 Chambers) aka virtual environment:

```shell
source ~/.venvs/auditee/bin/activate
```

Install `auditee` from GitHub:

```shell
pip install git+https://github.com/sbellem/auditee.git
```

To install the SGX SDK, see
https://01.org/intel-softwareguard-extensions/downloads/intel-sgx-linux-2.14-release.

Here's an example for installing the SDK on Ubuntu 20.04, under `$HOME`:

```shell
wget -O sdk.bin https://download.01.org/intel-sgx/sgx-linux/2.14/ubuntu20.04-server/sgx_linux_x64_sdk_2.14.100.2.bin --progress=dot:giga

echo d0626ffb36c2e20c589d954fb968fded24ce51529b8b61a42febb312fd9debfc sdk.bin" | sha256sum --strict --check -
chmod +x sdk.bin
./sdk.bin --prefix=~/
echo 'source ~/sgxsdk/environment' >> ~/.bashrc
```


## Usage
See the examples documented under https://auditee.readthedocs.io/en/latest/examples.html
for an in-depth look into how `auditee` can be used.

Documentation of the main interfaces is at
https://auditee.readthedocs.io/en/latest/tool.html.

There's also simple command-line, still under development that can be used,
e.g.:

```console
auditee mrenclave --help

usage: auditee mrenclave [-h]
                     [--signed-binary SIGNED_BINARY | --src SRC | --ias-response IAS_RESPONSE | --quote-binary QUOTE_BINARY]

Compute the MRENCLAVE of an enclave.

optional arguments:
  -h, --help            show this help message and exit
  --signed-binary SIGNED_BINARY
                        signed enclave binary
  --src SRC             enclave source code (local file path or git repository URL)
  --ias-response IAS_RESPONSE
  --quote-binary QUOTE_BINARY

examples:
    Compute the MRENCLAVE from a signed enclave binary:
    $ auditee mrenclave --signed-binary enclave.signed.so

    Compute the MRENCLAVE from local source code:
    $ auditee mrenclave --src sgx-iot/

    Compute the MRENCLAVE from source code of a remote git repository:
    $ auditee mrenclave --src https://github.com/sbellem/sgx-iot

    Specify a branch or a commit:
    $ auditee mrenclave --src https://github.com/sbellem/sgx-iot@dev
    $ auditee mrenclave --src https://github.com/sbellem/sgx-iot@313fb50

    Compute the MRENCLAVE from an IAS verification report:
    $ auditee mrenclave --ias-response ias_response.json
```
