.. auditee documentation master file, created by
   sphinx-quickstart on Mon Feb 15 17:48:46 2021.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

auditee
=======
**WORK IN PROGRESS** -- **Don't trust!**

``auditee`` is a tool to help verifying the reproducibility of Intel SGX
enclave builds. This can be helpful to assess if a given signed enclave build
and/or remote attestation report correspond to some source code.

Although currently focused on Intel SGX, some concepts may be applicable to
other trusted execution environments (TEEs).

Installation
------------
In order to use all the functionalities that ``auditee`` can provide, the
Intel SGX SDK must be installed. If you don't want to bother with, the easiest
is to clone the repo and use the provided ``Dockerfile`` and
``docker-compose.yml``. The examples assume this setup for now. See below for
an alternative installation, without ``docker``, in which the Intel SGX SDK
is installed.

Clone the GitHub repository:

.. code-block:: shell

    $ git clone --recurse-submodules https://github.com/initc3/auditee.git

Note the ``--recurse-submodules`` option to initialize the git submodules
used in the examples.


Alternative installtion (without docker)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. important:: The Intel SGX SDK version 2.14 must be installed.

Create a virtual environment, e.g.:

.. code-block:: shell

    python3.8 -m venv ~/.venvs/auditee

Enter the Wu-Tang (36 Chambers) aka virtual environment:

.. code-block:: shell

    source ~/.venvs/auditee/bin/activate

Install ``auditee`` from GitHub:

.. code-block:: shell

    pip install git+https://github.com/initc3/auditee.git


To install the SGX SDK, see https://01.org/intel-softwareguard-extensions/downloads/intel-sgx-linux-2.14-release.

Here's an example for installing the SDK on Ubuntu 20.04, under ``$HOME``:

.. code-block:: shell

    wget -O sdk.bin https://download.01.org/intel-sgx/sgx-linux/2.14/ubuntu20.04-server/sgx_linux_x64_sdk_2.14.100.2.bin --progress=dot:giga

    echo d0626ffb36c2e20c589d954fb968fded24ce51529b8b61a42febb312fd9debfc sdk.bin" | sha256sum --strict --check -
    chmod +x sdk.bin
    ./sdk.bin --prefix=~/
    echo 'source ~/sgxsdk/environment' >> ~/.bashrc

Here's an example for installing the SDK on Ubuntu 18.04, under ``~/``:

.. code-block:: shell

    wget -O sdk.bin https://download.01.org/intel-sgx/sgx-linux/2.14/distro/ubuntu18.04-server/sgx_linux_x64_sdk_2.14.100.2.bin --progress=dot:giga
    echo 3509a16e37e172369e1c4c4664047ad08bf3e608588a3a0df7367401e5f81e97 sdk.bin" | sha256sum --strict --check -
    chmod +x sdk.bin
    ./sdk.bin --prefix=~/
    echo 'source ~/sgxsdk/environment' >> ~/.bashrc


Usage
-----
See the examples documented under :ref:`sgx-hashmachine` and
:ref:`sgx-iot-gateway`, for an in-depth look into how ``auditee`` can be used.

Documentation of the main interfaces is at :ref:`api`.

There's also simple command-line, still under development that can be used,
e.g.:

.. code-block:: shell

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


.. toctree::
    :maxdepth: 1
    :hidden:

    examples
    config
    tool
    background
    relatedwork
    glossary
    refs
    ack

.. Prerequisites
.. -------------
.. The `SGX signing tool <sgxsign>`_, which is part of the SGX SDK, is needed
.. for some operations. See https://github.com/intel/linux-sgx instructions to
.. install manually, and ...
.. 
.. Once installed, ``auditee`` needs to know where the ``sgx_sign`` tool is.
.. It assumes it is under ``/opt/sgxsdk/bin/x64/sgx_sign`` by default. If your
.. installation differs set the environment variable ``SGX_SDK_CMD``. For
.. instance:
.. 
.. .. code-block:: shell
.. 
..     $ export SGX_SDK_CMD=~/sgxsdk/bin/sgx_sign
.. 
.. .. todo:: Provide instructions on installing the SGX SDK. Look into whether
..    it could be installed automatically when ``auditee`` is installed. Also,
..    suggest working in a docker container and/or with nix.
.. 
.. 
.. Installation
.. ------------
.. 
.. .. code-block:: shell
.. 
..     $ pip install auditee
.. 
.. 
.. Usage
.. =====
.. The intended use case of ``auditee`` is to verify whether a signed enclave
.. can be reproduced from its source code. Most importantly, the reproduced
.. enclave should have the same MRENCLAVE (enclave hash) than the signed
.. enclave.
.. 
.. For the following example, let's assume that the following material is
.. under the current directory:
.. 
.. * Unsigned enclave shared object file: e.g.: ``Enclave.so``
.. * Enclave configuration file: e.g.: ``Enclave.config.xml``
.. * Signed enclave shared object file: e.g.: ``Enclave.signed.so``
.. 
.. For instance:
.. 
.. .. code-block:: shell
.. 
..     $ ls
..     Enclave.config.xml  Enclave.signed.so  Enclave.so
.. 
.. Then, the ``Enclave.so`` can be verified against the ``Enclave.signed.so``
.. like so:
.. 
.. .. code-block:: python
.. 
..     import auditee
.. 
..     report = auditee.verify(
..         'Enclave.signed.so',
..         'Enclave.so',
..         'Enclave.config.xml',
..     )
.. 
.. By default, the above will print the report to the terminal, and this can
.. be turned off by passing ``verbose=False`` to ``verify()``. There's also a
.. function, ``print_report``, to print a report to the terminal:
.. 
.. .. code-block:: python
.. 
..     >>> auditee.print_report(report)
.. 
.. .. image:: _static/report_without_mrsigner.png



.. Indices and tables
.. ==================
.. 
.. * :ref:`genindex`
.. * :ref:`modindex`
.. * :ref:`search`


.. _sgxsign: https://github.com/intel/linux-sgx/tree/master/sdk/sign_tool/SignTool
