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
Clone the GitHub repository:

.. code-block:: shell

    $ git clone --recurse-submodules https://github.com/sbellem/auditee.git

Note the ``--recurse-submodules`` option to initialize the git submodules
used in the examples.

Usage
-----
See the examples documented under :ref:`sgx-hashmachine` and :ref:`sgx-iot-gateway`.



.. toctree::
    :maxdepth: 1
    :hidden:

    examples
    background
    credits

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
