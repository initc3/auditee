Configuration
=============
When using ``auditee`` to build an enclave binary from source code, the
source code is expected to contain an ``.auditee.yml`` file which instructs
``auditee`` on how to build the enclave binary. Here's an example:

.. code-block:: yaml

    enclaves:
      - name: sgx-iot
        build:
          builder: nix-build
          build_kwargs:
            file: default.nix
          output_dir: result/bin
          enclave_file: enclave.unsigned.so
        enclave_config: enclave/enclave.config.xml
