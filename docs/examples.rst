Examples
========
This section presents examples which can be followed through to see how the
``auditee`` tool can be used.

For background information see the section `<background-examples>`.

Prerequisites
-------------
To follow through the examples as they are presented it's best that you have
`<docker-compose>`_.

Clone the repository, for instance:

.. code-block:: shell

    $ git clone --recursive https://github.com/sbellem/auditee.git


.. _run-examples:

Running the examples
--------------------
This section presents examples which can be followed through to see how the
``auditee`` tool can be used. Each example contains the source code of an
enclave application, which for the sake of demonstration could be seen as
being under audit. One could imagine that an auditing party would inspect the
source code of the enclave to verify that it meets a set of requirements with
respect to security, functionalities, etc. In addition to the source code,
each example contains a pre-built and signed enclave binary, usually named
``Enclave.signed.so``, and a remote attestation verification report from
Intel's attestation service (IAS). In these examples, the IAS report is in a
json file, usually named ``ias-report.json``, which also contains Intel's
signature and certificate necessary to verify the authenticity of the report.
To sum up, an example contains the following pieces of information:

* enclave source code
* pre-built signed enclave binary (``Enclave.signed.so``)
* remote attestation report verified by Intel (``ias-report.json``)

A remote attestation report can contain application and/or user specific data
in a field named ``REPORT_DATA``. This report data is added by the enclave
code at the time a quote is generated. Each example presented in this
documentation will attempt to show a different usage of this ``REPORT_DATA``
field.

.. One important thing to notice is that if a remote attestation report
.. is "trusted" and hence the ``REPORT_DATA`` it contains, users and applications
.. can rely this ``REPORT_DATA``.


sgx-hashmachine
^^^^^^^^^^^^^^^
Alice claims that the hexadecimal string

.. code-block:: python

    b4930c4241d04a313d46452167274763f5a6437ca2c39ce2e2baa24079086e14

is the result of having computed the SHA 256 hash a billion times, starting
with the string ``"Hello World!"``, and repeatedly hashing the new result of
each iteration. For instance, in Python:

.. code-block:: python
    
    s = b'Hello World!'
    for _ in range(1000000000):
        s = sha256(s).digest()
    return s

You could perform the computation yourself, using the above code snippet, to
verify the veracity of the claim. This may take 10 minutes or so. But let's
say that for whatever reason you do not want or cannot perform the computation
yourself. Could you be convinced in another way that the claim is true?

The goal of this example is to show that, if you trust Intel, then you could
indeed be convinced that the claim is true. That is, presented with a remote
attestation verification report, which contains the result of the computation,
we'll verify whether this report "matches" source code that does perform
the billion-times hashing computation over "Hello World!".

To convince yourself that the claim is true, we'll go through the following
steps:

1. Inspect the source code that performs the computation to confirm that it
   indeed hashes a billion times, starting with the string "Hello World!".
2. Verify that the ``MRENCLAVE`` of the remote attestation verification report
   matches the ``MRENCLAVE`` from an enclave binary built from the above
   source code.

.. note:: The authenticity of the remote attestation verification report MUST
    be verified to make sure the report does indeed come from Intel. 

STEP 1: Inspect the source code
"""""""""""""""""""""""""""""""
Go into the directory ``examples/hashmachine/sgx-hashmachine/Enclave`` and
open the file ``Enclave.cpp`` ... check that the number of iterations is
indeed 1 billion (1000000000) and that the initial string is "Hello World!".

.. code-block:: cpp

    sgx_status_t get_report(sgx_report_t *report, sgx_target_info_t *target_info) {
      sgx_report_data_t report_data = {{0}};

      // Hardcoded "Hello World!" string in hexadecimal format
      const uint8_t x[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20,
                           0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21};
      int iterations = 100000000;
      sgx_status_t sha_ret;
      sgx_sha256_hash_t tmp_hash;
      sha_ret = sgx_sha256_msg(x, sizeof(x), (sgx_sha256_hash_t *)tmp_hash);

      for (int i = 1; i < iterations - 1; i++) {
        sha_ret = sgx_sha256_msg((const uint8_t *)&tmp_hash, sizeof(tmp_hash),
                                 (sgx_sha256_hash_t *)tmp_hash);
      }

      sha_ret = sgx_sha256_msg((const uint8_t *)&tmp_hash, sizeof(tmp_hash),
                               (sgx_sha256_hash_t *)&report_data);

      return sgx_create_report(target_info, &report_data, report);
    }

In this example, the enclave code computes the hash (SHA 256) of the string
``"Hello World!"`` and puts the result in the ``REPORT_DATA`` of an attestation
report that can be sent to Intel for verification. Roughly speaking,
``auditee`` can be used to build an enclave binary from some source code and
check that its ``MRENCLAVE`` matches the one in the report. If the
``MRENCLAVE`` of the built-from-source enclave matches the one of the report,
one can then trust that the ``REPORT_DATA`` was indeed generated according to
the source code.

STEP 2: MRENCLAVEs Comparison
"""""""""""""""""""""""""""""
Under the directory ``examples/hashmachine`` there's a file named
``ias-report.json``. This file contains a remote attestation verification
report that was received from Intel's Attestation Service (IAS). The
report contains the MRENCLAVE of the enclave that was attested and a
REPORT_DATA value. The REPORT_DATA contains the hash that we care about,
meanwhile the MRENCLAVE should match that of an enclave binary built from the
source code we inspected in step 1. To compare the two MRENCLAVEs we can use
the ``auditee`` tool which automates the multiple steps required, such as
building the enclave binary, extracting its MRENCLAVE, and parsing the report
for its MRENCLAVE.

From the root of the project, spin up a container:

.. code-block:: shell

    $ docker-compose run --rm auditee bash

Go into the directory of the ``sgx-hash`` example:

.. code-block:: console

    root@f07e2606a418:/usr/src# cd examples/hashmachine/

Start an ipython session:

.. code-block:: console

    root@f07e2606a418:/usr/src/examples/hashmachine# ipython

Use the :py:func:`auditee.verify_mrenclave()` function to verify that the
``MRENCLAVE`` from the enclave binary that built from source matches the
MRENCLAVE in the remote attestation report. Recall that the report confirms,
as per Intel, that the enclave with the specified MRENCLAVE, is a genuine
Intel SGX processor, which in turn, more or less confirms that the code that
it executes has not been tampered with.

.. code-block:: python

    import auditee

    auditee.verify_mrenclave(
        'sgx-quote-sample/',
        'Enclave.signed.so',
        ias_report='ias-report.json',
    )

.. image:: _static/sgx-hash-example.png



.. _background-examples:

Background
----------
**How can one trust the output of an enclave?**

Assuming one trusts the physical security of a chip, that known attacks have
been mitigated, and that the enclave code is not vulnerable to side channel
attacks, then how can one be certain that the output of an enclave is
trustworthy? The short answer is:

    **audits** + **reproducible builds** + **remote attestation**

.. _audits:

Audits
^^^^^^
Audits are necessary to verify that the enclave code does indeed what it is
expected to do and that it meets specific security requirements. For instance,
it may be possible through a security audit to verify that the enclave was
implemented such that it is not vulnerable to certain side-channel attacks.
See https://arxiv.org/abs/2006.13598.

.. todo:: Provide references/citations.

It's essential to make sure that the source code being audited is the exact
code that was used to build the enclave (`Enclave.signed.so`) that is
deployed. Hence, a signed enclave binary must be reproducible from its source
code. The next section covers reproducible builds in the context of enclaves.

.. _reproducible-builds:

Reproducible builds
^^^^^^^^^^^^^^^^^^^
In the context of SGX enclaves, a reproducible build mainly
means that the MRENCLAVE remains constant.

.. _remote-attestation:

Remote attestation
^^^^^^^^^^^^^^^^^^
The remote attestation report also
contains the MRENCLAVE, and can therefore be checked against the source code,
and the pre-built enclave under audit. In other words, given a remote
attestation report, it's possible to verify that the report was generated
by an enclave binary, and it's possible to verify that the enclave binary
was built from a specific version of source code. Through this verification
process a user can then gain trust in the ``REPORT_DATA`` contained in the
remote attestation report. This ``REPORT_DATA`` can contain arbitrary data,
according to the needs of the application.


The auditee tool wishes to help a user of an application that relies on
some output of an enclave wishes

Current State & Motivation
--------------------------

Techincal Challenges
^^^^^^^^^^^^^^^^^^^^

.. _docker-compose: https://docs.docker.com/compose/install/
