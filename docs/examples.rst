Examples
========
This section presents examples which can be followed through to see how the
``auditee`` tool can be used.

Before diving in, it may be useful to survey the context of these examples,
and consequently, we present a bit of background information
:ref:`below <background-examples>`. To start with the examples just jump to
:ref:`run-examples`.

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
`Enclave.signed.so`, and a remote attestation verification report from Intel's
attestation service (IAS). In these examples, the IAS report is in a json
file, usually named `ias-report.json`, which also contains Intel's signature
and certificate necessary to verify the authenticity of the report. To sum up,
an example contains the following pieces of information:

* enclave source code
* pre-built signed enclave binary (`Enclave.signed.so`)
* remote attestation report verified by Intel (`ias-report.json`)

A remote attestation report can contain application and/or user specific data
in a field named ``REPORT_DATA``. This report data is added by the enclave
code at the time a quote is generated. Each example presented in this
documentation will attempt to show a different usage of this ``REPORT_DATA``
field. One important thing to notice is that if a remote attestation report
is "trusted" and hence the ``REPORT_DATA`` it contains, users and applications
can make use of this ``REPORT_DATA`` 

in the context as trusted data originating from a "trusted" enclave.




sgx-hash
^^^^^^^^

