"""Auditee is a small tool to assist the task of auditing an SGX enclave.

Given the following 3 pieces of data:

* a signed enclave binary file (``Enclave.signed.so``),
* the source code that was used to compile the enclave binary, and
* an attestation verification report signed by Intel for this enclave binary

an auditor, would like to verify that the signed enclave binary can be reproduced
from the source code, and more particularly that the MRENCLAVE of the signed enclave
matches that of the reproduced binary, and also matches the MRENCLAVE found in the
report, signed by Intel. If the MRENCLAVE is the same for all three, then an auditor
can link the different observations from auditing the source code, to the signed
enclave binary and to its deployment, to which the attestation report corresponds.
"""
from auditee.reproducibility import print_report, verify  # noqa F401
