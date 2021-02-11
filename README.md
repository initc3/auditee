# auditee
**WORK IN PROGRESS -- DO NOT USE -- DO NOT TRUST**

``auditee`` is a tool to help verifying that an SGX enclave that has been
remotely attested matches some given source code.

The idea is as follows:

Given:
* a signed enclave binary file (e.g. `Enclave.signed.so`),
* the source code used to build the enclave, and
* an attestation report,

an auditor verifies:

* whether the signed enclave build can be reproduced, using the source code,
  and a nix & docker based toolchain to rebuild the enclave binary;
* whether the MRENCLAVE and ATTRIBUTES of the provided signed Enclave match
  that of the rebuilt one;
* whether the MRENCLAVE and ATTRIBUTES match the ones from the provided
  report.

The verification can allow an external user gain confidence in the user or
applicaiton specific data that may be included in the remote attestation
report. The verification may also allow a user to deploy the provided signed
enclave with confidence that it corresponds to some source code.
