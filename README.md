# auditee

**WORK IN PROGRESS -- DO NOT USE -- DO NOT TRUST**

Tool to help with auditing an SGX enclave that has been remotely attested.
The idea is as follows:

Given:
* a signed enclave binary file (e.g. `Enclave.signed.so`),
* the source code used to build the enclave, and
* an attestation report,

an auditor verifies:

* whether the signed enclave build can be reproduced, using the source code, and
a nix & docker based toolchain to rebuild the enclave binary
* Whether the MRENCLAVE and ATTRIBUTES of the provided signed Enclave match that of
  the rebuilt one
* Whether the MRENCLAVE and ATTRIBUTES match the ones from the provided report

Roughly speaking the goal is to establish that the source code was indeed the code
used to build the signed enclave that has been successfully (remotely) attested.

Such an audit can help external users gain trust into a system which depends on
Intel SGX and remote attestation. Without such an audit, remote attestation is not
sufficient because the fact that an MRENCLAVE (enclave hash) matches that of the
attestation verification report does not prove to a user of the system that the
MRENCLAVE corresponds to a version of source code that they are willing to trust.


## MRENCLAVE (enclave hash)
The MRENCLAVE, also known as enclave hash, from three sources must all match. The
enclave hash is obtained via a _measurment_ of the enclave code and data when an
enclave is initialized. This measurement can also be simulated, and thus a verifier
can obtain the MRENCLAVE using a build toolchain, and the SGX signing tool to get
the SIGSTRUCT which contains the MRENCLAVE.

1. Hash extracted from the signed enclave (`Enclave.signed.so`) that is remotely attestated
2. Hash in the attestation report, from IAS
3. Hash extracted from the enclave, which was rebuilt from source code using a
   nix+docker based toolchain

If (1) and (3) match then the auditor can trust that they are auditing the correct
code, and can trust that the report is for the enclave that is under audit, and
consequently the successful attesation can be trusted in sofar that the attestation
is for source code that has been audited.
