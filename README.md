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


---

* whether the signed enclave build can be reproduced, using the source code, and a nix & docker based toolchain to rebuild the enclave binary
* IF possible: whether the MRENCLAVE and MRSIGNER of the provided signed Enclave match that of the rebuilt one
* whether the MRENCLAVE and MRSIGNER match the ones from the provided report

Roughly speaking the goal is to establish that the source code was indeed the code used to build the signed enclave that has been successfully (remotely) attested.

Such an audit can help external users gain trust into a system which depends on Intel SGX and remote attestation. Without such an audit, remote attestation is not sufficient because the fact that an MRENCLAVE (enclave hash) matches that of the attestation verification report does not prove to a user of the system that the MRENCLAVE corresponds to a version of source code that they can trust.

In way, this kind of audit could be seen as a setup phase, in which a precise version (e.g. with a specifc commit hash) of a codebase goes through security audits, and is then "frozen", meaning that the code MUST remain in that state which is uniquely identified with the latest commit hash.

Then the enclave is built and signed, and its hash and signature (MRENCLAVE & MRSIGNER) can be published to parties that will interact with the enclave applicaiton, and will need to verify its attestation with IAS. A remote verifier before trusting an enclave requests a "quote" from the application hosting the enclave which can be sent to IAS for verification. IAS returns to the remote verifier a report in which the MRENCLAVE and MRSIGNER can be verified against the "trusted configutation" which for our case here, mainly contains the MRENCLAVE and MRSIGNER. So how is this "trusted configuration" established, and obtained? The idea here, is that this "trusted configuration" is established trough security audits, which verify that an MRENCLAVE, in an attestation verification report, match that of a signed enclave, which in turn can be reproduced from source code that is under audit. 

So, 3 hashes must all match:

1. Hash extracted from the signed enclave (`Enclave.signed.so`) that is remotely attestated
2. Hash in the attestation report, from IAS
3. Hash extracted from the rebuilt enclave by an auditor, using the nix+docker based toolchain

If (1) and (3) match then the auditor can trust that they are auditing the correct code, and can trust that report is for the enclave that is under audit, and consequently the successful attesation can be trusted in sofar that the attestation is for source code that has been audited

To put things differently. Alice wants to use new app that claims to be ultra secure because it uses SGX. The app says you can provide it your secrets, and that your secrets will be safe because they will be in an SGX enclave which cannot be accessed by anyone, even those who have access to the computer system software, excluding the hardware, as some attacks such as chip attacks, or power voltage attacks (voltpillager) may be possible. Assuming Alice trusts that no one will be able to perform hardware attacks, she is willing to trust the app and Intel, as long as Intel can attest that the enclave is a legit one. But Alice wonders whether the code of the enclave is secure. So let's say she audits the code, and concludes the code is secure. Great! But wait, how can Alice be sure that the app is indeed using that code that she just audited? Using the audited source code, Alice builds an enclave binary (`Enclave.so`) and signs it with a key. She then requests the app to provide a copy of the signed enclave binary that has been remotely attested, along with the latest remote attestation report. Alice then compares the app's signed enclave with the one she built to see if they are the "same" (what does "same" mean in this context MUST be explained -- is it same hash - MRENCLAVE). If the 2 enclaves match it is not sufficient, as the enclave must also be proven to be a "genuine" enclave. For this verification a report from IAS is necessary. Alice, verifies the authenticity of the report by checking its certificate/public key and signature. If the report is authentic, meaning indeed from Intel, then Alice checks whether the report states that the enclave is legit, and if so Alice must then verify that the MRENCLAVE in the report matches the one of the app's signed enclave. Alice can only trusts that the signed enclave was built from the source code if she can herself rebuild the ~same enclave binary from the source code.


**How can this be summarized?**

Bob claims to have a super secure app based on Intel SGX.
Alice trusts Intel but does not trust Bob. To determine whether she trust Bob's app, Alice asks Bob to provide her:

* a copy of the enclave binary, signed by Bob, being used by the app
* access to the source code which was used to build the enclave binary
* latest attestation verification report from Intel's attestation service (IAS)

Alice then performs an audit, involving:
* verification of the protocol
* security audit of the source code, making sure the implementation is correct, and corresponds to a protocol that is theoretically secure 
* build the enclave binary from the source code, using "reproducible build" nix+docker based toolchain 
* verifies whether the signed enclave binary was indeed signed by Bob (extract the MRSIGNER)
* verifies whether the signed enclave's metadata matches Alice's enclave build (this metadata SHOULD have the MRENCLAVE)
* verifies that the MRENCLAVE in the IAS report matches the MRENCLAVE of both Bob's enclave and Alice's reproduced enclave
* verifies that the IAS report states that the enclave is a genuine enclave that can be trusted

Upon a successful audit Alice, can then trust that the app is secure ...

A successful verification can help providing higher confidence to external users of a system which claims to be secur as the source code passes the scrutitny 
