# SGX Hello World! Hash Example
This very simple example, shows how to use the `auditee` tool to check whether
a given signed enclave binary can be rebuilt from source in a reproducible manner,
meaning that the MRENCLAVE of the signed enclave and the one built from source match.
The benefit of the verification is to confirm whether a given signed enclave does
correspond to some source code that can be audited.

In addition to verifying a signed enclave against its source code, it's also possible
to verify that a given IAS (Intel Attestation Service) report does indeed correspond to
the given signed enclave and source code. If all three have their respective MRENCLAVE
matching, an auditing party can gain trust in the REPORT DATA that is included in the
IAS report. That is, an auditing party can trust that the given source code was indeed
the source code used to build the given signed enclave, for which a remote attestation
report was verified by Intel's Attestation Service. It's important to note that Intel
is a trusted party.

To try the example, if you have not done so already, clone the repository,
with submodules, e.g.:

```shell
$ git clone --recurse-submodules https://github.com/sbellem/auditee.git
```

Work in a docker container using `docker-compose`:

```shell
$ docker-compose build auditee
```

Start an ipython session in a container, under the `hashmachine` example directory:

```shell
docker-compose run --rm --workdir /usr/src/examples/hashmachine auditee ipython
```

Verify the "trustworthiness" of the REPORT DATA in a remote attestion report
(`ias-report.json`) that claims to be for a signed enclave (`Enclave.signed.so`)
and some source code (`sgx-quote-sample`):

```python
import auditee

auditee.verify_mrenclave('sgx-hashmachine/', 'Enclave.signed.so', ias_report='ias-report.json')
```

This should output something similar to the following at the end:

```python
# ...

Reproducibility Report
----------------------
- Signed enclave MRENCLAVE:                    901c3b2c92fd8c08654bae68d858f59c81a6121f81e8998cbf9daf236e2ead74
- Built-from-source enclave MRENCLAVE:         901c3b2c92fd8c08654bae68d858f59c81a6121f81e8998cbf9daf236e2ead74
- IAS report MRENCLAVE:                        901c3b2c92fd8c08654bae68d858f59c81a6121f81e8998cbf9daf236e2ead74

MRENCLAVES match!

Report data
-----------
7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d90690000000000000000000000000000000000000000000000000000000000000000

True
```

Now, you can check the report data for yourself. It's supposed to be the SHA 256 of
the string 'Hello World!'. You can inspect (audit) the
[SGX enclave code](https://github.com/sbellem/sgx-hashmachine/blob/main/Enclave/Enclave.cpp#L88-L102)
yourself to verify this:


```cpp
sgx_status_t enclave_set_report_data(sgx_report_data_t *report_data) {
  const uint8_t x[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20,
                       0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21};
  sgx_status_t sha_ret;
  sha_ret = sgx_sha256_msg(x, sizeof(x), (sgx_sha256_hash_t *)report_data);
  return sha_ret;
}
```

```python
>>> import hashlib

>>> hashlib.sha256(b'Hello World!').hexdigest()
'7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069'
```

**TODO**
Explain how it works.

---

# SGX Hash Machine Example
This is a toy application to demonstrate a very simple example of remote
attestation, from the creation of a quote, to the establishment of trust in
the REPORT DATA contained in the remote attestation report.

The goal of remote attestation is to verify that the expected software was
used on a genuine Intel SGX processor. Hence two things need to be verified:

1. Is the enclave code the expected code?
2. Is the enclave code running on genuine hardware?

A remote attestation report provides answers to the above two questions.

The main steps of remote attestation (with the EPID scheme):

1. Verifier, identified by SPID (Service Provider ID) requests a quote to
   enclave application
2. Untrusted code requests a quote for the requesting verifier SPID
3. Trusted code produces quote for the given SPID
4. Untrusted code sends the quote to the verifier
5. Verifier sends quote to Intel Attestation Service for verification, using a
   secret API key, which is linked to the SPID.
6. Intel verifies quote and returns response to verifier
7. Verifier verifies Intel's response authenticity (check signature and
   certificates)
8. Verifier computes the expected MRENCLAVE by reproducing the enclave binary
   from the trusted source code
9. Verifier verifies that the MRENCLAVE in the report corresponds to the
   "simulated" MRENCLAVE from the trusted source code
10. If the MRENCLAVE matches, the Verifier gains trust in the REPORT DATA,
    and proceeds forward with the protocol

`auditee` is used to help with steps 7, 8, 9 and 10. That is, auditee aims to
help automating the verification of a remote attestation report against some
trusted source code. Note that steps 7-10 can be performed by any party,
meaning that these steps don't need to be performed by the verifier who
requested the quote. However since a quote is produced for a specific SPID,
and that sending a quote to Intel requires an API key that matches the SPID,
the quote must be sent by the user who controls the secret API key.

Once the verifier receives the response of Intel, it could delegate the
subsequent steps to another party, or multiple parties. The verifier could
also publish the report on a public bulletin board. For instance, in the
above steps, we could add:

7a. (Optional) Verifier publishes Intel's response on public bulletin board.

and steps 7-10 could be done by anyone. For the rest of this document, let's
assume that the verifier does indeed delegate steps 7-10 to another party.
Intel refers to the verifier as ISV (Independent Software Vendor), let's call
it "Indie the ISV", and let's use the term/name "Vinnie the Verifier" for steps
7-10. So the steps are now:

1. Indie the ISV, identified by a unique SPID (Service Provider ID) requests
   a quote to enclave application
2. Untrusted code requests a quote for the requesting SPID (Indie the ISV)
3. Trusted code produces quote for the given SPID
4. Untrusted code sends the quote to Indie the ISV
5. Indie the ISV, sends the quote to Intel Attestation Service for
   verification, using a secret API key, which is linked to the SPID.
6. Intel verifies the quote and returns its response to Indie the ISV
7a. Indy the ISV, delegates verifications by publishing Intel's response on a
    public bulletin board.
7. Vinnie the Verifier, verifies Intel's response authenticity (check
   signature and certificates)
8. Vinnie the Verifier computes the expected MRENCLAVE by reproducing the
   enclave binary from the trusted source code
9. Vinnie the Verifier verifies that the MRENCLAVE in the report corresponds
   to the "simulated" MRENCLAVE from the trusted source code
10. If the MRENCLAVE matches, Vinnie the Verifier gains trust in the
    REPORT DATA, and proceeds forward with the protocol

It's interesting to note Indy the ISV is not even required and could be
replaced by the host of the enclave application, which is untrusted. Some
works (e.g. DECENT) build on this approach to produce self-attestation
reports.

Re-writing the above steps we get:

0. Untrusted code/host registers itself with IAS to get a secret API key and
   a unique SPID (Service Provider ID)
1. Untrusted code requests a quote for its SPID
2. Trusted code produces quote for the given SPID
3. Untrusted code sends the quote to Intel Attestation Service for
   verification, using its secret API key, which is linked to its SPID.
4. Intel verifies the quote and returns its response to the untrusted code
5. Untrusted code delegates verifications by publishing Intel's response on a
   public bulletin board.
6. Vinnie the Verifier, read Intel's report from the public bulletin board, and
   verifies the report's authenticity (check signature and certificates)
7. Vinnie the Verifier computes the expected MRENCLAVE by reproducing the
   enclave binary from the trusted source code
8. Vinnie the Verifier verifies that the MRENCLAVE in the report corresponds
   to the "simulated" MRENCLAVE from the trusted source code
9. If the MRENCLAVE matches, Vinnie the Verifier gains trust in the
    REPORT DATA, and proceeds forward with the protocol

We now have fewer steps, and as a result, we're now concern with steps 6-9.


## Reproducible Builds
In order to have reproducible builds, we use `nix`.

---

There are three main trust anchors:

* Intel SGX hardware
* Intel Attesation Service
* Enclave Source Code

---
