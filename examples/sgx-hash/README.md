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

Start an ipython session in a container, under the `sgx-hash` example directory:

```shell
docker-compose run --rm --workdir /usr/src/examples/sgx-hash auditee ipython
```

Verify the "trustworthiness" of the REPORT DATA in a remote attestion report
(`ias-report.json`) that claims to be for a signed enclave (`Enclave.signed.so`)
and some source code (`sgx-quote-sample`):

```python
import auditee

auditee.verify_mrenclave('sgx-quote-sample/', 'Enclave.signed.so', ias_report='ias-report.json')
```

This should output something similar to the following at the end:

```python
# ...

Reproducibility Report
----------------------
- Signed enclave NMRENCLAVE:                    901c3b2c92fd8c08654bae68d858f59c81a6121f81e8998cbf9daf236e2ead74
- Built-from-source enclave NMRENCLAVE:         901c3b2c92fd8c08654bae68d858f59c81a6121f81e8998cbf9daf236e2ead74
- IAS report NMRENCLAVE:                        901c3b2c92fd8c08654bae68d858f59c81a6121f81e8998cbf9daf236e2ead74

MRENCLAVES match!

Report data
-----------
7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d90690000000000000000000000000000000000000000000000000000000000000000

True
```

Now, you can check the report data for yourself. It's supposed to be the SHA 256 of
the string 'Hello World!'. You can inspect (audit) the
[SGX enclave code](https://github.com/sbellem/sgx-quote-sample/blob/c950a0e1f89b346c3efb27d2cc41eb4327328adc/Enclave/Enclave.cpp#L140-L146) yourself to verify this:


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
