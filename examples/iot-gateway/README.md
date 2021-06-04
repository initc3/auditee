# sgx-iot example
This example is based on an Intel Code Sample [Gateway Key Provisioning and Secure
Signing using Intel® Software Guard Extensions](https://software.intel.com/content/www/us/en/develop/articles/code-sample-gateway-key-provisioning-and-secure-signing-using-intel-software-guard.html).

> One issue that may arise in IoT scenarios involving sensor data is the trustworthiness
> of the data.  For example, are the sensor readings authentic and integrity-protected?
> One way to provide integrity protection and prove authenticity is to use an IoT
> gateway at the edge to digitally sign the captured data, but then the validity of the
> digital signatures become dependent upon the uniqueness and confidentiality of the
> private key.  This code sample demonstrates the use of Intel® Software Guard
> Extensions (Intel® SGX) to protect the private key of an asymmetric elliptic curve
> keypair used to sign sensor data collected at the edge.

> The baseline implementation of gateway key provisioning and secure signing is built
> with OpenSSL. The `run_demo_openssl.sh` script performs the following actions:
>
> 1. Creates an elliptic curve key pair and saves it to disk.
> 2. Simulates uploading the public key to a cloud.
> 3. Signs some "sensor data."
> 4. Simulates uploading the sensor data and signature to a cloud.
> 5. Simulated cloud verifies the sensor data and detached signature.

The SGX-based original implementation improves the security of the above by generating
the key pair in an enclave and sealing the private key, and storing it on disk. That is:

1. In an SGX enclave: create an elliptic curve key pair, seal the private key and save
   sealed blob to disk.
2. Simulate uploading the public key to a cloud.
3. In an SGX enclave: unseals the private key, and sign some "sensor data."
4. Simulate uploading the sensor data and signature to a cloud.
5. Simulated cloud verifies the sensor data and detached signature.

In step 2 above, how can one be certain that the correct public key is uploaded to the
cloud?

**In this modified example, remote attestation is used to prove that the enclave is
genuine and moreover to prove that the public key comes from the an enclave that was
built from a trusted source code.**

---

### *DRAFT* -- needs review
> The public key is being sealed to prevent that an attacker would swap
> the key with a different one, such that the public key of the attacker
> would end up in the report data of a quote.
> 
> The original implementation writes the public key to a buffer from which
> the key is written to file. The operation is done in "untrusted" mode,
> meaning NOT in an enclave, and consequently it appears that an attacker,
> could modify the content of the buffer and/or file.
> 
> If the above assumption is correct, then a different mechanism is
> required in order to make sure that the public key that will be put into
> the report data of a quote will not have been tampered with, modified or
> changed for a different one.
> 
> By tampering with the public key an attacker could perform two types of
> attacks: 1) impersonation 2) denial of service.
> 
> 1) Impersonation attack: the attacker swaps the public key with its own,
> and signs different data such that it looks like the data is indeed from
> the enclave program when it fact it is not.
> 
> 2) Denial of service attack: the attacker simply corrupts the public key
> such that it is not valid, as it will not match the private key and
> consequently data that is indeed authentic, truly originating from the
> legit enclave, will be recognized as having an invalid signature and
> therefore the enclave will be "denied". Perhaps "denial of service" is
> not an accurate naming. The idea is that an authentic enclave is
> recognized as being invalid, when it actual is valid.

---

## Quickstart
To try, spin up a container from the root of the repository:

```shell
docker-compose run --rm auditee bash
```

Go under the `examples/iot` directory:

```shell
cd examples/iot
```

Start an `ipython` session:

```shell
ipython
```

Verify that the verified remote attestation report contains the "trusted" MRENCLAVE,
which corresponds to the trusted source code. The signed enclave binary  (`.so` file)
may be considered optional, but could also be useful in some cases. For instance, a
developer or service could build the enclave and sign it, meanwhile another service,
before deploying the enclave, would want to verify that it matches the source code,
(and possibly a previous attestation (?)).

```python
import auditee

auditee.verify_mrenclave(
    "sgx-iot/",
    "enclave.signed.so",
    ias_report="ias_report.json",
)
```
