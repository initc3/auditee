SGX Background
==============
Some brief notes and pointers about Intel SGX.

Measurement
-----------
The MRENCLAVE and MRSIGNER are known as measurements of an enclave. The
MRENCLAVE is also known as the enclave hash and can be used to verify that
an enclave contains the expected code and data. Enclave measurments are done
by SGX enabled processors but can also be simulated with a build toolchain,
and using the SgxSign tool from Intel's linux-sgx.

SIGSTRUCT
---------
From `Intel SGX Explained`_ by Victor Costan and Srinivas Devadas:

.. image:: _static/sigstruct.png



Attestation
-----------
There are 2 types of attestation:

* _local_
* _remote_

Local attestation is when an enclave is attested by another enclave that "sits"
on the same CPU. Remote attestation is when a third party, that does not need
an SGX process requests a quote or report from a remote enclave, and sends that
report to Intel for verification.

In local attestation the verifier can verify the report without communicating with
Intel, whereas in remote attestation the verifier must contact Intel for verifying
the report.

In local attestation, the report contains a MAC tag which can verified by another
enclave that runs on the same CPU, as it has access to the secret key that was used
to create the MAC and which can be used to verify the MAC.

In remote attestation, the enclave being attested generates a local attestation
report which is verified by the Quoting Enclave (provided by Intel). According to
the Intel SGX explained paper, the quoting enclave replaces the MAC of the report with
a signature ... MUST check this in the code. The quoting enclave signs the report
with an attesation key, that it obtains, encrypted, from a provisioning enclave.
**The signature is encrypted.**

Quote
^^^^^

**Structure of a quote:**

.. code-block:: cpp

    typedef struct _quote_t
    {
        uint16_t            version;        /* 0   */
        uint16_t            sign_type;      /* 2   */
        sgx_epid_group_id_t epid_group_id;  /* 4   */
        sgx_isv_svn_t       qe_svn;         /* 8   */
        sgx_isv_svn_t       pce_svn;        /* 10  */
        uint32_t            xeid;           /* 12  */
        sgx_basename_t      basename;       /* 16  */
        sgx_report_body_t   report_body;    /* 48  */
        uint32_t            signature_len;  /* 432 */
        uint8_t             signature[];    /* 436 */
    } sgx_quote_t;


(source: `linux-sgx/common/inc/sgx_quote.h <https://github.com/intel/linux-sgx/blob/bb3d1a5a302511954fcd1b20df4466554e129df1/common/inc/sgx_quote.h#L75-L87>`_)

EPID signature verification
"""""""""""""""""""""""""""
The Quoting Enclave, provided by Intel, is responsible for signing the quote, and
it encrypts the signature:

.. code-block:: cpp

    /* Encrypt the basic signature. */
    se_ret = sgx_aes_gcm128_enc_update(
        (uint8_t *)&basic_sig,   //start address to data before/after encryption
        sizeof(basic_sig),
        (uint8_t *)&encrypted_basic_sig, //length of data
        aes_gcm_state); //pointer to a state

(source `linux-sgx/psw/ae/qe/quoting_enclave.cpp <https://github.com/intel/linux-sgx/blob/bb3d1a5a302511954fcd1b20df4466554e129df1/psw/ae/qe/quoting_enclave.cpp#L536-L541>`_)

**Structure of signature:**

.. code-block:: cpp

    typedef struct _se_encrypted_sign
    {
        se_wrap_key_t       wrap_key;               /* 0 */
        uint8_t             iv[QUOTE_IV_SIZE];      /* 288 */
        uint32_t            payload_size;           /* 300 */
        BasicSignature      basic_sign;             /* 304, this field is encrypted, and contributes to the mac */
        uint32_t            rl_ver;                 /* 656, this field is encrypted, and contributes to the mac */
        uint32_t            rl_num;                 /* 660, this field is encrypted, and contributes to the mac */
        uint8_t             nrp_mac[];              /* 664, this filed contains the encrypted nrps followed by the mac */
    }se_encrypted_sign_t;

(source: `linux-sgx/common/inc/internal/se_quote_internal.h <https://github.com/intel/linux-sgx/blob/bb3d1a5a302511954fcd1b20df4466554e129df1/common/inc/internal/se_quote_internal.h#L50-L60>`_)


.. code-block:: cpp

    /// Intel(R) EPID 2.0 basic signature.
    /*!
     * Basic signature: (B, K, T, c, sx, sf, sa, sb)
     */
    typedef struct BasicSignature {
      G1ElemStr B;   ///< an element in G1
      G1ElemStr K;   ///< an element in G1
      G1ElemStr T;   ///< an element in G1
      FpElemStr c;   ///< an integer between [0, p-1]
      FpElemStr sx;  ///< an integer between [0, p-1]
      FpElemStr sf;  ///< an integer between [0, p-1]
      FpElemStr sa;  ///< an integer between [0, p-1]
      FpElemStr sb;  ///< an integer between [0, p-1]
    } BasicSignature;

source: `linux-sgx/external/epid-sdk/epid/common/types.h <https://github.com/intel/linux-sgx/blob/bb3d1a5a302511954fcd1b20df4466554e129df1/external/epid-sdk/epid/common/types.h#L220-L233>`_


The signature is encrypted, and consequently cannot be verified without Intel.

    Intel is not currently supporting 3rd party attestation verifications
    of EPID signatures for either Linkable or unlinkable.

    -- https://community.intel.com/t5/Intel-Software-Guard-Extensions/Verify-EPID-Signature/m-p/1085984#M706

Also see https://github.com/kudelskisecurity/sgxfun/blob/master/GETQUOTE.md.



.. _intel sgx explained: https://eprint.iacr.org/2016/086
