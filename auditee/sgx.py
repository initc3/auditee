"""Wrapper around sgx_sign command. Invokes the command via subprocess."""
import itertools
import functools
import os
import pathlib
import struct
import subprocess
from hashlib import sha256

from .errors import SGXSignError


SGX_SDK = os.environ.get("SGX_SDK", "/opt/sgxsdk")
"""str: Directory where the Linux SGX SDK is installed.

It can be set via the environment variable ``SGX_SDK``.
Defaults to :file:`/opt/sgxsdk`.
"""

SGX_SIGN_CMD = str(pathlib.Path(SGX_SDK).joinpath("bin/x64/sgx_sign"))
"""str: Location of the ``sgx_sign`` tool.

Defaults to :file:`/opt/sgxsdk/bin/x64/sgx_sign`.
"""


def _sgx_sign(
    cmd,
    *,
    enclave,
    # key=None,
    # config=None,
    # out=None,
    # sig=None,
    # unsigned=None,
    # dumpfile=None,
    # cssfile=None,
    ignore_rel_error=False,
    ignore_init_sec_error=False,
    **opts,
):
    """Wrapper around the SGX signing tool.

Usage: sgx_sign <commands> [options] file...
Commands:
   sign                    Sign the enclave using the private key
   gendata                 Generate enclave signing material to be signed
   catsig                  Generate the signed enclave with the input signature file, the
                           public key and the enclave signing material
   dump                    Dump metadata information for a signed enclave file
Options:
   -enclave                Specify the enclave file to be signed or already signed
                           It is a required option for the four commands
   -key                    Specify the key file
                           It is a required option for "sign" and "catsig"
   -config                 Specify the configuration for the enclave
   -out                    Specify the output file
                           It is a required option for "sign", "gendata" and "catsig"
   -sig                    Specify the signature file for the enclave signing material
                           It is a required option for "catsig"
   -unsigned               Specify the enclave signing material generated by "gendata"
                           It is a required option for "catsig"
   -dumpfile               Specify a file to dump metadata information (text format)
                           It is a required option for "dump"
   -cssfile                Specify a file to dump the enclave SIGSTRUCT information (binary format)
   -ignore-rel-error       By default, sgx_sign provides an error for enclaves with
                           text relocations. You can ignore the error and continue signing
                           by providing this option. But it is recommended you eliminate the
                           text relocations instead of bypassing the error with this option.
   -ignore-init-sec-error  By default, sgx_sign provides an error for enclaves with .init section.
                           You can ignore the error and continue signing by providing this option.
                           But it is recommended you eliminate the section instead of bypassing
                           the error with this option.
   -resign                 By default, sgx_sign reports an error if an input enclave has already been signed.
                           You can force sgx_sign to resign the enclave by providing this option.

Run "sgx_sign -help" to get this help and exit.
Run "sgx_sign -version" to output version information and exit.
"""  # noqa
    # popenargs = [SGX_SIGN_CMD, cmd] + list(
    #    itertools.chain.from_iterable(list(opts.items()))
    # )
    popenargs = [SGX_SIGN_CMD, cmd, "-enclave", enclave]
    # if key is not None:
    #    popenargs += ['-key', key]
    popenargs += list(
        itertools.chain.from_iterable((f"-{opt}", value) for opt, value in opts.items())
    )
    if ignore_rel_error:
        popenargs.append("-ignore-rel-error")
    if ignore_init_sec_error:
        popenargs.append("-ignore-init-sec-error")

    return subprocess.run(popenargs).returncode


"""Dump metadata information for a signed enclave file"""
_dump = functools.partial(_sgx_sign, cmd="dump")


"""Sign the enclave using the private key"""
_sign = functools.partial(_sgx_sign, cmd="sign")

"""
   gendata                 Generate enclave signing material to be signed
   catsig                  Generate the signed enclave with the input signature file, the
                           public key and the enclave signing material
"""


def dump_enclave_sigstruct(enclave, cssfile):
    """Dump the enclave SIGSTRUCT to file."""
    _dump(enclave=enclave, cssfile=cssfile, dumpfile="/dev/null")


def sign(enclave, *, key, out, config):
    """
    Sign the given enclave with the given key.

    This function invokes the Linux SGX SDK ``sgx_sign`` tool, using
    Python's :py:mod:`subprocess` module.

    .. attention:: The SGX SDK must be installed on the system where
        this function is invoked.

        The path to the ``sgx_sign`` tool can be set via the
        environment variable :attr:`~.SGX_SDK`. It defaults to
        :file:`/opt/sgxsdk/bin/x64/sgx_sign`.

    Parameters
    ----------
    enclave: str
        Local file path to the unsigned enclave binary.
    key: str
        Local file path to a signing key with which to sign the enclave.
    out: str
        Local file path where the signed enclave should be written to.
    config: str
        Local file path to the enclave configuration file.

    Raises
    ------
    :py:exc:`~.errors.SGXSignError`:
        If something wrong happen when invoking the ``sgx_sign`` tool.

    Returns
    -------
    bytes:
        Signed enclave bytes.

    Examples
    --------
    .. code-block:: python

        from auditee import sgx
        sgx.sign('enclv.so', key='key.pem', out='enclv.sig.so', config='config.xml')

    The above is equivalent to invoking the ``sgx_sign`` tool in a shell:

    .. code-block:: shell

        $ sgx_sign sign -enclave enclv.so -key key.pem -out enclv.sig.so -config config.xml
    """
    # FIXME if the returncode is not zero, try getting more informaton about the error
    returncode = _sign(enclave=enclave, key=key, out=out, config=config)
    if returncode != 0:
        raise SGXSignError(
            f"sgx_sign failed for enclave file: {enclave}, key: {key}, out: {out}, config: {config}"
        )
    # FIXME handle errors in the above call, rather than proceeding forward despite
    # errors -- for instance, errors in signing can result in no file being written
    # to 'out' thus causing the following open() instruction to fail.
    with open(out, "rb") as f:
        signed_enclave_bytes = f.read()
    return signed_enclave_bytes


def get_enclave_sigstruct(enclave, cssfile="/tmp/sigstruct"):
    dump_enclave_sigstruct(enclave, cssfile)
    with open(cssfile, "rb") as f:
        sigstruct_bytes = f.read()
    return sigstruct_bytes


def get_mrenclave(enclave, cssfile="/tmp/sigstruct"):
    sigstruct = get_enclave_sigstruct(enclave, cssfile=cssfile)
    return bytes(unpack_mrenclave(sigstruct))


def get_mrsigner(enclave, cssfile="/tmp/sigstruct"):
    sigstruct = get_enclave_sigstruct(enclave, cssfile=cssfile)
    return sha256(unpack_key_modulus(sigstruct)).digest()


"""Functions to unpack data from an Enclave Signature Structure also
known as SIGSTRUCT.

For now using ``struct``, but some work is currently being done to use cffi
to bind to the C structs.

See https://github.com/intel/linux-sgx/blob/bb3d1a5a302511954fcd1b20df4466554e129df1/common/inc/internal/arch.h#L198-L252

.. code-block:: c

    /****************************************************************************
    * Definitions for enclave signature
    ****************************************************************************/
    #define SE_KEY_SIZE         384         /* in bytes */
    #define SE_EXPONENT_SIZE    4           /* RSA public key exponent size in bytes */
    
    typedef struct _css_header_t {        /* 128 bytes */
        uint8_t  header[12];                /* (0) must be (06000000E100000000000100H) */
        uint32_t type;                      /* (12) bit 31: 0 = prod, 1 = debug; Bit 30-0: Must be zero */
        uint32_t module_vendor;             /* (16) Intel=0x8086, ISV=0x0000 */
        uint32_t date;                      /* (20) build date as yyyymmdd */
        uint8_t  header2[16];               /* (24) must be (01010000600000006000000001000000H) */
        uint32_t hw_version;                /* (40) For Launch Enclaves: HWVERSION != 0. Others, HWVERSION = 0 */
        uint8_t  reserved[84];              /* (44) Must be 0 */
    } css_header_t;
    se_static_assert(sizeof(css_header_t) == 128);
    
    
    typedef struct _css_key_t {           /* 772 bytes */
        uint8_t modulus[SE_KEY_SIZE];       /* (128) Module Public Key (keylength=3072 bits) */
        uint8_t exponent[SE_EXPONENT_SIZE]; /* (512) RSA Exponent = 3 */
        uint8_t signature[SE_KEY_SIZE];     /* (516) Signature over Header and Body */
    } css_key_t;
    se_static_assert(sizeof(css_key_t) == 772);
    
    
    typedef struct _css_body_t {             /* 128 bytes */
        sgx_misc_select_t    misc_select;    /* (900) The MISCSELECT that must be set */
        sgx_misc_select_t    misc_mask;      /* (904) Mask of MISCSELECT to enforce */
        uint8_t              reserved[4];    /* (908) Reserved. Must be 0. */
        sgx_isvfamily_id_t   isv_family_id;  /* (912) ISV assigned Family ID */
        sgx_attributes_t     attributes;     /* (928) Enclave Attributes that must be set */
        sgx_attributes_t     attribute_mask; /* (944) Mask of Attributes to Enforce */
        sgx_measurement_t    enclave_hash;   /* (960) MRENCLAVE - (32 bytes) */
        uint8_t              reserved2[16];  /* (992) Must be 0 */
        sgx_isvext_prod_id_t isvext_prod_id; /* (1008) ISV assigned Extended Product ID */
        uint16_t             isv_prod_id;    /* (1024) ISV assigned Product ID */
        uint16_t             isv_svn;        /* (1026) ISV assigned SVN */
    } css_body_t;
    se_static_assert(sizeof(css_body_t) == 128);
    
    
    typedef struct _css_buffer_t {         /* 780 bytes */
        uint8_t  reserved[12];              /* (1028) Must be 0 */
        uint8_t  q1[SE_KEY_SIZE];           /* (1040) Q1 value for RSA Signature Verification */
        uint8_t  q2[SE_KEY_SIZE];           /* (1424) Q2 value for RSA Signature Verification */
    } css_buffer_t;
    se_static_assert(sizeof(css_buffer_t) == 780);
    
    
    typedef struct _enclave_css_t {        /* 1808 bytes */
        css_header_t    header;             /* (0) */
        css_key_t       key;                /* (128) */
        css_body_t      body;               /* (900) */
        css_buffer_t    buffer;             /* (1028) */
    } enclave_css_t;
    
    
    se_static_assert(sizeof(enclave_css_t) == 1808);
"""  # noqa

MODULUS_OFFSET = 128
MODULUS_SIZE = 384
ENCLAVEHASH_OFFSET = 960
ENCLAVEHASH_SIZE = 32
isvprodid_OFFSET = 1024

"""
typedef struct _css_header_t {        /* 128 bytes */
    uint8_t  header[12];                /* (0) must be (06000000E100000000000100H) */
    uint32_t type;                      /* (12) bit 31: 0 = prod, 1 = debug; Bit 30-0: Must be zero */
    uint32_t module_vendor;             /* (16) Intel=0x8086, ISV=0x0000 */
    uint32_t date;                      /* (20) build date as yyyymmdd */
    uint8_t  header2[16];               /* (24) must be (01010000600000006000000001000000H) */
    uint32_t hw_version;                /* (40) For Launch Enclaves: HWVERSION != 0. Others, HWVERSION = 0 */
    uint8_t  reserved[84];              /* (44) Must be 0 */
} css_header_t;
se_static_assert(sizeof(css_header_t) == 128);
"""  # noqa E501
CSS_HEADER_FORMAT = "12BIII16BI84B"

"""
typedef struct _css_key_t {           /* 772 bytes */
    uint8_t modulus[SE_KEY_SIZE];       /* (128) Module Public Key (keylength=3072 bits) */
    uint8_t exponent[SE_EXPONENT_SIZE]; /* (512) RSA Exponent = 3 */
    uint8_t signature[SE_KEY_SIZE];     /* (516) Signature over Header and Body */
} css_key_t;
se_static_assert(sizeof(css_key_t) == 772);
"""  # noqa E501
SE_KEY_SIZE = 384  # in bytes */
SE_EXPONENT_SIZE = 4  # RSA public key exponent size in bytes
CSS_KEY_FORMAT = f"{SE_KEY_SIZE}B{SE_EXPONENT_SIZE}B{SE_KEY_SIZE}B"

"""
common/inc/sgx_attributes.h
---------------------------
typedef struct _attributes_t
{
    uint64_t      flags;
    uint64_t      xfrm;
} sgx_attributes_t;

/* define MISCSELECT - all bits are currently reserved */
typedef uint32_t    sgx_misc_select_t;


common/inc/sgx_report.h
-----------------------
#define SGX_HASH_SIZE        32              /* SHA256 */
#define SGX_MAC_SIZE         16              /* Message Authentication Code - 16 bytes */

#define SGX_REPORT_DATA_SIZE    64

#define SGX_ISVEXT_PROD_ID_SIZE 16
#define SGX_ISV_FAMILY_ID_SIZE  16

typedef struct _sgx_measurement_t
{
    uint8_t                 m[SGX_HASH_SIZE];
} sgx_measurement_t;

typedef uint8_t             sgx_mac_t[SGX_MAC_SIZE];

typedef struct _sgx_report_data_t
{
    uint8_t                 d[SGX_REPORT_DATA_SIZE];
} sgx_report_data_t;

typedef uint16_t            sgx_prod_id_t;

typedef uint8_t sgx_isvext_prod_id_t[SGX_ISVEXT_PROD_ID_SIZE];
typedef uint8_t sgx_isvfamily_id_t[SGX_ISV_FAMILY_ID_SIZE];

common/inc/internal/arch.h
--------------------------
typedef struct _css_body_t {             /* 128 bytes */
    sgx_misc_select_t    misc_select;    /* (900) The MISCSELECT that must be set */
    sgx_misc_select_t    misc_mask;      /* (904) Mask of MISCSELECT to enforce */
    uint8_t              reserved[4];    /* (908) Reserved. Must be 0. */
    sgx_isvfamily_id_t   isv_family_id;  /* (912) ISV assigned Family ID */
    sgx_attributes_t     attributes;     /* (928) Enclave Attributes that must be set */
    sgx_attributes_t     attribute_mask; /* (944) Mask of Attributes to Enforce */
    sgx_measurement_t    enclave_hash;   /* (960) MRENCLAVE - (32 bytes) */
    uint8_t              reserved2[16];  /* (992) Must be 0 */
    sgx_isvext_prod_id_t isvext_prod_id; /* (1008) ISV assigned Extended Product ID */
    uint16_t             isv_prod_id;    /* (1024) ISV assigned Product ID */
    uint16_t             isv_svn;        /* (1026) ISV assigned SVN */
} css_body_t;
se_static_assert(sizeof(css_body_t) == 128);
"""  # noqa E501
SGX_HASH_SIZE = 32  # SHA256
SGX_MAC_SIZE = 16  # Message Authentication Code - 16 bytes
SGX_REPORT_DATA_SIZE = 64
SGX_ISVEXT_PROD_ID_SIZE = 16
SGX_ISV_FAMILY_ID_SIZE = 16
CSS_BODY_FORMAT = (
    f"II4B{SGX_ISV_FAMILY_ID_SIZE}BQQQQ"
    f"{SGX_HASH_SIZE}B16B{SGX_ISVEXT_PROD_ID_SIZE}BHH"
)


def read_sigstruct(cssfile):
    with open(cssfile, "rb") as f:
        sigstruct = f.read()
    return sigstruct


def unpack_key_modulus(sigstruct):
    fmt = f"<{MODULUS_SIZE}s"
    return struct.unpack_from(fmt, sigstruct, MODULUS_OFFSET)[0]


def unpack_mrenclave(sigstruct):
    fmt = f"<{ENCLAVEHASH_SIZE}B"
    return struct.unpack_from(fmt, sigstruct, ENCLAVEHASH_OFFSET)


def unpack_isvprodid(sigstruct):
    """
    1024 2 ISV assigned Product ID. Y
    """
    offset = 1024
    fmt = "<H"
    return struct.unpack_from(fmt, sigstruct, offset)[0]


def unpack_isvsvn(sigstruct):
    """
    ISVSVN 1026 2 ISV assigned SVN (security version number). Y
    """
    offset = 1026
    fmt = "<H"
    return struct.unpack_from(fmt, sigstruct, offset)[0]


def unpack_sigstruct(sigstruct):
    """
    """  # noqa

    raise NotImplementedError


class Sigstruct:
    def __init__(self, sigstruct_bytes):
        self.mrsigner = sha256(unpack_key_modulus(sigstruct_bytes)).digest()
        self.mrenclave = bytes(unpack_mrenclave(sigstruct_bytes))
        self.isvprodid = unpack_isvprodid(sigstruct_bytes)
        self.isvsvn = unpack_isvsvn(sigstruct_bytes)

    @classmethod
    def from_file(cls, cssfile):
        with open(cssfile, "rb") as f:
            sigstruct = f.read()
        return cls(sigstruct)

    @classmethod
    def from_enclave_file(cls, enclave_file):
        sigstruct = get_enclave_sigstruct(enclave_file)
        return cls(sigstruct)

    def cmp(self, other):
        return {
            attr: getattr(self, attr) == getattr(other, attr)
            for attr in ("mrenclave", "mrsigner", "isvprodid", "isvsvn")
        }
