"""Functions to unpack data from an Enclave Signature Structure also
known as SIGSTRUCT.

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
import pathlib
from hashlib import sha256

from cffi import FFI

ffi = FFI()

header_filepath = pathlib.Path(__file__).parent.resolve().joinpath("arch.h")

with open(header_filepath) as f:
    ffi.cdef(f.read())


def _unpack_sigstruct_from_bytes(sigstruct_bytes):
    """ """


def _unpack_sigstruct_from_file(sigstruct_file):
    """ """
    enclave_css = ffi.new("enclave_css_t *")

    with open(sigstruct_file, "rb") as f:
        f.readinto(ffi.buffer(enclave_css))

    return enclave_css


def _mrsigner(enclave_css):
    return sha256(enclave_css.key.modulus).digest()


class _SigStruct:
    def __init__(self, cdata_enclave_css_t):
        self.enclave_css = cdata_enclave_css_t
        self.mrsigner = sha256(bytes(cdata_enclave_css_t.key.modulus)).digest()
        self.mrenclave = bytes(cdata_enclave_css_t.body.enclave_hash.m)

    @classmethod
    def from_file(cls, cssfile):
        enclave_css = _unpack_sigstruct_from_file(cssfile)
        return cls(enclave_css)
