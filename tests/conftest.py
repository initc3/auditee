from base64 import urlsafe_b64decode
from collections import namedtuple
from typing import NamedTuple

from pytest import fixture

Sigstruct = namedtuple("Sigstruct", ("mrenclave", "mrsigner", "isvprodid", "isvsvn"))


@fixture
def enclave_path():
    # sha256: 1c2358bc52faabbac48fa4b32063885e1b16528b85b7dd75f9c3d734f1d345d8
    return "tests/vectors/Enclave.so"


@fixture
def signed_enclave_path():
    # sha256: 2fcb14082387781de3efc89cd8ada6c2f992621d9f353cdba90b8adde04edfc7
    return "tests/vectors/Enclave.signed.so"


@fixture
def cssfile_path():
    # sha256: 59a059bdd20855c8e9735ba08944762704b3a3afaeb5ec8a0d6b268eaca87f94
    return "tests/vectors/sigstruct"


@fixture
def cssfile_sha256(cssfile_path):
    return "59a059bdd20855c8e9735ba08944762704b3a3afaeb5ec8a0d6b268eaca87f94"


@fixture
def enclave_config_path():
    return "tests/vectors/Enclave.config.xml"


@fixture
def developer_sk_path():
    return "tests/vectors/developer_private.pem"


@fixture
def auditor_sk_path():
    return "tests/vectors/auditor_private.pem"


@fixture
def signed_enclave_bytes(signed_enclave_path):
    with open(signed_enclave_path, "rb") as signed_enclave_file:
        signed_enclave_bytes = signed_enclave_file.read()
    return signed_enclave_bytes


@fixture
def sigstruct():
    return Sigstruct(
        mrenclave="f19de84787f1a90ad7bc2d4c2fd952e05545c6f177e8b10b112a4cef31ba0454",
        mrsigner="bd71c6380ef77c5417e8b2d1ce2d4b6504b9f418e5049342440cfff2443d95bd",
        isvprodid=0,
        isvsvn=1,
    )


@fixture
def sgx_quote_b64():
    return (
        "AgAAAFsLAAALAAoAAAAAAFOrdeScwC/lZP1RWReIG+j6/9b5LyockGPA3CDEaPS4CRH//wECAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAPGd6EeH"
        "8akK17wtTC/ZUuBVRcbxd+ixCxEqTO8xugRUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "C9ccY4Dvd8VBfostHOLUtlBLn0GOUEk0JEDP/yRD2VvQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAXwbIdunJY1ls6p2iE5AErVjJKZgOjzGdnECRcreQTIQAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAIAAAIY8V1JQNljITe3UZMiAQPH3wF4MdEe+ZAUH99jGXs8"
        "5/YG+iK+3oAiV9v7gxgdhJx2o7wYN3tj8Vfri6ypn/0ahpLgOHlQJN3/ZlrLBwtpFcfAE903qkzc0h"
        "I2CUa59xlvpFgplhEC94epLkpg+5rlb2I4VTahwE+4+7xlUI6wEFI8VugKBfgu/DYrCuOkhectlhDI"
        "ao5g+HbxwhTJ1y1dk0qangF81P6Ztweb3uVdenpn6NZ4s7kt3JxRadrOa+M7aUWNRTli6cRxgRw4dg"
        "i17NZr6IUrLoVY4w5eBADv6g8qICTpSuGNoPmnKbKEqq4/DSdTDcgM1s8a9TT6hl53NRi934iz0Rwc"
        "TD6LYrYF+F0c0YciUErK0S8/9/uoKHdXtYO0LWpLF/RTX2gBAABCbKrLStn7XA63GbNEoG90fApLRD"
        "ICmm/F1B6/b0xR2yeuFhqEfrZdXs4poGVuLbkESBmBpKBFuw24Su6WO/hRz8dCZEBg8F03i4nMtuNr"
        "359DKCHN8fVRGxV8MIbxrs3DJYiDTKaTjXPU1jyO90MlLn7cuvZ6Hc6P/rp94X0i3kRbKXKUgPNZC5"
        "0FZz0x05xEtvWYM3uQs964MRfP/ScAvssixyVHP2VSQL8nDyup012OHhSqKoSRkkR0uYktkRBW0nbb"
        "wJPtZZiNPSXUq7BmfSOi0dohIpecPKKUppq+Vbvp9kz4WTCQ3y1vwbbpfOcK+qEk2oxzQIMQVPKVMG"
        "j2Z4MZ33aPo9Nz4wEEJR4xhjUWuFCNcmWNTeMpLs6NewAXAi5sjGM6qNToJaHXSSQ4PXu66mqCCDpU"
        "MmdbJvvKvSviXCAUec8tjyL3VpF6gkNKRW94uouEPLgLbXgO8IKCssJuv6DskPsPzTwhM2Iowk1NOt"
        "bAksbb"
    )


def sgx_quote_bytes(sgx_quote_b64):
    return urlsafe_b64decode(sgx_quote_b64)


class SGXAttributes(NamedTuple):
    flags: int
    xfrm: int


class SGXReport(NamedTuple):
    """
    typedef struct _report_body_t
    {
        sgx_cpu_svn_t           cpu_svn;        /* (  0) Security Version of the CPU */
        sgx_misc_select_t       misc_select;    /* ( 16) Which fields defined in SSA.MISC */
        uint8_t                 reserved1[SGX_REPORT_BODY_RESERVED1_BYTES];  /* ( 20) */
        sgx_isvext_prod_id_t    isv_ext_prod_id;/* ( 32) ISV assigned Extended Product ID */
        sgx_attributes_t        attributes;     /* ( 48) Any special Capabilities the Enclave possess */
        sgx_measurement_t       mr_enclave;     /* ( 64) The value of the enclave's ENCLAVE measurement */
        uint8_t                 reserved2[SGX_REPORT_BODY_RESERVED2_BYTES];  /* ( 96) */
        sgx_measurement_t       mr_signer;      /* (128) The value of the enclave's SIGNER measurement */
        uint8_t                 reserved3[SGX_REPORT_BODY_RESERVED3_BYTES];  /* (160) */
        sgx_config_id_t         config_id;      /* (192) CONFIGID */
        sgx_prod_id_t           isv_prod_id;    /* (256) Product ID of the Enclave */
        sgx_isv_svn_t           isv_svn;        /* (258) Security Version of the Enclave */
        sgx_config_svn_t        config_svn;     /* (260) CONFIGSVN */
        uint8_t                 reserved4[SGX_REPORT_BODY_RESERVED4_BYTES];  /* (262) */
        sgx_isvfamily_id_t      isv_family_id;  /* (304) ISV assigned Family ID */
        sgx_report_data_t       report_data;    /* (320) Data provided by the user */
    } sgx_report_body_t;
    """  # noqa

    # bytes(sgx_quote_t.report_body.cpu_svn.svn).hex()
    cpu_svn: bytes
    misc_select: int
    reserved1: bytes
    isv_ext_prod_id: bytes
    attributes: SGXAttributes
    mr_enclave: bytes
    reserved2: bytes
    mr_signer: bytes
    reserved3: bytes
    config_id: bytes
    isv_prod_id: int
    isv_svn: int
    config_svn: int
    reserved4: bytes
    isv_family_id: bytes
    report_data: bytes

    def from_dict(cls, data):
        """
        "cpu_svn": "0911ffff010200000000000000000000",
        "misc_select": "00000000",
        "attributes": {"flags": "0700000000000000", "xfrm": "0700000000000000"},
        "mr_enclave": "f19de84787f1a90ad7bc2d4c2fd952e05545c6f177e8b10b112a4cef31ba0454",
        "mr_signer": "bd71c6380ef77c5417e8b2d1ce2d4b6504b9f418e5049342440cfff2443d95bd",
        "isv_prod_id": "0000",
        "isv_svn": "0100",
        "report_data": "17c1b21dba7258d65b3aa76884e4012b56324a6603a3cc676710245cade413210000000000000000000000000000000000000000000000000000000000000000",
        """


class SGXQuote(NamedTuple):
    """
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
    """

    version: int  # uint16_t (in C struct)
    sign_type: int  # uint16_t (in C struct)
    epid_group_id: str  # sgx_epid_group_id_t
    # int.to_bytes(sgx_quote_t.qe_svn, length=2, byteorder='little').hex()
    qe_svn: int  # sgx_isv_svn_t (in C struct)
    # int.to_bytes(sgx_quote_t.pce_svn, length=2, byteorder='little').hex()
    pce_svn: int  # sgx_isv_svn_t (in C struct)
    # int.to_bytes(sgx_quote_t.xeid, length=4, byteorder='little').hex()
    xeid: int  # uint32_t (in C struct)
    # bytes(sgx_quote_t.basename.name).hex()
    basename: str  # sgx_basename_t (in C struct)
    report_body: SGXReport  # sgx_report_body_t (in C struct)
    # int.to_bytes(sgx_quote_t.signature_len, length=4, byteorder='little').hex()
    signature_len: int  # uint32_t (in C struct)
    signature: str  # uint8_t[]

    @classmethod
    def from_dict(cls, data):
        """ """


@fixture
def sgx_report_body():
    """
    ---- Enclave Report Details ------------------------------------------------
    cpu_svn     = 0911ffff010200000000000000000000
    misc_select = 00000000
    attributes  = 07000000000000000700000000000000
    mr_enclave  = f19de84787f1a90ad7bc2d4c2fd952e05545c6f177e8b10b112a4cef31ba0454
    mr_signer   = bd71c6380ef77c5417e8b2d1ce2d4b6504b9f418e5049342440cfff2443d95bd
    isv_prod_id = 0000
    isv_svn     = 0001
    report_data = 17c1b21dba7258d65b3aa76884e4012b56324a6603a3cc676710245cade413210000000000000000000000000000000000000000000000000000000000000000
    """
    return {
        "cpu_svn": "0911ffff010200000000000000000000",
        "misc_select": "00000000",
        "attributes": {"flags": "0700000000000000", "xfrm": "0700000000000000"},
        "mr_enclave": "f19de84787f1a90ad7bc2d4c2fd952e05545c6f177e8b10b112a4cef31ba0454",
        "mr_signer": "bd71c6380ef77c5417e8b2d1ce2d4b6504b9f418e5049342440cfff2443d95bd",
        "isv_prod_id": "0000",
        "isv_svn": "0001",
        "report_data": "17c1b21dba7258d65b3aa76884e4012b56324a6603a3cc676710245cade413210000000000000000000000000000000000000000000000000000000000000000",
    }


@fixture
def sgx_quote_0_dict(sgx_quote_b64, sgx_report_body):
    return {
        "base64": sgx_quote_b64,
        "version": 2,
        "sign_type": 0,
        "epid_group_id": "5b0b0000",
        # "qe_svn": "0b00",
        "qe_svn": 11,
        # "pce_svn": "0a00",
        "pce_svn": 10,
        # "xeid": "00000000",
        "xeid": 0,
        "basename": "53ab75e49cc02fe564fd515917881be8faffd6f92f2a1c9063c0dc20c468f4b8",
        # "report_body": sgx_report_body,
        "report_body": {
            "cpu_svn": "0911ffff010200000000000000000000",
            "misc_select": 0,
            "attributes": {"flags": 7, "xfrm": 7},
            "mr_enclave": "f19de84787f1a90ad7bc2d4c2fd952e05545c6f177e8b10b112a4cef31ba0454",
            "mr_signer": "bd71c6380ef77c5417e8b2d1ce2d4b6504b9f418e5049342440cfff2443d95bd",
            "isv_prod_id": "0000",
            "isv_svn": "0100",
            "report_data": "17c1b21dba7258d65b3aa76884e4012b56324a6603a3cc676710245cade413210000000000000000000000000000000000000000000000000000000000000000",
        },
        "signature_len": 680,
        "signature": "0218f15d4940d9632137b75193220103c7df017831d11ef990141fdf63197b3ce7f606fa22bede802257dbfb83181d849c76a3bc18377b63f157eb8baca99ffd1a8692e038795024ddff665acb070b6915c7c013dd37aa4cdcd212360946b9f7196fa45829961102f787a92e4a60fb9ae56f62385536a1c04fb8fbbc65508eb010523c56e80a05f82efc362b0ae3a485e72d9610c86a8e60f876f1c214c9d72d5d934a9a9e017cd4fe99b7079bdee55d7a7a67e8d678b3b92ddc9c5169dace6be33b69458d453962e9c471811c387608b5ecd66be8852b2e8558e30e5e0400efea0f2a2024e94ae18da0f9a729b284aaae3f0d27530dc80cd6cf1af534fa865e773518bddf88b3d11c1c4c3e8b62b605f85d1cd18722504acad12f3ff7fba8287757b583b42d6a4b17f4535f68010000426caacb4ad9fb5c0eb719b344a06f747c0a4b4432029a6fc5d41ebf6f4c51db27ae161a847eb65d5ece29a0656e2db904481981a4a045bb0db84aee963bf851cfc742644060f05d378b89ccb6e36bdf9f432821cdf1f5511b157c3086f1aecdc32588834ca6938d73d4d63c8ef743252e7edcbaf67a1dce8ffeba7de17d22de445b29729480f3590b9d05673d31d39c44b6f598337b90b3deb83117cffd2700becb22c725473f655240bf270f2ba9d35d8e1e14aa2a8491924474b9892d911056d276dbc093ed65988d3d25d4abb0667d23a2d1da2122979c3ca294a69abe55bbe9f64cf8593090df2d6fc1b6e97ce70afaa124da8c7340831054f2953068f6678319df768fa3d373e30104251e31863516b8508d72658d4de3292ece8d7b0017022e6c8c633aa8d4e825a1d74924383d7bbaea6a82083a5432675b26fbcabd2be25c201479cf2d8f22f756917a82434a456f78ba8b843cb80b6d780ef08282b2c26ebfa0ec90fb0fcd3c21336228c24d4d3ad6c092c6db",
    }


@fixture
def sgx_quote_0(sgx_quote_0_dict):
    return SGXQuote.from_dict(sgx_report_body)


# report_body   = 0911ffff010200000000000000000000000000000000000000000000000000000000000000000000000000000000000007000000000000000700000000000000f19de84787f1a90ad7bc2d4c2fd952e05545c6f17e8b10b112a4cef31ba04540000000000000000000000000000000000000000000000000000000000000000bd71c6380ef77c5417e8b2d1ce2d4b6504b9f418e5049342440cfff2443d95bd00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000017c1b21dba7258d65b3aa76884e4012b56324a6603a3cc676710245cade413210000000000000000000000000000000000000000000000000000000000000000
# signature_len = a8020000
# signature     = 0218f15d4940d9632137b75193220103c7df017831d11ef990141fdf63197b3ce7f606fa22bede802257dbfb83181d849c76a3bc18377b63f157eb8baca99ffd1a8692e038795024ddff665acb070b6915c7c013d37aa4cdcd212360946b9f7196fa45829961102f787a92e4a60fb9ae56f62385536a1c04fb8fbbc65508eb010523c56e80a05f82efc362b0ae3a485e72d9610c86a8e60f876f1c214c9d72d5d934a9a9e017cd4fe99b7079bdee55d7a7a67e8d678b3b92ddc9c5169dac6be33b69458d453962e9c471811c387608b5ecd66be8852b2e8558e30e5e0400efea0f2a2024e94ae18da0f9a729b284aaae3f0d27530dc80cd6cf1af534fa865e773518bddf88b3d11c1c4c3e8b62b605f85d1cd18722504acad12f3ff7fba8287757b583b42d6a4b1f4535f68010000426caacb4ad9fb5c0eb719b344a06f747c0a4b4432029a6fc5d41ebf6f4c51db27ae161a847eb65d5ece29a0656e2db904481981a4a045bb0db84aee963bf851cfc742644060f05d378b89ccb6e36bdf9f432821cdf1f5511b157c3086f1aecdc3258834ca6938d73d4d63c8ef743252e7edcbaf67a1dce8ffeba7de17d22de445b29729480f3590b9d05673d31d39c44b6f598337b90b3deb83117cffd2700becb22c725473f655240bf270f2ba9d35d8e1e14aa2a8491924474b9892d911056d276dbc093ed65988d3d25dabb0667d23a2d1da2122979c3ca294a69abe55bbe9f64cf8593090df2d6fc1b6e97ce70afaa124da8c7340831054f2953068f6678319df768fa3d373e30104251e31863516b8508d72658d4de3292ece8d7b0017022e6c8c633aa8d4e825a1d74924383d7bbaea6a8203a5432675b26fbcabd2be25c201479cf2d8f22f756917a82434a456f78ba8b843cb80b6d780ef08282b2c26ebfa0ec90fb0fcd3c21336228c24d4d3ad6c092c6db
