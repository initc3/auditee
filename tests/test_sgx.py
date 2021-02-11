import filecmp
import subprocess
from hashlib import sha256

from pytest import mark

# MODULUS_OFFSET = 128
# MODULUS_SIZE = 384
# ENCLAVEHASH_OFFSET = 960
# ENCLAVEHASH_SIZE = 32


def test_dump_enclave_sigstruct(
    signed_enclave_path, cssfile_path, cssfile_sha256, tmp_path
):
    from auditee.sgx import dump_enclave_sigstruct

    sigstruct_path = tmp_path / "sigstruct"
    dump_enclave_sigstruct(signed_enclave_path, str(sigstruct_path))
    assert filecmp.cmp(cssfile_path, sigstruct_path)
    with open(sigstruct_path, "rb") as f:
        sigstruct_bytes = f.read()
    assert cssfile_sha256 == sha256(sigstruct_bytes).hexdigest()


def test_sign_enclave(
    enclave_path, enclave_config_path, developer_sk_path, tmp_path, sigstruct,
):
    from auditee.sgx import sign, SGX_SIGN_CMD

    out = tmp_path / "Enclave.signed.so"
    sign(
        enclave=enclave_path,
        key=developer_sk_path,
        out=out,
        config=enclave_config_path,
    )
    # dump the sigstruct of the enclave to file
    sigstruct_path = tmp_path / "sigstruct"
    subprocess.run(
        [
            SGX_SIGN_CMD,
            "dump",
            "-enclave",
            out,
            "-dumpfile",
            "/dev/null",
            "-cssfile",
            sigstruct_path,
        ]
    )

    # read the sigstruct file
    with open(sigstruct_path, "rb") as f:
        sigstruct_bytes = f.read()

    modulus = sigstruct_bytes[128:512]
    mrenclave = sigstruct_bytes[960:992]
    isvprodid = sigstruct_bytes[1024:1026]
    isvsvn = sigstruct_bytes[1026:1028]
    assert mrenclave.hex() == sigstruct.mrenclave
    assert sha256(modulus).hexdigest() == sigstruct.mrsigner
    assert int.from_bytes(isvprodid, byteorder="little") == sigstruct.isvprodid
    assert int.from_bytes(isvsvn, byteorder="little") == sigstruct.isvsvn


def test_signed_enclave_sha256(signed_enclave_bytes):
    """Just make sure the signed enclave used for tests has not changed."""
    assert (
        sha256(signed_enclave_bytes).hexdigest()
        == "2fcb14082387781de3efc89cd8ada6c2f992621d9f353cdba90b8adde04edfc7"
    )


@mark.skip
def test_get_enclave_sigstruct(signed_enclave_path):
    from auditee import sgx

    expected_sha256 = "59a059bdd20855c8e9735ba08944762704b3a3afaeb5ec8a0d6b268eaca87f94"
    sigstruct = sgx.get_enclave_sigstruct(signed_enclave_path)
    assert sha256(sigstruct).hexdigest() == expected_sha256


@mark.skip
def test_get_mrenclave(signed_enclave_path):
    from auditee.sgx import get_mrenclave

    expected = "f19de84787f1a90ad7bc2d4c2fd952e05545c6f177e8b10b112a4cef31ba0454"
    mrenclave = get_mrenclave(signed_enclave_path)
    assert mrenclave.hex() == expected


@mark.skip
def test_get_mrsigner(signed_enclave_path):
    from auditee.sgx import get_mrsigner

    expected = "bd71c6380ef77c5417e8b2d1ce2d4b6504b9f418e5049342440cfff2443d95bd"
    mrsigner = get_mrsigner(signed_enclave_path)
    assert mrsigner.hex() == expected
