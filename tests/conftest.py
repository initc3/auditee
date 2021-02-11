from collections import namedtuple

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
