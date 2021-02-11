from pytest import mark


def test_verify(
    signed_enclave_path, enclave_path, enclave_config_path, auditor_sk_path
):
    from auditee.reproducibility import verify

    report = verify(
        signed_enclave_path,
        enclave_path,
        enclave_config_path,
        signing_key=auditor_sk_path,
    )
    assert report.mrenclave.matches
    assert report.isvprodid.matches
    assert report.isvsvn.matches
    assert not report.mrsigner.matches


def test_verify_with_same_signing_key(
    signed_enclave_path, enclave_path, enclave_config_path, developer_sk_path
):
    from auditee.reproducibility import verify

    report = verify(
        signed_enclave_path,
        enclave_path,
        enclave_config_path,
        signing_key=developer_sk_path,
    )
    assert report.mrenclave.matches
    assert report.isvprodid.matches
    assert report.isvsvn.matches
    assert report.mrsigner.matches


@mark.skip
def test_verify_mrenclave_mismatch():
    raise NotImplementedError
