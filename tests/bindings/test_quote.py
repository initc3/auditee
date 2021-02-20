from base64 import urlsafe_b64decode


def test_quote(sgx_quote_0_dict):
    from auditee.bindings.quote import read_sgx_quote_bytes

    quote = sgx_quote_0_dict
    quote_bytes = urlsafe_b64decode(quote.pop("base64"))
    sgx_quote_t = read_sgx_quote_bytes(quote_bytes)
    assert sgx_quote_t.version == quote["version"]
    assert sgx_quote_t.sign_type == quote["sign_type"]
    assert bytes(sgx_quote_t.epid_group_id).hex() == quote["epid_group_id"]
    assert sgx_quote_t.qe_svn == quote["qe_svn"]
    assert sgx_quote_t.pce_svn == quote["pce_svn"]
    assert sgx_quote_t.xeid == quote["xeid"]
    assert bytes(sgx_quote_t.basename.name).hex() == quote["basename"]
    report_body = quote["report_body"]
    assert bytes(sgx_quote_t.report_body.cpu_svn.svn).hex() == report_body["cpu_svn"]
    assert sgx_quote_t.report_body.misc_select == report_body["misc_select"]
    assert (
        sgx_quote_t.report_body.attributes.flags == report_body["attributes"]["flags"]
    )
    assert sgx_quote_t.report_body.attributes.xfrm == report_body["attributes"]["xfrm"]
    assert (
        bytes(sgx_quote_t.report_body.mr_enclave.m).hex() == report_body["mr_enclave"]
    )
    assert bytes(sgx_quote_t.report_body.mr_signer.m).hex() == report_body["mr_signer"]
    assert (
        int.to_bytes(
            sgx_quote_t.report_body.isv_prod_id, length=2, byteorder="little"
        ).hex()
        == report_body["isv_prod_id"]
    )
    assert (
        int.to_bytes(
            sgx_quote_t.report_body.isv_svn, length=2, byteorder="little"
        ).hex()
        == report_body["isv_svn"]
    )
    assert (
        bytes(sgx_quote_t.report_body.report_data.d).hex() == report_body["report_data"]
    )
