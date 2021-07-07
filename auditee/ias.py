import json
import os
from dataclasses import field
from typing import Any

from pydantic.dataclasses import dataclass
import requests

from auditee.bindings.quote import read_sgx_quote_body_b64

DEV_URL = "https://api.trustedservices.intel.com/sgx/dev"
VERIFY_ENDPOINT = "/attestation/v4/report"
VERIFY_URL = DEV_URL + VERIFY_ENDPOINT

report_attrs_rename_map = {
    "nonce": "nonce",
    "id": "request_id",
    "timestamp": "timestamp",
    "version": "version",
    "advisoryURL": "advisory_url",
    "advisoryIDs": "advisory_ids",
    "isvEnclaveQuoteStatus": "isv_enclave_quote_status",
    "platformInfoBlob": "platform_info_blob",
    "isvEnclaveQuoteBody": "isv_enclave_quote_body",
}


@dataclass
class IASReport:
    nonce: str
    request_id: str
    timestamp: str
    version: int
    advisory_url: str
    advisory_ids: list
    isv_enclave_quote_status: str
    platform_info_blob: str
    isv_enclave_quote_body: str
    sgx_quote_t: Any = field(init=False)

    def __post_init__(self):
        self.sgx_quote_t = unpack_b64_quote_body(self.isv_enclave_quote_body)

    @classmethod
    def from_json(cls, report):
        with open(report) as f:
            report_dict = json.load(f)
        report_dict.setdefault("nonce", "")
        return cls(**{report_attrs_rename_map[k]: v for k, v in report_dict.items()})

    def quote(self):
        return unpack_b64_quote_body(self.isv_enclave_quote_body)

    def report_body(self):
        return self.quote().report_body

    def mrenclave(self):
        return bytes(self.report_body().mr_enclave.m)


def send_quote(quote, *, ias_primary_key=None):
    """Send quote to IAS for verification.

    Example of quote
    ----------------
    quote = {
        "isvEnclaveQuote":"AgAAAFsLAAALAAoAAAAAAFOrdeScwC/lZP1RWReIG+h/rVJejTZl/1GvCOdvcauJCRH//wECAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAACY/GzrimHYXELYGCnKp2A+go2mzJCqHNDdOpdwBbe38AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAC9ccY4Dvd8VBfostHOLUtlBLn0GOUEk0JEDP/yRD2VvQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB/g7Flf/H8U7ktwYFIodZd/C1LH6PWdyhK3dIAEm2QaQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqAIAAGw7FkGhY+XgiLhY0eOe6K74pj8IX4OVDOa+GKEgtwAUtOsdiPih+XcJ3qRYp+h6anUunYRo3bUyjMMW4jtwCFHzKb9rnMEN/pUup4pPD8cv27f8kkafYux41x25sEkhknPurBTWDRA0QzXFXN03qBwsOflQUTJdaVcuj3QDR3lUFdpobDu253dqh5Fe1VocOsgkaugLOaXM0QMbdT+kz55QxXV+xIVNf9o6B6tb7gXpFlMgv5s48wdF6APxbMMgvXS7MalstAvDy0SvhVu9vle2ARhAqRsFPadB/UpvIs9yukWE9gZQn9ys0VSDjwnjsWn/2dia4k7Mys39Exoqe/5KEwHtaDEqlDOKZLgHufFujVeMRuhGUdXlegzaXf2u0YdpQoWBpdlv7iZ0uGgBAADqp5Gp2fZB5O8rUh/hEW1025QNzSIzOaqxxJkvo/Ptl3rW6A5ayroZU1cQ8p6ivimVTngImH2bKc/X+JTUceHUBS2Dyx8B2RE/M4dRgTAF5u5yfY6nTXi0Llt1Elz1DImLHaNN2DtFjhwDsX/H+y5rpZ0eIhm98zdg6kh3Yc+BJauGP0HHsNDUqgcu/NInxZS1r9XGwY6kq+x0L1k/n7igD2XRTMcMjN7EgP573O+nzTnHU/yQBKwyYxkNfkna8yR/NS8RsyjELJjqVaxZSavGoeT0O7V47Zdc1XPlJFqIa0Ba1HrA0RQWr1Hu5QoTwEIctwnR/Ua1ZGxqain+DwcNcMChWNLYC8nTt3KCky2tnLwOWVefCk5gIN9fwg3RQDFZTcM7En33lgP6P8NNbrzjJv7uq0RqErR8X+PV8l5pKfoWy99OupOswO8RHub/64y8Z2+2kFdYlZViSRgXZIAxN6XVPXk9D1BB/A7wQeH2pXxmsVq3slN3",
        "nonce":"848c6566356c188bb48d0471e8a61164",
    }
    """
    if not ias_primary_key:
        try:
            ias_primary_key = os.environ["IAS_PRIMARY_KEY"]
        except KeyError:
            raise KeyError(
                "The IAS primary key must either be passed as a"
                " keyword argument or be set as an environment variable"
            )

    headers = {
        "Content-Type": "application/json",
        "Ocp-Apim-Subscription-Key": ias_primary_key,
    }
    res = requests.post(VERIFY_URL, json=quote, headers=headers)
    if not res.ok:
        # TODO
        # 400 Bad Request Invalid Attestation Evidence Payload. The client should not
        #     repeat the request without modifications.
        # 401 Unauthorized Failed to authenticate or authorize request.
        # 500 Internal Server Error Internal error occurred.
        # 503 Service Unavailable Service is currently not able to process the request
        #     (due to a temporary overloading or maintenance). This is a temporary
        #     state –the same request can be repeated after some time.
        raise NotImplementedError(f"Request failed with status code {res.status_code}")
    # TODO verify certs and signature, in header -- return headers, or just return
    # response object
    # return res.json()
    return res


def unpack_b64_quote_body(b64_quote_body):
    quote_body = read_sgx_quote_body_b64(b64_quote_body)
    return quote_body
