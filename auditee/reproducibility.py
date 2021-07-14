import json
import os
import pathlib
import subprocess
from collections import namedtuple

import yaml
from blessings import Terminal
from colorama import init as init_colorama  # , Fore, Back, Style
from python_on_whales import docker

from auditee.sgx import Sigstruct, sign as sgx_sign
from auditee.bindings.quote import read_sgx_quote_body_b64

init_colorama()
term = Terminal()

ReproducibilityReport = namedtuple(
    "ReproducibilityReport", ("mrenclave", "isvprodid", "isvsvn", "mrsigner")
)
ReportItem = namedtuple("ReportItem", ("matches", "expected", "computed"))


def build_enclave(source_code, *, docker_build_progress=False):
    """ """
    source_code_path = pathlib.Path(source_code).resolve()
    auditee_file = source_code_path.joinpath(".auditee.yml")

    with open(auditee_file) as f:
        auditee_config = yaml.safe_load(f)

    enclave_build_config = auditee_config["enclaves"][0]

    # Get absolute path of enclave config
    # enclave_config = source_code_path.joinpath(enclave_build_config["enclave_config"])

    build_config = enclave_build_config["build"]
    builder = build_config["builder"]
    build_kwargs = build_config["build_kwargs"]
    os.chdir(source_code_path)
    if builder == "docker":
        docker.build(
            output={"type": "local", "dest": "/tmp/out"},
            progress=docker_build_progress,
            **build_kwargs,
        )
    elif builder == "nix-build":
        popenargs = [builder, build_kwargs.get("file", "default.nix")]
        returncode = subprocess.run(popenargs).returncode
        if returncode != 0:
            raise RuntimeError(f"Error building enclave with {builder}")
    os.chdir("..")
    return source_code_path.joinpath(
        build_config["output_dir"], build_config["enclave_file"]
    )


def sign_enclave(
    unsigned_enclave,
    enclave_config,
    *,
    signed_enclave="/tmp/enclave.signed.so",
    signing_key=None,
):
    """ """
    if signing_key is None:
        signing_key = (
            pathlib.Path(__file__).parent.resolve().joinpath("signing_key.pem")
        )
    else:
        signing_key = pathlib.Path(signing_key).resolve()

    sgx_sign(
        unsigned_enclave,
        key=signing_key,
        out=signed_enclave,
        config=pathlib.Path(enclave_config).resolve(),
    )
    return signed_enclave


def extract_sigstruct(signed_enclave):
    """ """
    return Sigstruct.from_enclave_file(signed_enclave)


def verify_ias_report(report, signed_enclave):
    sigstruct = Sigstruct.from_enclave_file(signed_enclave)
    return _verify_ias_report(report, sigstruct)


def _verify_ias_report(report, sigstruct):
    """ """
    with open(report) as f:
        report_data = json.load(f)

    report_body = report_data["body"]
    isv_enclave_quote_body = report_body["isvEnclaveQuoteBody"]
    quote_body = read_sgx_quote_body_b64(isv_enclave_quote_body)
    report_mrenclave = bytes(quote_body.report_body.mr_enclave.m)

    print(
        f"- Provided enclave MRENCLAVE: "
        f"\t\t{term.bold}{sigstruct.mrenclave.hex()}{term.normal}"
    )
    print(
        f"- IAS report MRENCLAVE: "
        f"\t\t{term.bold}{report_mrenclave.hex()}{term.normal}"
    )
    print()

    match = report_mrenclave == sigstruct.mrenclave
    if match:
        print(f"{term.green}MRENCLAVES match!{term.normal}")
    else:
        print(f"{term.red}MRENCLAVES do not match!{term.normal}")
    return match


def verify_signed_enclave(signed_enclave, sigstruct_data):
    """ """


def print_report(dev_mrenclave, audit_mrenclave, *, ias_report_mrenclave=None):
    print(f"\n{term.bold}Reproducibility Report\n----------------------{term.normal}")
    print(f"- Signed enclave MRENCLAVE: \t\t\t{term.bold}{dev_mrenclave}{term.normal}")
    print(
        f"- Built-from-source enclave MRENCLAVE: "
        f"\t\t{term.bold}{audit_mrenclave}{term.normal}"
    )
    if ias_report_mrenclave:
        print(
            f"- IAS report MRENCLAVE: "
            f"\t\t\t{term.bold}{ias_report_mrenclave}{term.normal}"
        )
    print()


def verify_mrenclave(
    source_code,
    signed_enclave,
    *,
    ias_report=None,
    docker_build_progress=False,
    signing_key=None,
):
    """Given some source code, a signed enclave, and optionally, a remote attestation
    verification report from Intel's attestation service (IAS), verify whether
    the signed enclave binary can be reproduced from the given source code, and
    whether the IAS report corresponds to the given signed enclave.
    """
    unsigned_enclave = build_enclave(
        source_code, docker_build_progress=docker_build_progress
    )

    source_code = pathlib.Path(source_code).resolve()
    auditee_file = source_code.joinpath(".auditee.yml")

    with open(auditee_file) as f:
        auditee_config = yaml.safe_load(f)

    enclave_build_config = auditee_config["enclaves"][0]

    # Get absolute path of enclave config
    enclave_config = source_code.joinpath(enclave_build_config["enclave_config"])

    rebuilt_signed_enclave = sign_enclave(
        unsigned_enclave, enclave_config, signing_key=signing_key
    )

    if ias_report is not None:
        ias_report = pathlib.Path(ias_report).resolve()

    auditor_sigstruct = Sigstruct.from_enclave_file(rebuilt_signed_enclave)
    dev_sigstruct = Sigstruct.from_enclave_file(signed_enclave)
    if not ias_report:
        print_report(dev_sigstruct.mrenclave.hex(), auditor_sigstruct.mrenclave.hex())
        if auditor_sigstruct.mrenclave == dev_sigstruct.mrenclave:
            print(f"{term.green}MRENCLAVE match!{term.normal}")
        else:
            print(f"{term.red}MRENCLAVE do not match!{term.normal}")
        return auditor_sigstruct.mrenclave == dev_sigstruct.mrenclave

    with open(ias_report) as f:
        ias_report_data = json.load(f)

    report_body = ias_report_data["body"]
    # TODO verify certificate & signature -- see issue #5
    # https://github.com/sbellem/auditee/issues/5
    # report_headers = ias_report_data["headers"]
    isv_enclave_quote_body = report_body["isvEnclaveQuoteBody"]
    quote_body = read_sgx_quote_body_b64(isv_enclave_quote_body)
    report_mrenclave = bytes(quote_body.report_body.mr_enclave.m)
    print_report(
        dev_sigstruct.mrenclave.hex(),
        auditor_sigstruct.mrenclave.hex(),
        ias_report_mrenclave=report_mrenclave.hex(),
    )
    mrenclave_match = (
        auditor_sigstruct.mrenclave == dev_sigstruct.mrenclave == report_mrenclave
    )
    if mrenclave_match:
        print(f"{term.green}MRENCLAVES match!{term.normal}")
    else:
        print(f"{term.red}MRENCLAVES do not match!{term.normal}")

    print(f"\n{term.bold}Report data\n-----------{term.normal}")
    can_or_cannot = (
        f"{term.bold_green}CAN{term.normal}"
        if mrenclave_match
        else f"{term.bold_red}CANNOT{term.normal}"
    )
    print(
        f"The following {term.bold}REPORT DATA{term.normal} contained in "
        f"the remote attestation verification report {can_or_cannot} be trusted."
    )
    report_data = bytes(quote_body.report_body.report_data.d).hex()
    print(f"{report_data}")

    return mrenclave_match


def _verify_mrenclave(
    signed_enclave,
    enclave_config,
    *,
    ias_report=None,
    unsigned_enclave_filename="Enclave.so",
    docker_build_attrs,
):
    """Verifies if the MRENCLAVE of the provided signed enclave matches
    with the one obtained when rebuilding the enclave from source, and
    the one in the IAS report.

    Example
    -------
    docker_build_attrs = {'target': 'export-stage'}

    """
    context_path = docker_build_attrs.pop("context_path", ".")
    output = docker_build_attrs.pop("output", {"type": "local", "dest": "out"})
    # target="export-stage", output={"type": "local", "dest": "out"}
    docker.build(context_path, output=output, **docker_build_attrs)

    unsigned_enclave = pathlib.Path(output["dest"]).joinpath(unsigned_enclave_filename)
    signing_key = pathlib.Path(__file__).parent.resolve().joinpath("signing_key.pem")
    dev_sigstruct = Sigstruct.from_enclave_file(signed_enclave)
    out = "/tmp/audit_enclave.signed.so"
    sgx_sign(unsigned_enclave, key=signing_key, out=out, config=enclave_config)
    auditor_sigstruct = Sigstruct.from_enclave_file(out)
    if not ias_report:
        print(
            f"\nsigned enclave MRENCLAVE: \t\t{term.bold}{dev_sigstruct.mrenclave.hex()}{term.normal}"
        )
        print(
            f"built-from-source enclave MRENCLAVE: \t\t{term.bold}{auditor_sigstruct.mrenclave.hex()}{term.normal}\n"
        )
        if auditor_sigstruct.mrenclave == dev_sigstruct.mrenclave:
            print(f"{term.green}MRENCLAVE match!{term.normal}")
        else:
            print(f"{term.red}MRENCLAVE do not match!{term.normal}")
        return auditor_sigstruct.mrenclave == dev_sigstruct.mrenclave

    raise NotImplementedError


def verify(
    signed_enclave,
    unsigned_enclave,
    enclave_config,
    signing_key=None,
    show_mrsigner=False,
    verbose=True,
):
    """Sign the enclave_so, and compare with the signed_enclave.

    :param str signed_enclave: The signed enclave to check against.
    :param str unsigned_enclave: The enclave to sign and verify
        against the signed enclave.
    :param str enclave_config: The enclave configuration used to sign
        the enclave.
    :param str signing_key: The private key used to sign the enclave.
    :param bool show_mrsigner: Whether to show the mrsigner field or not.
        Defaults to ``False``.
    :param bool verbose: Whether to use verbose mode or not.
        Defaults to ``True``.
    """
    if not signing_key:
        signing_key = (
            pathlib.Path(__file__).parent.resolve().joinpath("signing_key.pem")
        )
    dev_sigstruct = Sigstruct.from_enclave_file(signed_enclave)
    out = "/tmp/audit_enclave.signed.so"
    sgx_sign(unsigned_enclave, key=signing_key, out=out, config=enclave_config)
    auditor_sigstruct = Sigstruct.from_enclave_file(out)
    report_data = {
        attr: ReportItem(
            matches=val,
            expected=getattr(dev_sigstruct, attr),
            computed=getattr(auditor_sigstruct, attr),
        )
        for attr, val in auditor_sigstruct.cmp(dev_sigstruct).items()
    }
    report = ReproducibilityReport(**report_data)
    if verbose:
        _print_report(report, show_mrsigner=show_mrsigner)
    return report


def _print_report(report, show_mrsigner=False):
    print(f"\n{term.bold}Reproducibility Report\n----------------------")
    for attr, val in report._asdict().items():
        if attr == "mrsigner" and not show_mrsigner:
            continue
        print(f"{term.bold}{attr}:{term.normal}")
        for k, v in val._asdict().items():
            if attr in ("mrenclave", "mrsigner") and k in ("expected", "computed"):
                v = v.hex()
            print(f"   {k}: ", end="")
            if k == "matches":
                if v:
                    matches = True
                    print(f"{term.green}{v}{term.normal}")
                else:
                    matches = False
                    print(f"{term.red}{v}{term.normal}")
            else:
                if not matches and k == "computed":
                    print(f"{term.red}{v}{term.normal}")
                else:
                    print(f"{v}")
