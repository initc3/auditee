import argparse
import textwrap

from auditee.enclave import Enclave
from auditee.ias import IASReport
from auditee.bindings.quote import read_sgx_quote_bytes

# from auditee.sgx import Sigstruct


def mrenclave(args):
    if args.signed_binary:
        enclave = Enclave(signed_enclave_path=args.signed_binary)
        print(f"\nMRENCLAVE: {enclave.mrenclave().hex()}")
    elif args.src:
        enclave = Enclave.from_src(args.src)
        enclave.sign()
        print(f"\nMRENCLAVE: {enclave.mrenclave().hex()}")
    elif args.ias_response:
        report = IASReport.from_json(args.ias_response)
        print(report.mrenclave().hex())
    elif args.quote_binary:
        with open(args.quote_binary, "rb") as f:
            q = f.read()
        print(bytes(read_sgx_quote_bytes(q).report_body.mr_enclave.m).hex())


def main():
    parser = argparse.ArgumentParser(description="auditee tool command line")
    subparsers = parser.add_subparsers()

    mrenclave_parser = subparsers.add_parser(
        "mrenclave",
        description="Compute the MRENCLAVE of an enclave.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent(
            """\
            examples:
                Compute the MRENCLAVE from a signed enclave binary:
                $ auditee mrenclave --signed-binary enclave.signed.so

                Compute the MRENCLAVE from local source code:
                $ auditee mrenclave --src sgx-iot/

                Compute the MRENCLAVE from source code of a remote git repository:
                $ auditee mrenclave --src https://github.com/sbellem/sgx-iot

                Specify a branch or a commit:
                $ auditee mrenclave --src https://github.com/sbellem/sgx-iot@dev
                $ auditee mrenclave --src https://github.com/sbellem/sgx-iot@313fb50

                Compute the MRENCLAVE from an IAS verification report:
                $ auditee mrenclave --ias-response ias_response.json
            """
        ),
    )
    group = mrenclave_parser.add_mutually_exclusive_group()
    group.add_argument("--signed-binary", help="signed enclave binary")
    group.add_argument(
        "--src", help="enclave source code (local file path or git repository URL)"
    )
    # "(append '@<branch-or-rev>' to set  branch or revision)"
    # "https://github.com/alice/teecode@dev, or "
    # "https://github.com/alice/teecode@313fb50"
    group.add_argument("--ias-response")
    group.add_argument("--quote-binary")
    mrenclave_parser.set_defaults(func=mrenclave)

    args = parser.parse_args()
    try:
        args.func(args)
    except AttributeError:
        # TODO: Add more descriptive error messages for when there are more auditee commands
        print("Too few arguments. Please use `auditee mrenclave --help` for more information")
