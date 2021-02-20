import pathlib

from cffi import FFI

ffi = FFI()

header_filepath = pathlib.Path(__file__).parent.resolve().joinpath("quote.h")

with open(header_filepath) as f:
    ffi.cdef(f.read())


def read_sgx_quote_bytes(quote_bytes):
    """Does not read the signature ... having problems reading it."""
    sgx_quote_t = ffi.new("sgx_quote_t*")
    ffi.buffer(sgx_quote_t)[:436] = quote_bytes[:436]
    return sgx_quote_t
