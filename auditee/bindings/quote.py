import pathlib
from base64 import b64decode

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


def read_sgx_quote_b64(quote_b64):
    """Does not read the signature ... having problems reading it."""
    quote_bytes = b64decode(quote_b64)
    sgx_quote_t = ffi.new("sgx_quote_t*")
    ffi.buffer(sgx_quote_t)[:436] = quote_bytes[:436]
    return sgx_quote_t


def read_sgx_quote_body_b64(quote_body_b64):
    """The quote body is the quote without the signature len and signature."""
    quote_body_bytes = b64decode(quote_body_b64)
    sgx_quote_t = ffi.new("sgx_quote_t*")
    ffi.buffer(sgx_quote_t)[:432] = quote_body_bytes
    return sgx_quote_t
