"""Classes for ``auditee``-specific errors."""


class AuditeeError(Exception):
    """Base class for ``auditee`` errors."""


class SGXSignError(AuditeeError):
    """Error stemming from calling the ``sgx_sign`` tool."""
