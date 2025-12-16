"""Gmail CSE / S/MIME certificate validator.

This module validates that a PKCS#12 (P12/PFX) contains a leaf certificate
suitable for Gmail Client-side encryption recipient eligibility checks:
- Subject Alternative Name includes rfc822Name matching the user email
- Extended Key Usage includes emailProtection

Usage (CLI):
  python cse_smime_validator.py --p12-path /path/to/user.pfx --password 'secret' --email user@example.com

Usage (import):
  from cse_smime_validator import p12_bytes_from_path, load_p12_and_validate
  p12_bytes = p12_bytes_from_path('/path/to/user.p12')
  load_p12_and_validate(p12_bytes, 'secret', 'user@example.com')
"""

from __future__ import annotations

import argparse
from typing import Iterable

from cryptography import x509
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID


# ---------------------------------------------------------------------
# Optional request/response models (kept commented per your snippet)
# ---------------------------------------------------------------------
# from pydantic import BaseModel, EmailStr, Field
#
# class CSRRequest(BaseModel):
#     common_name: str = Field(..., example="user@example.com")
#     email: EmailStr
#     organization: str | None = None
#     country: str | None = None
#     validity_days: int = 365
#
# class CertificateResponse(BaseModel):
#     certificate_pem: str
#     private_key_pem: str


def _lower_emails(values: Iterable[str]) -> set[str]:
    return {v.strip().lower() for v in values if v and v.strip()}


def validate_smime_cert_for_user(cert: x509.Certificate, user_email: str) -> None:
    """Validate the leaf cert for recipient eligibility.

    Raises:
        ValueError: if SAN/EKU requirements are not met.
    """
    user_email_lc = user_email.strip().lower()

    # SAN must contain the email
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
        # RFC822Name objects
        emails = _lower_emails([e.value for e in san.get_values_for_type(x509.RFC822Name)])
    except x509.ExtensionNotFound:
        emails = set()

    if user_email_lc not in emails:
        raise ValueError(
            f"Certificate SAN rfc822Name missing {user_email_lc}; found {sorted(emails)}"
        )

    # EKU must contain emailProtection
    try:
        eku = cert.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        ).value
        if ExtendedKeyUsageOID.EMAIL_PROTECTION not in eku:
            raise ValueError("Certificate EKU missing emailProtection")
    except x509.ExtensionNotFound:
        raise ValueError("Certificate EKU extension missing (need emailProtection)")


def p12_bytes_from_path(p12_path: str) -> bytes:
    """Load a PKCS#12 file from disk as raw bytes."""
    with open(p12_path, "rb") as f:
        return f.read()


def load_p12_and_validate(p12_bytes: bytes, p12_password: str, user_email: str) -> None:
    """Load PKCS#12 and validate the leaf cert matches the user email.

    Raises:
        ValueError: if P12 missing private key/cert, password is wrong, or cert invalid.
    """
    try:
        private_key, certificate, _ = pkcs12.load_key_and_certificates(
            p12_bytes,
            p12_password.encode("utf-8"),
        )
    except Exception as e:
        raise ValueError(f"Unable to load PKCS#12 (bad password or corrupt file): {e}") from e

    if private_key is None or certificate is None:
        raise ValueError("P12 missing private key or leaf certificate")

    validate_smime_cert_for_user(certificate, user_email)


def load_p12_and_validate_from_path(p12_path: str, p12_password: str, user_email: str) -> None:
    """Convenience wrapper for file-path validation."""
    p12_bytes = p12_bytes_from_path(p12_path)
    load_p12_and_validate(p12_bytes, p12_password, user_email)


def _main() -> int:
    parser = argparse.ArgumentParser(description="Validate S/MIME P12/PFX for Gmail CSE.")
    parser.add_argument("--p12-path", required=True, help="Path to .p12/.pfx file")
    parser.add_argument("--password", required=True, help="PKCS#12 passphrase")
    parser.add_argument("--email", required=True, help="Expected rfc822Name email")
    args = parser.parse_args()

    load_p12_and_validate_from_path(args.p12_path, args.password, args.email)
    print("OK: P12 certificate SAN/EKU validated for", args.email)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
