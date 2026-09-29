#!/usr/bin/env python3
"""
Generate an RSA-2048 private key and a self-signed X.509 certificate
in the same style as the UIDAI signing cert.

Outputs:
  icard_sign.key  - PEM private key (keep this secret)
  icard_sign.cer  - PEM certificate (distribute with the card reader)

Usage:
  python3 gen_cert.py [--org "My Organisation"] [--cn "DS MYORG 01"]
"""

import argparse
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def main():
    parser = argparse.ArgumentParser(description="Generate icard signing key + cert")
    parser.add_argument("--org",     default="My Organisation")
    parser.add_argument("--cn",      default="DS MYORG 01")
    parser.add_argument("--country", default="IN")
    parser.add_argument("--state",   default="Karnataka")
    parser.add_argument("--city",    default="Bengaluru")
    parser.add_argument("--ou",      default="Technology Centre")
    parser.add_argument("--years",   default=3, type=int,
                        help="Certificate validity in years")
    parser.add_argument("--key-out", default="icard_sign.key")
    parser.add_argument("--cer-out", default="icard_sign.cer")
    args = parser.parse_args()

    # --- Generate RSA-2048 private key ---
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # --- Build subject / issuer (self-signed, so both are identical) ---
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME,             args.country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME,   args.state),
        x509.NameAttribute(NameOID.LOCALITY_NAME,            args.city),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,        args.org),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, args.ou),
        x509.NameAttribute(NameOID.COMMON_NAME,              args.cn),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365 * args.years))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )

    # --- Write private key ---
    key_path = Path(args.key_out)
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    print(f"Private key : {key_path}  ← keep secret")

    # --- Write certificate ---
    cer_path = Path(args.cer_out)
    cer_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Certificate : {cer_path}  ← distribute with reader")

    print(f"Valid from  : {cert.not_valid_before_utc}")
    print(f"Valid until : {cert.not_valid_after_utc}")
    print(f"Subject     : {cert.subject}")


if __name__ == "__main__":
    main()
