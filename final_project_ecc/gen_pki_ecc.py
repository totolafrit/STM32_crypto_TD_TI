from __future__ import annotations

import argparse
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

OUT = Path("pki")


def w(path: Path, data: bytes) -> None:
    path.write_bytes(data)


def exists_any() -> bool:
    return any((OUT / f).exists() for f in ["ca_key.pem", "ca_cert.pem", "server_key.pem", "server_cert.pem"])


def main():
    parser = argparse.ArgumentParser(description="Generate ECC CA + Server certificate (P-256, SHA-256).")
    parser.add_argument("--force", action="store_true", help="Overwrite existing pki files.")
    args = parser.parse_args()

    OUT.mkdir(exist_ok=True)

    if exists_any() and not args.force:
        print("[SKIP] pki already exists. Use --force to regenerate.")
        print("Existing files in pki/: ca_key.pem, ca_cert.pem, server_key.pem, server_cert.pem")
        return

    now = datetime.datetime.now(datetime.UTC)

    # ---- CA key (ECDSA P-256) ----
    ca_key = ec.generate_private_key(ec.SECP256R1())
    w(
        OUT / "ca_key.pem",
        ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )

    ca_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ISEN"),
            x509.NameAttribute(NameOID.COMMON_NAME, "TP-CA-ECC"),
        ]
    )

    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    w(OUT / "ca_cert.pem", ca_cert.public_bytes(serialization.Encoding.PEM))

    # ---- Server key (ECDSA P-256) ----
    srv_key = ec.generate_private_key(ec.SECP256R1())
    w(
        OUT / "server_key.pem",
        srv_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )

    srv_subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ISEN"),
            x509.NameAttribute(NameOID.COMMON_NAME, "tp-server-ecc.local"),
        ]
    )

    srv_cert = (
        x509.CertificateBuilder()
        .subject_name(srv_subject)
        .issuer_name(ca_cert.subject)
        .public_key(srv_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,     # ECDSA signatures
                key_encipherment=False,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=True,         # if you later want to use the cert key for ECDH (optional)
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.SERVER_AUTH,
                    # ExtendedKeyUsageOID.CLIENT_AUTH,  # uncomment if you later do mutual auth
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("tp-server-ecc.local"),
                    x509.DNSName("localhost"),
                ]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    w(OUT / "server_cert.pem", srv_cert.public_bytes(serialization.Encoding.PEM))

    print("[OK] Generated ECC PKI:")
    print(" - pki/ca_key.pem")
    print(" - pki/ca_cert.pem")
    print(" - pki/server_key.pem")
    print(" - pki/server_cert.pem")
    print("Tip: re-run with --force to regenerate")


if __name__ == "__main__":
    main()
