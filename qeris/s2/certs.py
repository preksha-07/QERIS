"""
QERIS S2: TLS Certificate Management for Gateway-to-Cloud Transport

Generates and manages self-signed X.509 certificates for the QERIS Cloud Telemetry Service.
In accordance with Blueprint S2 Specification:
"Gateway to cloud: ordinary TLS with a self-signed local certificate. This is not a PKI; do not claim one."
"""
from __future__ import annotations

import datetime
import ipaddress
from pathlib import Path
from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

DEFAULT_CERT_DIR = Path(__file__).resolve().parent / "certs"
DEFAULT_CERT_FILE = DEFAULT_CERT_DIR / "cloud_cert.pem"
DEFAULT_KEY_FILE = DEFAULT_CERT_DIR / "cloud_key.pem"


def generate_self_signed_tls_cert(
    cert_path: Path = DEFAULT_CERT_FILE,
    key_path: Path = DEFAULT_KEY_FILE,
    common_name: str = "qeris-cloud",
    valid_days: int = 3650,
) -> Tuple[Path, Path]:
    """
    Generates an ECDSA P-256 self-signed certificate and private key.
    Includes Subject Alternative Names (SAN) for 'localhost', 'qeris-cloud', and '127.0.0.1'.
    """
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    # Generate ECDSA SECP256R1 private key
    key = ec.generate_private_key(ec.SECP256R1())

    # Build subject and issuer identity (self-signed)
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "QERIS IoT Edge-Cloud Gateway Project"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    san_list = [
        x509.DNSName("localhost"),
        x509.DNSName("qeris-cloud"),
        x509.DNSName("qeris-gateway"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ]

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    with open(cert_path, "wb") as f:
        f.write(cert_pem)
    with open(key_path, "wb") as f:
        f.write(key_pem)

    return cert_path, key_path


def ensure_cloud_tls_certs(
    cert_path: Path = DEFAULT_CERT_FILE,
    key_path: Path = DEFAULT_KEY_FILE,
) -> Tuple[Path, Path]:
    """Ensures self-signed TLS certificates exist on disk, creating them if missing."""
    if not cert_path.exists() or not key_path.exists():
        return generate_self_signed_tls_cert(cert_path, key_path)
    return cert_path, key_path


if __name__ == "__main__":
    c, k = ensure_cloud_tls_certs()
    print(f"Ensured TLS certificates: cert={c}, key={k}")
