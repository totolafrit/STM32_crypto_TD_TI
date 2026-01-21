from __future__ import annotations

import asyncio
import base64
import json
import os
import time
from pathlib import Path
from typing import Dict, Any, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# -------------------------
# CONFIG
# -------------------------
TCP_HOST = "127.0.0.1"
TCP_PORT = 9000

PKI = Path("pki")
CA_CERT_PATH = PKI / "ca_cert.pem"
SERVER_CERT_PATH = PKI / "server_cert.pem"


# -------------------------
# Helpers
# -------------------------
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def load_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def server_cert_pem() -> str:
    return SERVER_CERT_PATH.read_text(encoding="utf-8")


def verify_server_cert_signed_by_ca() -> None:
    """
    Vérifie que server_cert.pem est bien signé par ca_cert.pem (ECDSA OK).
    """
    ca = load_cert(CA_CERT_PATH)
    srv = load_cert(SERVER_CERT_PATH)

    try:
        ca.public_key().verify(
            srv.signature,
            srv.tbs_certificate_bytes,
            ec.ECDSA(srv.signature_hash_algorithm),
        )
    except InvalidSignature as e:
        raise RuntimeError("Server certificate is NOT signed by CA") from e


def derive_aes_key(shared: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256
        salt=None,
        info=b"ISEN-FINALPROJECT-ECDH",
    )
    return hkdf.derive(shared)


# -------------------------
# Sensor source (UART later)
# -------------------------
def get_sensor_sample() -> Dict[str, Any]:
    """
    Remplace ça par l’UART quand tu veux.
    Pour l’instant, mock propre (temp/pressure/ts).
    """
    # temp: 20..30
    temp = round(20 + (os.urandom(1)[0] / 255) * 10, 2)
    # pressure: 980..1040 hPa
    pressure = round(980 + (os.urandom(1)[0] / 255) * 60, 2)
    return {"temp": temp, "pressure": pressure, "ts": int(time.time())}


# -------------------------
# Main TCP server
# -------------------------
async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    print(f"[SRV] Client connected: {peer}")

    # 0) envoyer le certificat serveur au client
    writer.write((json.dumps({"type": "cert", "cert_pem": server_cert_pem()}) + "\n").encode("utf-8"))
    await writer.drain()
    print("[SRV] Sent server certificate")

    # 1) recevoir hello (optionnel mais propre)
    line = await reader.readline()
    if not line:
        writer.close()
        await writer.wait_closed()
        return

    hello = json.loads(line.decode("utf-8"))
    if hello.get("type") != "hello":
        raise RuntimeError(f"Expected hello, got {hello}")
    print(f"[SRV] Hello: {hello}")

    # 2) ECDH: serveur génère sa paire éphémère
    srv_priv = ec.generate_private_key(ec.SECP256R1())
    srv_pub = srv_priv.public_key()
    srv_pub_bytes = srv_pub.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )

    # 3) recevoir pubkey ECDH du client
    line = await reader.readline()
    if not line:
        raise RuntimeError("Client disconnected before ECDH pub")
    msg = json.loads(line.decode("utf-8"))
    if msg.get("type") != "ecdh_pub":
        raise RuntimeError(f"Expected ecdh_pub, got {msg}")

    cli_pub_bytes = b64d(msg["pub_b64"])
    cli_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), cli_pub_bytes)

    # 4) envoyer pubkey ECDH serveur
    writer.write((json.dumps({"type": "ecdh_pub", "pub_b64": b64e(srv_pub_bytes)}) + "\n").encode("utf-8"))
    await writer.drain()
    print("[SRV] ECDH pub exchanged")

    # 5) dériver AES-256
    shared = srv_priv.exchange(ec.ECDH(), cli_pub)
    aes_key = derive_aes_key(shared)
    aesgcm = AESGCM(aes_key)

    # 6) ack
    writer.write((json.dumps({"type": "key_ok"}) + "\n").encode("utf-8"))
    await writer.drain()
    print("[SRV] AES key derived, streaming encrypted sensor data...")

    # 7) boucle d’envoi données chiffrées
    while True:
        payload = get_sensor_sample()
        plain = json.dumps(payload).encode("utf-8")

        nonce = os.urandom(12)
        ct_tag = aesgcm.encrypt(nonce, plain, associated_data=None)
        ct = ct_tag[:-16]
        tag = ct_tag[-16:]

        out = {
            "type": "data",
            "ts": payload["ts"],
            "nonce_b64": b64e(nonce),
            "ct_b64": b64e(ct),
            "tag_b64": b64e(tag),
        }

        writer.write((json.dumps(out) + "\n").encode("utf-8"))
        await writer.drain()
        await asyncio.sleep(2)


async def main():
    # Bonus: vérifier l’intégrité du cert serveur signé CA
    verify_server_cert_signed_by_ca()
    print("[SRV] Server certificate verified with CA ✅")

    server = await asyncio.start_server(handle_client, TCP_HOST, TCP_PORT)
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    print(f"[SRV] Listening on {addrs}")

    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
