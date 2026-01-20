from __future__ import annotations

import asyncio
import base64
import json
import os
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


TCP_HOST = "127.0.0.1"
TCP_PORT = 9000

PKI = Path("pki")
CA_CERT_PATH = PKI / "ca_cert.pem"


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def derive_aes_key(shared: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256
        salt=None,
        info=b"ISEN-FINALPROJECT-ECDH",
    )
    return hkdf.derive(shared)


def verify_server_cert_with_ca(cert_pem: str) -> x509.Certificate:
    ca = x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())
    srv = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))

    # CA is ECDSA -> verify using ECDSA
    ca.public_key().verify(
        srv.signature,
        srv.tbs_certificate_bytes,
        ec.ECDSA(srv.signature_hash_algorithm),
    )
    return srv


async def main():
    reader, writer = await asyncio.open_connection(TCP_HOST, TCP_PORT)
    print("[SIM] Connected to server")

    try:
        # Send hello
        writer.write((json.dumps({"type": "hello", "deviceId": "stm32-01", "proto": 1}) + "\n").encode("utf-8"))
        await writer.drain()

        # Receive server cert
        cert_msg = json.loads((await reader.readline()).decode("utf-8"))
        if cert_msg.get("type") != "cert":
            raise RuntimeError(f"Expected 'cert', got: {cert_msg}")
        cert_pem = cert_msg["cert_pem"]
        print("[SIM] Received server certificate")

        # BONUS: verify server cert using CA
        _ = verify_server_cert_with_ca(cert_pem)
        print("[SIM] Server cert verified with CA ✅")

        # ECDH (client side): generate ephemeral keypair
        client_priv = ec.generate_private_key(ec.SECP256R1())
        client_pub = client_priv.public_key()
        client_pub_bytes = client_pub.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )

        # Send client ECDH pub
        writer.write((json.dumps({"type": "ecdh_pub", "pub_b64": b64e(client_pub_bytes)}) + "\n").encode("utf-8"))
        await writer.drain()
        print("[SIM] Sent client ECDH public key")

        # Receive server ECDH pub
        srv_ecdh_msg = json.loads((await reader.readline()).decode("utf-8"))
        if srv_ecdh_msg.get("type") != "ecdh_pub":
            raise RuntimeError(f"Expected 'ecdh_pub', got: {srv_ecdh_msg}")

        srv_pub_bytes = b64d(srv_ecdh_msg["pub_b64"])
        srv_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), srv_pub_bytes)
        print("[SIM] Received server ECDH public key")

        # Derive shared secret -> AES key
        shared = client_priv.exchange(ec.ECDH(), srv_pub)
        aes_key = derive_aes_key(shared)
        print("[SIM] Derived AES-256 key via HKDF ✅")

        # Ack key_ok (optional)
        ack = json.loads((await reader.readline()).decode("utf-8"))
        print("[SIM] Server says:", ack)

        aesgcm = AESGCM(aes_key)

        while True:
            # ---- SENSOR PAYLOAD (SIMULATION) ----
            # temp: 20..30°C
            # pressure: 980..1040 hPa (typical)
            payload = {
                "temp": round(20 + (os.urandom(1)[0] / 255) * 10, 2),
                "pressure": round(980 + (os.urandom(1)[0] / 255) * 60, 2),
                "ts": int(time.time()),
            }

            plain = json.dumps(payload).encode("utf-8")

            nonce = os.urandom(12)  # AES-GCM nonce 12 bytes
            ct_tag = aesgcm.encrypt(nonce, plain, associated_data=None)
            ct = ct_tag[:-16]
            tag = ct_tag[-16:]

            msg = {
                "type": "data",
                "ts": payload["ts"],
                "nonce_b64": b64e(nonce),
                "ct_b64": b64e(ct),
                "tag_b64": b64e(tag),
            }

            writer.write((json.dumps(msg) + "\n").encode("utf-8"))
            await writer.drain()
            print("[SIM] Sent:", payload)

            await asyncio.sleep(2)

    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


if __name__ == "__main__":
    asyncio.run(main())
