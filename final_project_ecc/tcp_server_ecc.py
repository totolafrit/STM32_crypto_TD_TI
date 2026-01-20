from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path
from typing import Optional, Dict, Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature


PKI = Path("pki")
CA_CERT_PATH = PKI / "ca_cert.pem"
SERVER_CERT_PATH = PKI / "server_cert.pem"
SERVER_KEY_PATH = PKI / "server_key.pem"

TCP_HOST = "127.0.0.1"
TCP_PORT = 9000

# shared state for web UI (imported by web_server)
STATE: Dict[str, Any] = {
    "deviceId": None,
    "temp": None,
    "pressure": None,
    "ts": None,
    "status": "idle",
}

# internal session key (per connection in this TP)
_session_aes_key: Optional[bytes] = None


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def load_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def load_privkey(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def server_cert_pem() -> str:
    return SERVER_CERT_PATH.read_text(encoding="utf-8")


def verify_server_cert_signed_by_ca() -> None:
    """
    BONUS trust: verify server_cert signature using CA public key.
    Works for ECDSA CA too.
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


def derive_aes_key_from_ecdh(
    server_priv: ec.EllipticCurvePrivateKey,
    client_pub: ec.EllipticCurvePublicKey,
) -> bytes:
    shared = server_priv.exchange(ec.ECDH(), client_pub)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256
        salt=None,
        info=b"ISEN-FINALPROJECT-ECDH",
    )
    return hkdf.derive(shared)


async def run_tcp_server(broadcast_cb):
    """
    broadcast_cb: async function that receives dict events to send to WS clients
    """
    verify_server_cert_signed_by_ca()
    print("[OK] Server certificate verified with CA (bonus)")

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        global _session_aes_key
        peer = writer.get_extra_info("peername")

        STATE["status"] = f"stm32_connected {peer}"
        await broadcast_cb({"type": "status", "status": STATE["status"]})

        # 1) send certificate to client
        writer.write(
            (json.dumps({"type": "cert", "cert_pem": server_cert_pem()}) + "\n").encode("utf-8")
        )
        await writer.drain()

        # 2) create server ECDH ephemeral keypair (P-256)
        server_ecdh_priv = ec.generate_private_key(ec.SECP256R1())
        server_ecdh_pub = server_ecdh_priv.public_key()

        try:
            while True:
                line = await reader.readline()
                if not line:
                    break

                msg = json.loads(line.decode("utf-8"))
                t = msg.get("type")

                if t == "hello":
                    STATE["deviceId"] = msg.get("deviceId")
                    await broadcast_cb({"type": "hello", "deviceId": STATE["deviceId"]})

                elif t == "ecdh_pub":
                    # Receive client ECDH public key
                    client_pub_bytes = b64d(msg["pub_b64"])
                    client_pub = ec.EllipticCurvePublicKey.from_encoded_point(
                        ec.SECP256R1(), client_pub_bytes
                    )

                    # Send server ECDH public key
                    server_pub_bytes = server_ecdh_pub.public_bytes(
                        encoding=serialization.Encoding.X962,
                        format=serialization.PublicFormat.UncompressedPoint,
                    )
                    writer.write(
                        (json.dumps({"type": "ecdh_pub", "pub_b64": b64e(server_pub_bytes)}) + "\n")
                        .encode("utf-8")
                    )
                    await writer.drain()

                    # Derive AES key
                    _session_aes_key = derive_aes_key_from_ecdh(server_ecdh_priv, client_pub)
                    await broadcast_cb({"type": "key_ok"})
                    writer.write((json.dumps({"type": "key_ok"}) + "\n").encode("utf-8"))
                    await writer.drain()

                elif t == "data":
                    if _session_aes_key is None:
                        raise RuntimeError("No session key yet (ECDH not done).")

                    nonce = b64d(msg["nonce_b64"])
                    ct = b64d(msg["ct_b64"])
                    tag = b64d(msg["tag_b64"])

                    aesgcm = AESGCM(_session_aes_key)
                    plain = aesgcm.decrypt(nonce, ct + tag, associated_data=None)
                    payload = json.loads(plain.decode("utf-8"))

                    STATE["temp"] = payload.get("temp")
                    STATE["pressure"] = payload.get("pressure")
                    STATE["ts"] = payload.get("ts")
                    STATE["status"] = "running"

                    await broadcast_cb({"type": "data", **STATE})

                else:
                    await broadcast_cb({"type": "log", "msg": f"Unknown message type: {t}"})

        except Exception as e:
            STATE["status"] = f"error: {e}"
            await broadcast_cb({"type": "status", "status": STATE["status"]})

        finally:
            writer.close()
            await writer.wait_closed()
            _session_aes_key = None
            STATE["status"] = "stm32_disconnected"
            await broadcast_cb({"type": "status", "status": STATE["status"]})

    server = await asyncio.start_server(handle, TCP_HOST, TCP_PORT)
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    print(f"[OK] STM32 TCP server listening on {addrs}")

    async with server:
        await server.serve_forever()
