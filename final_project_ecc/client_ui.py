from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path
from typing import Set, Dict, Any, Optional

from fastapi import FastAPI, WebSocket
from fastapi.responses import HTMLResponse, PlainTextResponse, Response

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# -------------------------
# CONFIG
# -------------------------
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9000

PKI = Path("pki")
CA_CERT_PATH = PKI / "ca_cert.pem"

WEB_DIR = Path("web")


# -------------------------
# Shared state (for browser)
# -------------------------
STATE: Dict[str, Any] = {
    "deviceId": "server-link",
    "temp": None,
    "pressure": None,
    "ts": None,
    "status": "idle",
}


# -------------------------
# FastAPI + WebSocket
# -------------------------
app = FastAPI()
clients: Set[WebSocket] = set()


async def broadcast(event: dict) -> None:
    data = json.dumps(event)
    dead: list[WebSocket] = []
    for ws in list(clients):
        try:
            await ws.send_text(data)
        except Exception:
            dead.append(ws)
    for ws in dead:
        clients.discard(ws)


# -------------------------
# Helpers crypto
# -------------------------
def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def derive_aes_key(shared: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ISEN-FINALPROJECT-ECDH",
    )
    return hkdf.derive(shared)


def verify_server_cert_with_ca(cert_pem: str) -> x509.Certificate:
    ca = x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())
    srv = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))

    ca.public_key().verify(
        srv.signature,
        srv.tbs_certificate_bytes,
        ec.ECDSA(srv.signature_hash_algorithm),
    )
    return srv


# -------------------------
# TCP client task
# -------------------------
async def tcp_client_task():
    while True:
        try:
            STATE["status"] = "connecting"
            await broadcast({"type": "status", "status": STATE["status"]})

            reader, writer = await asyncio.open_connection(SERVER_HOST, SERVER_PORT)
            STATE["status"] = "connected"
            await broadcast({"type": "status", "status": STATE["status"]})

            # 1) receive cert
            cert_msg = json.loads((await reader.readline()).decode("utf-8"))
            if cert_msg.get("type") != "cert":
                raise RuntimeError(f"Expected cert, got {cert_msg}")

            cert_pem = cert_msg["cert_pem"]
            verify_server_cert_with_ca(cert_pem)
            await broadcast({"type": "log", "msg": "Server cert verified with CA ✅"})

            # 2) send hello
            writer.write((json.dumps({"type": "hello", "clientId": "dashboard-01", "proto": 1}) + "\n").encode("utf-8"))
            await writer.drain()

            # 3) ECDH client keys
            cli_priv = ec.generate_private_key(ec.SECP256R1())
            cli_pub = cli_priv.public_key()
            cli_pub_bytes = cli_pub.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint,
            )

            writer.write((json.dumps({"type": "ecdh_pub", "pub_b64": b64e(cli_pub_bytes)}) + "\n").encode("utf-8"))
            await writer.drain()

            # 4) receive server ecdh pub
            srv_ecdh = json.loads((await reader.readline()).decode("utf-8"))
            if srv_ecdh.get("type") != "ecdh_pub":
                raise RuntimeError(f"Expected ecdh_pub, got {srv_ecdh}")

            srv_pub_bytes = b64d(srv_ecdh["pub_b64"])
            srv_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), srv_pub_bytes)

            # 5) derive AES
            shared = cli_priv.exchange(ec.ECDH(), srv_pub)
            aes_key = derive_aes_key(shared)
            aesgcm = AESGCM(aes_key)

            # 6) receive key_ok
            ok = json.loads((await reader.readline()).decode("utf-8"))
            if ok.get("type") != "key_ok":
                raise RuntimeError(f"Expected key_ok, got {ok}")

            STATE["status"] = "running"
            await broadcast({"type": "status", "status": STATE["status"]})
            await broadcast({"type": "key_ok"})

            # 7) loop receive encrypted data
            while True:
                line = await reader.readline()
                if not line:
                    raise RuntimeError("Server closed connection")

                msg = json.loads(line.decode("utf-8"))
                if msg.get("type") != "data":
                    continue

                nonce = b64d(msg["nonce_b64"])
                ct = b64d(msg["ct_b64"])
                tag = b64d(msg["tag_b64"])

                plain = aesgcm.decrypt(nonce, ct + tag, associated_data=None)
                payload = json.loads(plain.decode("utf-8"))

                STATE["temp"] = payload.get("temp")
                STATE["pressure"] = payload.get("pressure")
                STATE["ts"] = payload.get("ts")
                STATE["status"] = "running"

                await broadcast({"type": "data", **STATE})

        except Exception as e:
            STATE["status"] = f"error: {e}"
            await broadcast({"type": "status", "status": STATE["status"]})
            await asyncio.sleep(1.5)


# -------------------------
# FastAPI routes
# -------------------------
@app.on_event("startup")
async def startup():
    # start TCP client in background
    asyncio.create_task(tcp_client_task())


@app.get("/")
async def root():
    index_path = WEB_DIR / "index.html"
    if not index_path.exists():
        return PlainTextResponse("Missing web/index.html", status_code=500)
    return HTMLResponse(index_path.read_text(encoding="utf-8"))


@app.get("/styles.css")
async def styles():
    css_path = WEB_DIR / "styles.css"
    if not css_path.exists():
        return PlainTextResponse("Missing web/styles.css", status_code=500)
    return Response(content=css_path.read_text(encoding="utf-8"), media_type="text/css")


@app.get("/health")
async def health():
    return {"ok": True, "clients": len(clients), "state": STATE}


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    clients.add(ws)

    # send state immediately
    await ws.send_text(json.dumps({"type": "state", **STATE}))

    try:
        while True:
            msg = await ws.receive_text()
            if msg.strip().lower() == "ping":
                await ws.send_text(json.dumps({"type": "pong"}))
    except Exception:
        pass
    finally:
        clients.discard(ws)
