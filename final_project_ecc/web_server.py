from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Set

from fastapi import FastAPI, WebSocket
from fastapi.responses import HTMLResponse, PlainTextResponse, Response

#from tcp_server_ecc import STATE, run_tcp_server
from serial_gateway import STATE, run_serial_gateway


app = FastAPI()
clients: Set[WebSocket] = set()


# ------------------------------------------------------------------
# Broadcast helper (send events to all connected WS clients)
# ------------------------------------------------------------------
async def broadcast(event: dict) -> None:
    data = json.dumps(event)
    dead: list[WebSocket] = []

    # iterate on a snapshot to avoid "set changed size during iteration"
    for ws in list(clients):
        try:
            await ws.send_text(data)
        except Exception:
            dead.append(ws)

    for ws in dead:
        clients.discard(ws)


# ------------------------------------------------------------------
# Startup: launch TCP server in background
# ------------------------------------------------------------------
@app.on_event("startup")
async def startup() -> None:
    asyncio.create_task(run_serial_gateway(broadcast))
    # optional: push a status for UI logs
    await broadcast({"type": "status", "status": "web_server_started"})


# ------------------------------------------------------------------
# Main HTML page
# ------------------------------------------------------------------
@app.get("/")
async def root():
    index_path = Path("web") / "index.html"
    if not index_path.exists():
        return PlainTextResponse(
            "Missing web/index.html. Create the file in ./web/index.html",
            status_code=500,
        )

    html = index_path.read_text(encoding="utf-8")
    return HTMLResponse(html)


# ------------------------------------------------------------------
# CSS file (linked from index.html)
# ------------------------------------------------------------------
@app.get("/styles.css")
async def styles():
    css_path = Path("web") / "styles.css"
    if not css_path.exists():
        return PlainTextResponse(
            "Missing web/styles.css. Create the file in ./web/styles.css",
            status_code=500,
        )

    css = css_path.read_text(encoding="utf-8")
    return Response(content=css, media_type="text/css")


# ------------------------------------------------------------------
# (Optional) quick health check
# ------------------------------------------------------------------
@app.get("/health")
async def health():
    return {"ok": True, "clients": len(clients), "state": STATE}


# ------------------------------------------------------------------
# WebSocket endpoint
# ------------------------------------------------------------------
@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    clients.add(ws)

    # send current state immediately
    await ws.send_text(json.dumps({"type": "state", **STATE}))

    # optional: notify others
    await broadcast({"type": "status", "status": "web_connected"})

    try:
        while True:
            msg = await ws.receive_text()

            # simple keepalive protocol
            if msg.strip().lower() == "ping":
                await ws.send_text(json.dumps({"type": "pong"}))
            else:
                # future UI commands could go here
                await ws.send_text(json.dumps({"type": "log", "msg": f"UI says: {msg}"}))

    except Exception:
        pass
    finally:
        clients.discard(ws)
        await broadcast({"type": "status", "status": "web_disconnected"})
