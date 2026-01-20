from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Set

from fastapi import FastAPI, WebSocket
from fastapi.responses import HTMLResponse, PlainTextResponse

from tcp_server_ecc import STATE, run_tcp_server

app = FastAPI()
clients: Set[WebSocket] = set()


async def broadcast(event: dict):
    dead = []
    data = json.dumps(event)

    # iterate on a snapshot to avoid "set changed size during iteration"
    for ws in list(clients):
        try:
            await ws.send_text(data)
        except Exception:
            dead.append(ws)

    for ws in dead:
        clients.discard(ws)


@app.on_event("startup")
async def startup():
    # Start TCP server in background task
    asyncio.create_task(run_tcp_server(broadcast))
    # optional: log for UI
    await broadcast({"type": "status", "status": "web_server_started"})


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


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    clients.add(ws)

    # send current state immediately
    await ws.send_text(json.dumps({"type": "state", **STATE}))

    # inform all clients that someone connected (optional)
    await broadcast({"type": "status", "status": "web_connected"})

    try:
        while True:
            msg = await ws.receive_text()

            # simple keepalive protocol
            if msg.strip().lower() == "ping":
                await ws.send_text(json.dumps({"type": "pong"}))
            else:
                # if you later add UI commands, handle them here
                await ws.send_text(json.dumps({"type": "log", "msg": f"UI says: {msg}"}))

    except Exception:
        pass
    finally:
        clients.discard(ws)
        await broadcast({"type": "status", "status": "web_disconnected"})
