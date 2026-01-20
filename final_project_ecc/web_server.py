from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Set

from fastapi import FastAPI, WebSocket
from fastapi.responses import HTMLResponse

from tcp_server_ecc import STATE, run_tcp_server

app = FastAPI()
clients: Set[WebSocket] = set()

async def broadcast(event: dict):
    dead = []
    data = json.dumps(event)
    for ws in clients:
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

@app.get("/")
async def root():
    html = (Path("web") / "index.html").read_text(encoding="utf-8")
    return HTMLResponse(html)

@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    clients.add(ws)
    # send current state
    await ws.send_text(json.dumps({"type": "state", **STATE}))
    try:
        while True:
            await ws.receive_text()
    except Exception:
        pass
    finally:
        clients.discard(ws)
