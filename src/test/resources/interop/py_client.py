#!/usr/bin/env python3
"""Cliente Python mínimo para el test de interoperabilidad.

Se conecta a 127.0.0.1:<puerto> con WiFiClient y envía "chat".
Recibe la respuesta y la imprime en stdout (una línea JSON).

Uso:
    python3 py_client.py <puerto> <token>

Termina tras recibir la respuesta o tras 5 s.
"""

import asyncio
import json
import sys

from phonelink import Peer, WiFiClient


async def main() -> None:
    port = int(sys.argv[1])
    token = sys.argv[2]

    cli = WiFiClient("127.0.0.1", token=token, port=port, reconnect=False)
    peer = Peer(cli, heartbeat=0)

    done = asyncio.Event()
    respuesta = {}

    async def on_chat(msg):
        respuesta["text"] = msg.get("payload", {}).get("text")
        done.set()

    peer.on("chat", on_chat)
    await peer.start(timeout=5.0)
    await peer.send("chat", {"text": "hola desde Python"})

    try:
        await asyncio.wait_for(done.wait(), timeout=5.0)
    finally:
        await peer.stop()

    print(json.dumps(respuesta), flush=True)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        print(json.dumps({"error": str(e)}), flush=True)
        sys.exit(1)
