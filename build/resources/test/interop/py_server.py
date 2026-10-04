#!/usr/bin/env python3
"""Servidor Python mínimo para el test de interoperabilidad.

Arranca un WiFiServer en 127.0.0.1:0 (puerto elegido por el OS) y escribe
el puerto real a stdout (una línea), luego queda a la espera de un cliente.

Al recibir "chat" responde "echo:<texto>".

Uso:
    python3 py_server.py <token>

El script termina cuando:
  - Recibe una línea por stdin (cualquier cosa) → cierra y sale.
  - Es terminado por SIGTERM.
"""

import asyncio
import sys

# Ajusta esta ruta si el paquete phonelink está en otro sitio.
# El test añade PYTHONPATH, así que basta con `import phonelink`.
from phonelink import Peer, WiFiServer


async def main() -> None:
    token = sys.argv[1]
    srv = WiFiServer(token=token, host="127.0.0.1", port=0)
    peer = Peer(srv, heartbeat=0)

    async def on_chat(msg):
        texto = msg.get("payload", {}).get("text")
        await peer.send("chat", {"text": f"echo:{texto}"})

    peer.on("chat", on_chat)
    await peer.start()

    # Puerto real tras start()
    port = srv.bound_port
    print(port, flush=True)

    # Esperar a que el padre diga "stop" por stdin
    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(None, sys.stdin.readline)
    finally:
        await peer.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
