"""Comprueba desde un contenedor vivo todos sus pares firmados y cifrados."""
import json
import os
import sys
import urllib.request

sys.path.insert(0, "/opt/panel")
import configuracion  # noqa: E402
import seguridad  # noqa: E402


nodo = os.environ["FIP_NODO"]
nodos = [
    entrada.split(":")[0]
    for entrada in os.environ.get("FIP_NODOS", "").split(",")
    if entrada
]
protocolo = seguridad.ProtocoloCluster(
    configuracion.secreto("FIP_CLUSTER_TOKEN"), nodo, nodos)
pares = configuracion.urls_pares(os.environ.get("FIP_PARES", ""))

for base in pares:
    ruta = "/api/internal/local"
    peticion = urllib.request.Request(base + ruta)
    for nombre, valor in protocolo.firmar("GET", ruta).items():
        peticion.add_header(nombre, valor)
    with urllib.request.urlopen(peticion, timeout=5) as respuesta:
        sobre = json.loads(respuesta.read().decode())
    vista = protocolo.descifrar(sobre["payload"])
    assert vista.get("nodo") and vista["nodo"] != nodo

print(f"SIGNED_PEERS_OK={len(pares)}")
