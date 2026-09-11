#!/usr/bin/env python3
"""Laboratorio destructible y aislado de VRRP con dos contenedores reales.

No publica puertos, no usa la red del host y no reutiliza volúmenes ni nombres
de una instalación. El bloque ``finally`` elimina sólo recursos cuyo nombre
incluye el identificador aleatorio creado por esta ejecución.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path


def ejecutar(*argumentos: str, capturar: bool = False, comprobar: bool = True) -> str:
    resultado = subprocess.run(
        list(argumentos), check=False, text=True, capture_output=capturar)
    if comprobar and resultado.returncode != 0:
        salida = "\n".join(x for x in (resultado.stdout, resultado.stderr) if x)
        raise RuntimeError(f"falló {' '.join(argumentos)}\n{salida}".rstrip())
    return (resultado.stdout or "").strip()


def docker(*argumentos: str, capturar: bool = False, comprobar: bool = True) -> str:
    return ejecutar("docker", *argumentos, capturar=capturar, comprobar=comprobar)


def esperar(descripcion: str, prueba, segundos: int = 35) -> None:
    limite = time.monotonic() + segundos
    ultimo = ""
    while time.monotonic() < limite:
        try:
            valor = prueba()
            if valor:
                return
            ultimo = repr(valor)
        except Exception as error:  # el contenedor puede estar arrancando
            ultimo = f"{type(error).__name__}: {error}"
        time.sleep(1)
    raise RuntimeError(f"tiempo agotado esperando {descripcion}; último resultado: {ultimo}")


def escribir_atomico(contenedor: str, contenido: bytes) -> None:
    """Sustituye la configuracion dentro del nodo y conserva su modo POSIX."""
    codigo = r"""
import os
import stat
import sys
import tempfile

ruta = "/datos/keepalived.conf"
contenido = sys.stdin.buffer.read()
estado = os.lstat(ruta)
if not stat.S_ISREG(estado.st_mode) or stat.S_ISLNK(estado.st_mode):
    raise RuntimeError("keepalived.conf no es un fichero regular")
modo = stat.S_IMODE(estado.st_mode)
descriptor, temporal = tempfile.mkstemp(prefix=".keepalived.conf.", dir="/datos")
try:
    os.fchmod(descriptor, modo)
    with os.fdopen(descriptor, "wb") as fichero:
        descriptor = -1
        fichero.write(contenido)
        fichero.flush()
        os.fsync(fichero.fileno())
    os.replace(temporal, ruta)
    temporal = ""
    descriptor_directorio = os.open("/datos", os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor_directorio)
    finally:
        os.close(descriptor_directorio)
    estado_final = os.lstat(ruta)
    if not stat.S_ISREG(estado_final.st_mode) or estado_final.st_mode & 0o111:
        raise RuntimeError("keepalived.conf quedo ejecutable o dejo de ser regular")
    with open(ruta, "rb") as fichero:
        if fichero.read() != contenido:
            raise RuntimeError("keepalived.conf no coincide byte a byte")
finally:
    if descriptor >= 0:
        os.close(descriptor)
    if temporal:
        try:
            os.unlink(temporal)
        except FileNotFoundError:
            pass
"""
    resultado = subprocess.run(
        ["docker", "exec", "-i", contenedor, "python3", "-c", codigo],
        input=contenido,
        capture_output=True,
        check=False,
    )
    if resultado.returncode != 0:
        salida = b"\n".join(
            parte for parte in (resultado.stdout, resultado.stderr) if parte
        ).decode("utf-8", "replace")
        raise RuntimeError(f"fallo la escritura atomica de keepalived.conf\n{salida}".rstrip())


def leer_configuracion(contenedor: str) -> bytes:
    """Lee la configuración por Docker sin abrir el bind root-owned desde el runner."""
    resultado = subprocess.run(
        ["docker", "exec", contenedor, "cat", "/datos/keepalived.conf"],
        capture_output=True,
        check=False,
    )
    if resultado.returncode != 0:
        salida = b"\n".join(
            parte for parte in (resultado.stdout, resultado.stderr) if parte
        ).decode("utf-8", "replace")
        raise RuntimeError(f"fallo la lectura de keepalived.conf\n{salida}".rstrip())
    return resultado.stdout


def cambiar_vrid(contenido: bytes, anterior: int, nuevo: int) -> bytes:
    """Cambia una unica directiva VRID y rechaza una configuracion ambigua."""
    patron = re.compile(
        rb"(?m)^([ \t]*virtual_router_id[ \t]+)"
        + str(anterior).encode("ascii")
        + rb"([ \t]*(?:#[^\r\n]*)?\r?)$"
    )
    cambiado, total = patron.subn(
        lambda coincidencia: (
            coincidencia.group(1)
            + str(nuevo).encode("ascii")
            + coincidencia.group(2)
        ),
        contenido,
    )
    if total != 1:
        raise RuntimeError(
            f"se esperaba una directiva virtual_router_id {anterior}, se encontraron {total}"
        )
    return cambiado


def recargar_keepalived(contenedor: str) -> None:
    """Pide al PID 1 que reenvie HUP a Keepalived, como en produccion."""
    docker("kill", "--signal", "HUP", contenedor)


def cuadro_real(contenedor: str) -> dict:
    """Ejecuta el agregador real del panel dentro de uno de los nodos."""
    codigo = (
        "import json,sys;"
        "sys.path.insert(0,'/opt/panel');"
        "import servidor;"
        "d=json.load(open('/datos/pool.json',encoding='utf-8'));"
        "print(json.dumps(servidor.cuadro(d),sort_keys=True,separators=(',',':')))"
    )
    salida = docker(
        "exec", contenedor, "python3", "-c", codigo,
        capturar=True,
    )
    if not salida:
        raise RuntimeError("servidor.cuadro no produjo salida")
    return json.loads(salida.splitlines()[-1])


def cuadro_declara_portadores(
    contenedor: str, vip: str, portadores: set[str], duplicada: bool,
) -> bool:
    cuadro = cuadro_real(contenedor)
    filas = [fila for fila in cuadro.get("direcciones", []) if fila.get("ip") == vip]
    if len(filas) != 1:
        return False
    fila = filas[0]
    return (
        fila.get("duplicada") is duplicada
        and set(fila.get("portadores") or []) == portadores
    )


def tiene_vip(contenedor: str, vip: str) -> bool:
    salida = docker(
        "exec", contenedor, "ip", "-4", "-o", "addr", "show", "dev", "eth0",
        capturar=True, comprobar=False)
    return f" {vip}/" in salida


def estado_exclusivo(nodo_a: str, nodo_b: str, vip: str, esperado: str) -> bool:
    estado = {nodo_a: tiene_vip(nodo_a, vip), nodo_b: tiene_vip(nodo_b, vip)}
    return estado[esperado] and sum(estado.values()) == 1


def red_libre(prefijo: str) -> tuple[str, ipaddress.IPv4Network]:
    for tercer_octeto in range(247, 219, -1):
        red = ipaddress.ip_network(f"172.31.{tercer_octeto}.0/24")
        nombre = f"{prefijo}-net"
        resultado = subprocess.run(
            ["docker", "network", "create", "--driver", "bridge", "--subnet", str(red), nombre],
            check=False, text=True, capture_output=True)
        if resultado.returncode == 0:
            return nombre, red
    raise RuntimeError("no se encontró una subred /24 libre para el laboratorio")


def preparar_configuracion(
    imagen: str, datos: Path, secretos_dir: Path, nodo: str, nodos: str,
) -> None:
    codigo = (
        "import json,sys;"
        "sys.path.insert(0,'/opt/panel');"
        "import local,plan;"
        "d=json.load(open('/datos/pool.json',encoding='utf-8'));"
        "open('/datos/keepalived.conf','w',encoding='utf-8').write("
        "plan.generar_conf(d,local.YO,local.NODOS,retardo=2))"
    )
    docker(
        "run", "--rm", "--entrypoint", "python3",
        "--mount", f"type=bind,source={datos},target=/datos",
        "--mount", f"type=bind,source={secretos_dir / 'vrrp-auth.txt'},target=/run/secrets/fip_vrrp_auth,readonly",
        "--env", f"FIP_NODO={nodo}", "--env", f"FIP_NODOS={nodos}",
        "--env", "FIP_VIP_PREFIX=24",
        "--env", "FIP_VRRP_AUTH_PASS_FILE=/run/secrets/fip_vrrp_auth",
        imagen, "-c", codigo)


def preparar_permisos_laboratorio(imagen: str, temporal: Path) -> None:
    """Entrega el bind efímero al UID 0 que ejecuta el runtime sin DAC_OVERRIDE."""
    docker(
        "run", "--rm", "--network", "none", "--read-only",
        "--entrypoint", "sh",
        "--mount", f"type=bind,source={temporal},target=/lab",
        imagen, "-eu", "-c",
        "chown -R 0:0 /lab; "
        "chmod 0700 /lab /lab/secrets /lab/data-a /lab/data-b; "
        "find /lab -type f -exec chmod 0600 {} +",
    )


def devolver_permisos_laboratorio(imagen: str, temporal: Path) -> None:
    """Devuelve el árbol al usuario del runner para poder eliminarlo sin sudo."""
    propietario = f"{os.getuid()}:{os.getgid()}"
    docker(
        "run", "--rm", "--network", "none", "--read-only",
        "--entrypoint", "sh", "--env", f"LAB_OWNER={propietario}",
        "--mount", f"type=bind,source={temporal},target=/lab",
        imagen, "-eu", "-c",
        'chown -R "$LAB_OWNER" /lab; chmod -R u+rwX /lab',
    )


def arrancar_nodo(
    imagen: str, nombre: str, ip: str, par: str, red: str, datos: Path,
    secretos_dir: Path, nodo: str, nodos: str,
) -> None:
    docker(
        "run", "--detach", "--name", nombre, "--network", red, "--ip", ip,
        "--init", "--read-only", "--pids-limit", "256", "--cap-drop", "ALL",
        "--cap-add", "NET_ADMIN", "--cap-add", "NET_BROADCAST", "--cap-add", "NET_RAW",
        "--cap-add", "SETGID",
        "--security-opt", "no-new-privileges:true",
        "--tmpfs", "/run:rw,nosuid,noexec,size=32m",
        "--tmpfs", "/tmp:rw,nosuid,noexec,size=32m",
        "--mount", f"type=bind,source={datos},target=/datos",
        "--mount", f"type=bind,source={secretos_dir / 'vrrp-auth.txt'},target=/run/secrets/fip_vrrp_auth,readonly",
        "--mount", f"type=bind,source={secretos_dir / 'session-secret.txt'},target=/run/secrets/fip_session_secret,readonly",
        "--mount", f"type=bind,source={secretos_dir / 'cluster-token.txt'},target=/run/secrets/fip_cluster_token,readonly",
        "--env", "FIP_APP_VERSION=1.0.2", "--env", f"FIP_NODO={nodo}",
        "--env", f"FIP_NODOS={nodos}", "--env", f"FIP_PARES=http://{par}:6060",
        "--env", "FIP_PUERTO=6060", "--env", "FIP_VIP_PREFIX=24",
        "--env", "FIP_DATOS=/datos", "--env", "FIP_CONF=/datos/keepalived.conf",
        "--env", "FIP_RETARDO=2",
        "--env", "FIP_VRRP_AUTH_PASS_FILE=/run/secrets/fip_vrrp_auth",
        "--env", "FIP_SESSION_SECRET_FILE=/run/secrets/fip_session_secret",
        "--env", "FIP_CLUSTER_TOKEN_FILE=/run/secrets/fip_cluster_token", imagen)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", default="floating-ip:1.0.2-hardening-test")
    argumentos = parser.parse_args()

    identificador = uuid.uuid4().hex[:10]
    prefijo = f"fip-vrrp-{identificador}"
    nodo_a, nodo_b = f"{prefijo}-a", f"{prefijo}-b"
    temporal = Path(tempfile.mkdtemp(prefix=f"floating-ip-vrrp-{identificador}-")).resolve()
    raiz_temporal = Path(tempfile.gettempdir()).resolve()
    if raiz_temporal not in temporal.parents or not temporal.name.startswith("floating-ip-vrrp-"):
        raise RuntimeError("la ruta temporal del laboratorio no es segura")

    red_nombre = ""
    try:
        red_nombre, red = red_libre(prefijo)
        ip_a, ip_b, vip = (str(red.network_address + x) for x in (10, 11, 100))
        nodos = f"node-a:{ip_a}:eth0:150,node-b:{ip_b}:eth0:100"

        secretos_dir, datos_a, datos_b = (
            temporal / "secrets", temporal / "data-a", temporal / "data-b")
        for directorio in (secretos_dir, datos_a, datos_b):
            directorio.mkdir()
        (secretos_dir / "vrrp-auth.txt").write_text("LabVRRP7\n", encoding="utf-8")
        (secretos_dir / "session-secret.txt").write_text(
            secrets.token_urlsafe(48) + "\n", encoding="utf-8")
        (secretos_dir / "cluster-token.txt").write_text(
            secrets.token_urlsafe(48) + "\n", encoding="utf-8")

        ahora = datetime.now(timezone.utc).isoformat(timespec="seconds")
        pool = {
            "version": 1, "actualizado": ahora, "dhcp_desde": 200,
            "mantenimiento": [],
            "direcciones": [{
                "ip": vip, "vrid": 77, "estado": "en_uso", "servicio": "panel",
                "descripcion": "Servicio sano del laboratorio VRRP", "puertos": [6060],
                "chequeo": {"puerto": 6060, "ruta": "/api/health"},
                "preferente": "node-a", "notas": "dato efímero de prueba", "creada": ahora,
            }],
            "reclamaciones": {},
        }
        for datos in (datos_a, datos_b):
            (datos / "pool.json").write_text(
                json.dumps(pool, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

        preparar_permisos_laboratorio(argumentos.image, temporal)
        preparar_configuracion(argumentos.image, datos_a, secretos_dir, "node-a", nodos)
        preparar_configuracion(argumentos.image, datos_b, secretos_dir, "node-b", nodos)
        arrancar_nodo(
            argumentos.image, nodo_a, ip_a, ip_b, red_nombre, datos_a, secretos_dir,
            "node-a", nodos)
        arrancar_nodo(
            argumentos.image, nodo_b, ip_b, ip_a, red_nombre, datos_b, secretos_dir,
            "node-b", nodos)

        for contenedor in (nodo_a, nodo_b):
            esperar(
                f"salud HTTP de {contenedor}",
                lambda c=contenedor: docker(
                    "exec", c, "curl", "--fail", "--silent", "http://127.0.0.1:6060/api/health",
                    capturar=True, comprobar=False).startswith("{"))
            esperar(
                f"reconciliación y procesos de {contenedor}",
                lambda c=contenedor: docker(
                    "exec", c, "sh", "-c",
                    "pgrep -x keepalived >/dev/null && "
                    "pgrep -f '/opt/panel/servidor.py' >/dev/null && echo ok",
                    capturar=True, comprobar=False) == "ok",
                segundos=60,
            )

        esperar("VIP exclusiva en node-a", lambda: estado_exclusivo(nodo_a, nodo_b, vip, nodo_a))
        print(f"VIP_INITIAL_OK={vip}@node-a")

        docker("exec", nodo_a, "sh", "-c", "touch /run/floating-ip/drenar/panel")
        esperar("traspaso por drenaje a node-b", lambda: estado_exclusivo(nodo_a, nodo_b, vip, nodo_b))
        print("VIP_DRAIN_FAILOVER_OK=node-b")

        docker("exec", nodo_a, "sh", "-c", "rm /run/floating-ip/drenar/panel")
        esperar("recuperación preemptiva en node-a", lambda: estado_exclusivo(nodo_a, nodo_b, vip, nodo_a))
        print("VIP_PREEMPT_RECOVERY_OK=node-a")

        docker("stop", "--time", "5", nodo_a)
        esperar("traspaso tras caída de node-a", lambda: tiene_vip(nodo_b, vip))
        print("VIP_NODE_FAILURE_OK=node-b")
        print("SECURE_VRRP_LAB_OK")
    except Exception:
        for contenedor in (nodo_a, nodo_b):
            registros = docker("logs", "--tail", "80", contenedor, capturar=True, comprobar=False)
            if registros:
                print(f"--- {contenedor} ---\n{registros}")
        raise
    finally:
        for contenedor in (nodo_a, nodo_b):
            docker("rm", "--force", contenedor, capturar=True, comprobar=False)
        if red_nombre == f"{prefijo}-net":
            docker("network", "rm", red_nombre, capturar=True, comprobar=False)
        if temporal.exists() and raiz_temporal in temporal.parents and temporal.name.startswith("floating-ip-vrrp-"):
            devolver_permisos_laboratorio(argumentos.image, temporal)
            shutil.rmtree(temporal)


if __name__ == "__main__":
    main()
