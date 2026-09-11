"""Lo que este nodo puede contar de sí mismo: qué direcciones sostiene, si sus
servicios responden AQUÍ, y si está marcado para drenar.

Cada nodo responde solo por sí mismo y el panel funde las tres respuestas. Es el
mismo reparto que usa la instalación para sus métricas, y por el mismo motivo: hay
cosas que solo se saben desde dentro de la máquina.

No se monta el socket de Docker: convertiría el panel en control del demonio.
El acceso humano usa cuentas y 2FA, y las aplicaciones presentan claves con
permisos limitados. Todo lo que esta capa necesita sale de la tabla de
direcciones del propio nodo y de la declaración del registro.
"""
import os
import ipaddress
import re
# Sólo se invoca /sbin/ip con argumentos constantes y sin shell.
import subprocess  # nosec B404
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, wait

TIEMPO_CHEQUEO = 3
TRABAJADORES_SALUD = 8
PRESUPUESTO_VISTA = 4.0
TTL_SALUD = 5.0
MAX_NODOS = 16
_SERVICIO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_NODO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_INTERFAZ = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")


def _nodos_de_entorno():
    """FIP_NODOS = "nombre:ip:interfaz:prioridad,nombre:ip:interfaz:prioridad".

    Viene del manifiesto vía el despliegue, no se duplica aquí: el reparto de
    nodos tiene un solo sitio donde vivir.
    """
    crudo = os.environ.get("FIP_NODOS", "").strip()
    nodos = []
    for trozo in crudo.split(","):
        trozo = trozo.strip()
        if not trozo:
            continue
        partes = trozo.split(":")
        if len(partes) != 4:
            raise ValueError(
                "cada entrada de FIP_NODOS debe ser nombre:IPv4:interfaz:prioridad")
        nombre, ip, interfaz, prioridad_cruda = partes
        if not _NODO.fullmatch(nombre):
            raise ValueError(f"nombre de nodo no válido en FIP_NODOS: {nombre}")
        try:
            ip = str(ipaddress.IPv4Address(ip))
        except ipaddress.AddressValueError as error:
            raise ValueError(f"IPv4 no válida en FIP_NODOS: {ip}") from error
        if not _INTERFAZ.fullmatch(interfaz):
            raise ValueError(f"interfaz no válida en FIP_NODOS: {interfaz}")
        if not prioridad_cruda.isdigit() or not 1 <= int(prioridad_cruda) <= 254:
            raise ValueError(
                f"prioridad fuera de 1-254 en FIP_NODOS: {prioridad_cruda}")
        if any(n["nombre"] == nombre for n in nodos):
            raise ValueError(f"nodo repetido en FIP_NODOS: {nombre}")
        if any(n["ip"] == ip for n in nodos):
            raise ValueError(f"IPv4 repetida en FIP_NODOS: {ip}")
        prioridad = int(prioridad_cruda)
        if any(n["prioridad"] == prioridad for n in nodos):
            raise ValueError(
                f"prioridad repetida en FIP_NODOS: {prioridad}")
        nodos.append({
            "nombre": nombre,
            "ip": ip,
            "interfaz": interfaz,
            "prioridad": prioridad,
        })
        if len(nodos) > MAX_NODOS:
            raise ValueError(
                f"FIP_NODOS no puede declarar más de {MAX_NODOS} nodos")
    return nodos


# La colocación elegida no se lee del entorno: la decide quien opera el clúster
# y vive únicamente en el registro del panel. Mantenerla también en el
# manifiesto crearía dos fuentes de verdad capaces de divergir.
NODOS = _nodos_de_entorno()
YO = os.environ.get("FIP_NODO", "").strip()
DIR_DRENAR = os.environ.get("FIP_DRENAR", "/run/floating-ip/drenar")
_ejecutor_salud = ThreadPoolExecutor(
    max_workers=TRABAJADORES_SALUD, thread_name_prefix="local-health")
_candado_salud = threading.Lock()
_cache_salud = {}
_futuros_salud = {}


def mi_nodo():
    for n in NODOS:
        if n["nombre"] == YO:
            return n
    return {"nombre": YO, "ip": None, "interfaz": None, "prioridad": 0}


def direcciones_del_sistema():
    """Las IPv4 que este nodo tiene puestas ahora mismo, por interfaz."""
    try:
        # El binario y todos los argumentos son constantes; no interviene entrada externa.
        salida = subprocess.run(  # nosec B603
            ["/sbin/ip", "-4", "addr", "show"],
            capture_output=True, text=True, timeout=5, check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    encontradas = {}
    interfaz = None
    for linea in salida.splitlines():
        cab = re.match(r"^\d+:\s+([^:@]+)[:@]", linea)
        if cab:
            interfaz = cab.group(1).strip()
            continue
        m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", linea)
        if m and interfaz:
            encontradas[m.group(1)] = interfaz
    return encontradas


def drenando(servicio):
    if not isinstance(servicio, str) or not _SERVICIO.fullmatch(servicio):
        return False
    return os.path.exists(os.path.join(DIR_DRENAR, servicio))


def drenajes():
    try:
        return sorted(os.listdir(DIR_DRENAR))
    except OSError:
        return []


def marcar_drenaje(servicio, activo):
    """Poner o quitar la marca de drenaje de un servicio EN ESTE NODO.

    Con la marca puesta, el chequeo de ese servicio falla aquí a propósito;
    keepalived lo ve enfermo y cede la dirección a otro nodo. Es la forma de
    vaciar un servidor para mantenimiento usando el mecanismo que ya existe, sin
    regenerar configuración ni reiniciar nada.

    La marca vive en un tmpfs a propósito: no sobrevive a un reinicio del
    contenedor. Un servidor que se quedara drenado para siempre porque alguien
    se olvidó de quitar la marca es peor avería que la que se quería evitar.
    """
    if not isinstance(servicio, str) or not _SERVICIO.fullmatch(servicio):
        raise ValueError("nombre de servicio no valido para una marca de drenaje")
    os.makedirs(DIR_DRENAR, exist_ok=True)
    ruta = os.path.join(DIR_DRENAR, servicio)
    if activo:
        open(ruta, "w").close()
    else:
        try:
            os.unlink(ruta)
        except FileNotFoundError:
            pass
    return drenando(servicio)


def comprobar(chequeo):
    """¿Responde el servicio EN ESTE NODO? Contra 127.0.0.1, nunca contra la
    dirección flotante: la pregunta es «¿responde aquí?», no «¿responde en algún
    sitio?». Preguntar por la flotante daría siempre que sí, desde todos.
    """
    if not chequeo or not chequeo.get("puerto") or not chequeo.get("ruta"):
        return {"sano": None, "detalle": "sin chequeo declarado", "respuesta_ms": None}
    url = f"http://127.0.0.1:{chequeo['puerto']}{chequeo['ruta']}"
    inicio = time.perf_counter()
    try:
        # URL local construida con esquema fijo, IP loopback y ruta validada.
        with urllib.request.urlopen(url, timeout=TIEMPO_CHEQUEO) as r:  # nosec B310
            return {"sano": 200 <= r.status < 400, "detalle": f"HTTP {r.status}",
                    "respuesta_ms": round((time.perf_counter() - inicio) * 1000, 1)}
    except urllib.error.HTTPError as e:
        return {"sano": False, "detalle": f"HTTP {e.code}",
                "respuesta_ms": round((time.perf_counter() - inicio) * 1000, 1)}
    except Exception as e:  # noqa: BLE001 — cualquier fallo de red es «no responde»
        return {"sano": False, "detalle": type(e).__name__,
                "respuesta_ms": round((time.perf_counter() - inicio) * 1000, 1)}


def _clave_chequeo(chequeo):
    if not chequeo or not chequeo.get("puerto") or not chequeo.get("ruta"):
        return None
    return int(chequeo["puerto"]), chequeo["ruta"]


def _guardar_salud(clave, futuro):
    try:
        resultado = futuro.result()
    except Exception as error:  # pragma: no cover - comprobar ya normaliza fallos.
        resultado = {
            "sano": False, "detalle": type(error).__name__, "respuesta_ms": None}
    with _candado_salud:
        if _futuros_salud.get(clave) is futuro:
            _futuros_salud.pop(clave, None)
        _cache_salud[clave] = (time.monotonic() + TTL_SALUD, dict(resultado))


def _salud_cache_o_futuro(chequeo):
    clave = _clave_chequeo(chequeo)
    if clave is None:
        return clave, {
            "sano": None, "detalle": "sin chequeo declarado", "respuesta_ms": None}
    ahora_monotono = time.monotonic()
    nuevo = False
    with _candado_salud:
        cache = _cache_salud.get(clave)
        if cache and cache[0] > ahora_monotono:
            return clave, dict(cache[1])
        if cache:
            _cache_salud.pop(clave, None)
        futuro = _futuros_salud.get(clave)
        if futuro is None:
            futuro = _ejecutor_salud.submit(comprobar, dict(chequeo))
            _futuros_salud[clave] = futuro
            nuevo = True
    # add_done_callback puede ejecutar sincrónicamente si la tarea ya acabó;
    # se registra fuera del candado para no reentrar desde _guardar_salud.
    if nuevo:
        futuro.add_done_callback(
            lambda terminado, clave_actual=clave:
            _guardar_salud(clave_actual, terminado))
    return clave, futuro


def vista_local(datos_pool):
    """Lo que este nodo responde cuando le preguntan sus pares."""
    puestas = direcciones_del_sistema()
    mio = mi_nodo()
    entradas = [
        d for d in datos_pool.get("direcciones", [])
        if d.get("servicio") and d.get("estado") == "en_uso"
    ]
    salud_por_clave = {}
    futuros = {}
    inicio = time.monotonic()
    for entrada in entradas:
        clave, valor = _salud_cache_o_futuro(entrada.get("chequeo"))
        if hasattr(valor, "result"):
            futuros[clave] = valor
        else:
            salud_por_clave[clave] = valor
    if futuros:
        restante = max(0.0, PRESUPUESTO_VISTA - (time.monotonic() - inicio))
        terminados, _pendientes = wait(set(futuros.values()), timeout=restante)
        for clave, futuro in futuros.items():
            if futuro in terminados:
                salud_por_clave[clave] = dict(futuro.result())
            else:
                salud_por_clave[clave] = {
                    "sano": False,
                    "detalle": "presupuesto de salud agotado",
                    "respuesta_ms": None,
                }

    servicios = {}
    for d in entradas:
        serv = d.get("servicio")
        drenado = drenando(serv)
        salud = salud_por_clave[_clave_chequeo(d.get("chequeo"))]
        servicios[serv] = {
            "ip": d.get("ip"),
            "sostenida_aqui": d.get("ip") in puestas,
            "interfaz": puestas.get(d.get("ip")),
            "drenando": drenado,
            # Con la marca puesta el chequeo falla a propósito: se informa del
            # estado real del servicio y aparte de que está drenado, para no
            # confundir «lo he vaciado yo» con «se ha roto».
            "sano": (False if drenado else salud["sano"]),
            "salud_real": salud["sano"],
            "detalle": ("drenado a mano" if drenado else salud["detalle"]),
            "respuesta_ms": salud["respuesta_ms"],
        }
    return {
        "nodo": mio["nombre"],
        "ip": mio["ip"],
        "interfaz": mio["interfaz"],
        "prioridad": mio["prioridad"],
        "direcciones_puestas": sorted(puestas.keys()),
        "servicios": servicios,
        "drenajes": drenajes(),
    }
