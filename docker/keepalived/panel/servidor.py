"""El panel de direcciones flotantes: API, acceso y cara web.

Hay uno por nodo y todos responden el cuadro completo: cada uno conoce lo suyo de
primera mano y pregunta a los demás. Así puedes entrar por cualquiera de los
nodos y no dependes de ninguno — que importa justo el día que se ha caído uno, que
es cuando quieres mirar.

El acceso humano requiere cuenta local y puede protegerse con TOTP. Las
integraciones conservan rutas públicas de estado o usan token API; la
conversación entre nodos va firmada y el estado de cuentas, cifrado.
"""
import errno
import ipaddress
import json
import os
import re
import signal
import socket
import stat
# Sólo se invoca /usr/sbin/keepalived para validar una ruta interna controlada.
import subprocess  # nosec B404
import tempfile
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import local
import plan
import pool as pool_mod
import auth_http
import configuracion
import seguridad
import setup_config

PUERTO = int(os.environ.get("FIP_PUERTO", "6060"))
DIR_DATOS = os.environ.get("FIP_DATOS", "/datos")
DIR_WEB = os.environ.get("FIP_WEB", os.path.join(os.path.dirname(__file__), "web"))
PARES = configuracion.urls_pares(os.environ.get("FIP_PARES", ""))
CONTEXTO_TLS_CLUSTER = configuracion.contexto_tls_cluster()
TIEMPO_PAR = 4
MAX_CUERPO = 1024 * 1024
MAX_CABECERAS = 64 * 1024
MAX_HTTP_EXTERNOS = 24
MAX_HTTP_TOTAL = 32
TIEMPO_CABECERAS = 5.0
TIEMPO_CUERPO = 10.0
CAPACIDAD_POOL_V2 = "pool-causal-v2"
RUTA_POOL_V2 = "/api/internal/v2/pool"
RUTA_REPLICA_POOL_V2 = "/api/internal/v2/pool/replica"
CAPACIDAD_SEGURIDAD_V2 = "security-causal-v2"
RUTA_SEGURIDAD_V2 = "/api/internal/v2/security"
RUTA_REPLICA_SEGURIDAD_V2 = "/api/internal/v2/security/replica"
MARCADOR_LISTO = os.environ.get(
    "FIP_READY_MARKER", "/run/floating-ip/pool-ready")
MARCADOR_BOOTSTRAP_POOL = os.environ.get(
    "FIP_POOL_BOOTSTRAP_MARKER", os.path.join(DIR_DATOS, ".bootstrap-pool"))
MARCADOR_BOOTSTRAP_SEGURIDAD = os.environ.get(
    "FIP_SECURITY_BOOTSTRAP_MARKER",
    os.path.join(DIR_DATOS, ".bootstrap-security"),
)
MARCADOR_PROTOCOLO_V2 = os.environ.get(
    "FIP_PROTOCOL_V2_MARKER",
    os.path.join(DIR_DATOS, ".cluster-protocol-v2"),
)
MARCADOR_DEPLOY_FREEZE = os.environ.get(
    "FIP_DEPLOY_FREEZE_MARKER",
    os.path.join(DIR_DATOS, ".deploy-freeze"),
)
CONTENIDO_BOOTSTRAP = b"fresh-install-v1\n"
CONTENIDO_DEPLOY_FREEZE = b"deploy-freeze-v1\n"
REINTENTO_ARRANQUE = max(
    0.2, float(os.environ.get("FIP_STARTUP_RETRY_SECONDS", "2")))
INTERVALO_RECONCILIACION = max(
    1.0, float(os.environ.get("FIP_RECONCILE_SECONDS", "15")))


def version_info():
    """Identificador unico del codigo que esta sirviendo este proceso."""
    return {"version": os.environ.get("FIP_APP_VERSION", "").strip() or "1.0.7"}


SESSION_SECRET = configuracion.secreto("FIP_SESSION_SECRET")
CLUSTER_TOKEN = configuracion.secreto("FIP_CLUSTER_TOKEN")


def validar_arranque():
    """Falla antes de servir si la instalación está incompleta o es ambigua."""
    if not 1 <= PUERTO <= 65535:
        raise RuntimeError("FIP_PUERTO debe estar entre 1 y 65535")
    if len(local.NODOS) < 2:
        raise RuntimeError("FIP_NODOS debe declarar al menos dos nodos")
    if len(local.NODOS) > local.MAX_NODOS:
        raise RuntimeError(
            f"FIP_NODOS no puede declarar más de {local.MAX_NODOS} nodos")
    nombres = {n["nombre"] for n in local.NODOS}
    if not local.YO or local.YO not in nombres:
        raise RuntimeError("FIP_NODO no coincide con ningún nodo de FIP_NODOS")
    prioridades = [nodo["prioridad"] for nodo in local.NODOS]
    if len(prioridades) != len(set(prioridades)):
        raise RuntimeError("FIP_NODOS debe asignar una prioridad distinta a cada nodo")
    if len(PARES) != len(local.NODOS) - 1:
        raise RuntimeError(
            "FIP_PARES debe contener exactamente un panel por cada otro nodo")
    if len(PARES) > configuracion.MAX_PARES:
        raise RuntimeError(
            f"FIP_PARES no puede contener más de {configuracion.MAX_PARES} paneles")
    configuracion.validar_secreto_largo("FIP_SESSION_SECRET", SESSION_SECRET)
    configuracion.validar_secreto_largo("FIP_CLUSTER_TOKEN", CLUSTER_TOKEN)
    if SESSION_SECRET == CLUSTER_TOKEN:
        raise RuntimeError(
            "FIP_SESSION_SECRET y FIP_CLUSTER_TOKEN deben ser distintos")
    _validar_ruta_marker(
        MARCADOR_BOOTSTRAP_POOL, ".bootstrap-pool",
        "FIP_POOL_BOOTSTRAP_MARKER")
    _validar_ruta_marker(
        MARCADOR_BOOTSTRAP_SEGURIDAD, ".bootstrap-security",
        "FIP_SECURITY_BOOTSTRAP_MARKER")
    _validar_ruta_marker(
        MARCADOR_PROTOCOLO_V2, ".cluster-protocol-v2",
        "FIP_PROTOCOL_V2_MARKER")
    _validar_ruta_marker(
        MARCADOR_DEPLOY_FREEZE, ".deploy-freeze",
        "FIP_DEPLOY_FREEZE_MARKER")
    _validar_retardo_vuelta(RETARDO_VUELTA)
    plan._vip_prefijo()
    plan._auth_pass()

# Las mutaciones originadas por este panel abarcan preflight, escritura,
# réplica y aplicación. Las réplicas internas no toman este candado: el reloj
# vectorial del propio Pool decide si llegaron antes, después o en conflicto.
_candado_mutacion = threading.RLock()
_candado_configuracion = threading.Lock()
PROTECCION = seguridad.ProteccionCuenta(
    SESSION_SECRET,
    os.environ.get("FIP_PASSWORD_MIN_LENGTH", "12"),
    os.environ.get("FIP_TOTP_ISSUER", "Keepalived"),
)
SESIONES = seguridad.Sesiones(
    SESSION_SECRET,
    os.environ.get("FIP_SESSION_HOURS", "12"),
)
CUENTAS = seguridad.AlmacenSeguridad(
    os.path.join(DIR_DATOS, "security.json"), local.YO or "local")
PROTOCOLO = seguridad.ProtocoloCluster(
    CLUSTER_TOKEN, local.YO,
    [n["nombre"] for n in local.NODOS],
)
_candado_seguridad = threading.RLock()
_candado_protocolo_v2 = threading.Lock()
_observaciones_protocolo_v2 = {"pool": None, "security": None}

TIPOS = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
}


# ── conversación entre nodos ────────────────────────────────────────────
def _json_objeto_estricto(crudo, etiqueta):
    """Decodifica un objeto JSON sin duplicados ni constantes no finitas."""
    try:
        texto = crudo.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{etiqueta} no está codificada en UTF-8") from error
    try:
        valor = json.loads(
            texto or "{}",
            object_pairs_hook=pool_mod._objeto_json_sin_duplicados,
            parse_constant=lambda constante: (_ for _ in ()).throw(
                ValueError(f"constante JSON no válida: {constante}")),
        )
    except (TypeError, ValueError, RecursionError) as error:
        raise ValueError(f"{etiqueta} no contiene JSON estricto: {error}") from error
    if not isinstance(valor, dict):
        raise ValueError(f"{etiqueta} debe tener un objeto JSON en la raíz")
    return valor


def _socket_respuesta(respuesta):
    """Localiza, si existe, el socket de HTTPResponse para acotar cada lectura."""
    candidatos = [
        getattr(respuesta, "_sock", None),
        getattr(getattr(respuesta, "fp", None), "_sock", None),
        getattr(getattr(getattr(respuesta, "fp", None), "raw", None),
                "_sock", None),
    ]
    return next(
        (valor for valor in candidatos if hasattr(valor, "settimeout")), None)


def _leer_respuesta_interna(respuesta, tiempo):
    """Lee como máximo MAX_CUERPO y aplica un plazo total al cuerpo remoto."""
    cabeceras = getattr(respuesta, "headers", {})
    if cabeceras is None:
        valores_longitud = []
    elif hasattr(cabeceras, "get_all"):
        valores_longitud = cabeceras.get_all("Content-Length") or []
    else:
        valor = cabeceras.get("Content-Length")
        valores_longitud = [] if valor is None else [valor]
    if len(valores_longitud) > 1:
        raise ValueError("La respuesta interna contiene varios Content-Length")
    declarado = valores_longitud[0] if valores_longitud else None
    esperado = None
    if declarado is not None:
        if (not isinstance(declarado, str)
                or not re.fullmatch(r"0|[1-9][0-9]*", declarado)):
            raise ValueError("Content-Length interno no válido")
        esperado = int(declarado)
        if esperado < 0 or esperado > MAX_CUERPO:
            raise ValueError("La respuesta interna supera el máximo permitido")
        if esperado == 0:
            return b""

    plazo = time.monotonic() + max(0.0, float(tiempo))
    partes = []
    total = 0
    lector = getattr(respuesta, "read1", None) or respuesta.read
    sock = _socket_respuesta(respuesta)
    while esperado is None or total < esperado:
        restante = plazo - time.monotonic()
        if restante <= 0:
            raise TimeoutError("El cuerpo de la respuesta interna agotó su plazo")
        if sock is not None:
            sock.settimeout(max(0.001, restante))
        limite = min(64 * 1024, MAX_CUERPO + 1 - total)
        if esperado is not None:
            limite = min(limite, esperado - total)
        trozo = lector(limite)
        if not trozo:
            break
        if not isinstance(trozo, (bytes, bytearray)):
            raise ValueError("La respuesta interna no devolvió bytes")
        partes.append(bytes(trozo))
        total += len(trozo)
        if total > MAX_CUERPO:
            raise ValueError("La respuesta interna supera el máximo permitido")

    if esperado is not None and total != esperado:
        raise ValueError("La respuesta interna llegó incompleta")
    return b"".join(partes)


def _pedir_interno(base, ruta, datos=None, metodo=None, tiempo=TIEMPO_PAR):
    cuerpo = json.dumps(datos, ensure_ascii=False, separators=(",", ":")).encode() \
        if datos is not None else None
    metodo = metodo or ("POST" if cuerpo is not None else "GET")
    url = f"{base}{ruta}"
    pet = urllib.request.Request(url, data=cuerpo, method=metodo)
    for nombre, valor in PROTOCOLO.firmar(metodo, ruta, cuerpo or b"").items():
        pet.add_header(nombre, valor)
    if cuerpo:
        pet.add_header("Content-Type", "application/json")
    # configuracion.urls_pares limita base de forma estricta a http(s).
    with urllib.request.urlopen(  # nosec B310
        pet, timeout=tiempo, context=CONTEXTO_TLS_CLUSTER
    ) as r:
        return _json_objeto_estricto(
            _leer_respuesta_interna(r, tiempo), "La respuesta interna")


def _vista_no_alcanzable(nodo, error="PeerUnavailable"):
    """Estado estable de un nodo que no ha aportado una vista válida."""
    if isinstance(nodo, dict):
        nombre = nodo["nombre"]
        topologia = {
            clave: nodo[clave]
            for clave in ("ip", "interfaz", "prioridad")
            if clave in nodo
        }
    else:
        nombre = nodo
        topologia = {}
    return {
        "nodo": nombre,
        **topologia,
        "base": None,
        "alcanzable": False,
        "error": error,
        "servicios": {},
        "direcciones_puestas": [],
    }


def _vista_par_valida(vista):
    """Esquema mínimo para que una vista remota no rompa el cuadro global."""
    servicios = vista.get("servicios")
    direcciones = vista.get("direcciones_puestas")
    return (
        isinstance(vista.get("nodo"), str)
        and isinstance(servicios, dict)
        and all(isinstance(valor, dict) for valor in servicios.values())
        and isinstance(direcciones, list)
        and all(isinstance(ip, str) for ip in direcciones)
    )


def vistas_de_todos(datos_pool):
    """Devuelve siempre una entrada por nodo usando su identidad autenticada.

    Los endpoints son transporte, no identidad. Por eso un endpoint caído no
    aparece como una clave inventada: cada nodo lógico parte como no alcanzable
    y sólo una respuesta autenticada con una identidad configurada puede ocupar su
    lugar. Dos respuestas que reclamen el mismo nodo fallan de forma cerrada.
    """
    nombres = [nodo["nombre"] for nodo in local.NODOS]
    vistas = {
        nodo["nombre"]: _vista_no_alcanzable(nodo)
        for nodo in local.NODOS
        if nodo["nombre"] != local.YO
    }
    vistas[local.YO] = local.vista_local(datos_pool)

    def traer(base):
        try:
            respuesta = _pedir_interno(base, "/api/internal/local")
            vista = PROTOCOLO.descifrar(respuesta.get("payload"))
            if not isinstance(vista, dict) or not _vista_par_valida(vista):
                raise TypeError("la vista del par no es un objeto")
            return base, vista
        except Exception:  # noqa: BLE001
            return base, None

    if PARES:
        candidatos = {
            nombre: [] for nombre in nombres if nombre != local.YO
        }
        with ThreadPoolExecutor(max_workers=len(PARES)) as ex:
            for base, vista in ex.map(traer, PARES):
                if vista is None:
                    continue
                nombre = vista.get("nodo")
                if isinstance(nombre, str) and nombre in candidatos:
                    candidatos[nombre].append((base, vista))

        for nombre, respuestas in candidatos.items():
            if len(respuestas) == 1:
                base, vista = respuestas[0]
                vista = dict(vista)
                vista["alcanzable"] = True
                vista["base"] = base
                vistas[nombre] = vista
            elif len(respuestas) > 1:
                nodo = next(n for n in local.NODOS if n["nombre"] == nombre)
                vistas[nombre] = _vista_no_alcanzable(
                    nodo, "PeerIdentityDuplicate")
    vistas[local.YO]["alcanzable"] = True
    return vistas


def _quorum_pool():
    return len(local.NODOS) // 2 + 1


def _escritor_cluster():
    return local.NODOS[0]["nombre"] if local.NODOS else ""


def _cluster_v2_completo(capacidades):
    configurados = {nodo["nombre"] for nodo in local.NODOS}
    descubiertos = set(capacidades) | {local.YO}
    return descubiertos == configurados


def _exigir_cluster_v2_pool(capacidades):
    try:
        marcador = _marker_protocolo_v2_valido()
    except Exception as error:
        raise _error_revision(
            "La evidencia durable del protocolo causal v2 no es segura",
            "CLUSTER_PROTOCOL_MARKER_INVALID",
        ) from error
    if marcador:
        return
    if _cluster_v2_completo(capacidades):
        _observar_protocolo_v2("pool", capacidades)
        return
    raise _error_revision(
        "Hay nodos que aún no demostraron el protocolo causal v2; las "
        "mutaciones quedan congeladas hasta completar la actualización",
        "CLUSTER_UPGRADE_IN_PROGRESS",
    )


def _exigir_escritor_pool():
    escritor = _escritor_cluster()
    if not escritor or local.YO != escritor:
        raise _error_revision(
            f"Las mutaciones del pool deben enviarse al nodo escritor «{escritor}»",
            "POOL_WRITER_REQUIRED",
        )
    return escritor


def _error_revision(mensaje, codigo):
    return pool_mod.ErrorRevisionPool(mensaje, codigo)


def _validar_ruta_marker(ruta, nombre, variable):
    """Los testigos sólo pueden ser los ficheros reservados de FIP_DATOS."""
    directorio = os.path.abspath(DIR_DATOS)
    esperado = os.path.abspath(os.path.join(directorio, nombre))
    if (not isinstance(ruta, str)
            or os.path.normcase(os.path.abspath(ruta)) != os.path.normcase(esperado)):
        raise RuntimeError(
            f"{variable} debe apuntar exactamente a {esperado}; no se permiten "
            "rutas externas ni nombres alternativos")


def _leer_marker_seguro(ruta, contenido_esperado, etiqueta):
    """Lee un testigo exacto sin seguir enlaces ni aceptar hardlinks."""
    previo = os.lstat(ruta)
    propietario = os.geteuid() if hasattr(os, "geteuid") else previo.st_uid
    if (not stat.S_ISREG(previo.st_mode) or previo.st_nlink != 1
            or previo.st_uid != propietario
            or stat.S_IMODE(previo.st_mode) != 0o600):
        raise PermissionError(
            f"el testigo {etiqueta} debe ser regular, 0600, del proceso y sin enlaces")
    banderas = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        banderas |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        banderas |= os.O_NOFOLLOW
    fd = os.open(ruta, banderas)
    try:
        abierto = os.fstat(fd)
        if ((abierto.st_dev, abierto.st_ino) != (previo.st_dev, previo.st_ino)
                or not stat.S_ISREG(abierto.st_mode) or abierto.st_nlink != 1
                or abierto.st_uid != propietario
                or stat.S_IMODE(abierto.st_mode) != 0o600):
            raise PermissionError(
                f"el testigo {etiqueta} cambió durante su apertura")
        with os.fdopen(fd, "rb") as fichero:
            fd = -1
            contenido = fichero.read(len(contenido_esperado) + 1)
    finally:
        if fd >= 0:
            os.close(fd)
    if contenido != contenido_esperado:
        raise ValueError(f"contenido del testigo {etiqueta} no válido")
    return previo.st_dev, previo.st_ino


def _leer_marker_bootstrap(ruta):
    """Valida el testigo one-shot de instalación fresca."""
    return _leer_marker_seguro(ruta, CONTENIDO_BOOTSTRAP, "bootstrap")


def _leer_marker_deploy_freeze():
    """Valida la barrera operativa creada exclusivamente por root/deploy."""
    previo = os.lstat(MARCADOR_DEPLOY_FREEZE)
    if previo.st_uid != 0:
        raise PermissionError("el marker deploy-freeze debe pertenecer a root")
    return _leer_marker_seguro(
        MARCADOR_DEPLOY_FREEZE, CONTENIDO_DEPLOY_FREEZE, "deploy-freeze")


def _ruta_externa_mutante(metodo, ruta):
    """Distingue escrituras de usuario de réplica/anti-entropía internas."""
    if AUTH_HTTP._ruta_seguridad_mutante(metodo, ruta):
        return True
    if metodo == "POST":
        return ruta in {
            "/api/auth/session", "/api/claims", "/api/pool",
            "/api/mantenimiento", "/api/settings",
        }
    if metodo == "PUT":
        return bool(re.fullmatch(
            r"/api/pool/\d+\.\d+\.\d+\.\d+/servidor", ruta))
    if metodo == "PATCH":
        return bool(re.fullmatch(r"/api/pool/\d+\.\d+\.\d+\.\d+", ruta))
    if metodo == "DELETE":
        return bool(
            re.fullmatch(r"/api/claims/[A-Za-z0-9][A-Za-z0-9._:-]{7,127}", ruta)
            or re.fullmatch(r"/api/pool/\d+\.\d+\.\d+\.\d+", ruta)
        )
    return False


def _exigir_deploy_no_congelado():
    if not os.path.lexists(MARCADOR_DEPLOY_FREEZE):
        return
    try:
        _leer_marker_deploy_freeze()
    except Exception as error:
        raise _error_revision(
            "La barrera de despliegue existe pero no es un marker seguro",
            "DEPLOY_FREEZE_INVALID",
        ) from error
    raise _error_revision(
        "El despliegue ha congelado temporalmente las mutaciones externas",
        "DEPLOY_FROZEN",
    )


def _exigir_mutacion_no_congelada(metodo, ruta):
    if _ruta_externa_mutante(metodo, ruta):
        _exigir_deploy_no_congelado()


def _exigir_deploy_no_congelado_seguridad():
    try:
        _exigir_deploy_no_congelado()
    except pool_mod.ErrorRevisionPool as error:
        raise _error_seguridad(str(error), error.codigo, 503) from error


def _contenido_marker_protocolo_v2():
    """Ata la evidencia v2 a esta topología y a ambas familias causales."""
    contenido = {
        "capabilities": [CAPACIDAD_POOL_V2, CAPACIDAD_SEGURIDAD_V2],
        "nodos": [nodo["nombre"] for nodo in local.NODOS],
        "schema": 1,
    }
    return (json.dumps(
        contenido, ensure_ascii=False, sort_keys=True,
        separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def _marker_protocolo_v2_valido():
    """Distingue ausencia de evidencia de una evidencia presente insegura."""
    if not os.path.lexists(MARCADOR_PROTOCOLO_V2):
        return False
    _leer_marker_seguro(
        MARCADOR_PROTOCOLO_V2, _contenido_marker_protocolo_v2(),
        "cluster-protocol-v2")
    return True


def _publicar_marker_protocolo_v2():
    """Publica evidencia durable sólo si el destino ausente sigue siendo seguro."""
    contenido = _contenido_marker_protocolo_v2()
    directorio = os.path.dirname(MARCADOR_PROTOCOLO_V2) or "."
    pool_mod._comprobar_directorio(directorio)
    if os.path.lexists(MARCADOR_PROTOCOLO_V2):
        _leer_marker_seguro(
            MARCADOR_PROTOCOLO_V2, contenido, "cluster-protocol-v2")
        return
    fd, temporal = tempfile.mkstemp(
        dir=directorio, prefix=".cluster-protocol-v2.", suffix=".tmp")
    reemplazado = False
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as fichero:
            fd = -1
            fichero.write(contenido)
            fichero.flush()
            os.fsync(fichero.fileno())
        if os.path.lexists(MARCADOR_PROTOCOLO_V2):
            _leer_marker_seguro(
                MARCADOR_PROTOCOLO_V2, contenido, "cluster-protocol-v2")
            return
        os.replace(temporal, MARCADOR_PROTOCOLO_V2)
        reemplazado = True
        _sincronizar_directorio_de(MARCADOR_PROTOCOLO_V2)
    finally:
        if fd >= 0:
            os.close(fd)
        if not reemplazado:
            try:
                os.unlink(temporal)
            except FileNotFoundError:
                pass


def _observar_protocolo_v2(tipo, capacidades):
    """Sella la cohorte sólo con pruebas N/N recientes de pool y acceso."""
    if tipo not in _observaciones_protocolo_v2:
        raise ValueError("familia de protocolo causal desconocida")
    instante = time.monotonic()
    completa = _cluster_v2_completo(capacidades)
    with _candado_protocolo_v2:
        _observaciones_protocolo_v2[tipo] = instante if completa else None
        if os.path.lexists(MARCADOR_PROTOCOLO_V2):
            _leer_marker_seguro(
                MARCADOR_PROTOCOLO_V2, _contenido_marker_protocolo_v2(),
                "cluster-protocol-v2")
            return True
        ventana = max(15.0, (TIEMPO_PAR * 4) + 2.0)
        instantes = list(_observaciones_protocolo_v2.values())
        if (all(isinstance(valor, (int, float)) for valor in instantes)
                and max(instantes) - min(instantes) <= ventana
                and instante - min(instantes) <= ventana):
            _publicar_marker_protocolo_v2()
            return True
    return False


def _sincronizar_directorio_de(ruta):
    directorio = os.path.dirname(ruta) or "."
    pool_mod._comprobar_directorio(directorio)
    if not hasattr(os, "O_DIRECTORY"):
        return
    banderas = os.O_RDONLY | os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        banderas |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        banderas |= os.O_NOFOLLOW
    try:
        fd = os.open(directorio, banderas)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as error:
        no_soportado = {
            errno.EINVAL,
            getattr(errno, "ENOTSUP", errno.EINVAL),
            getattr(errno, "EOPNOTSUPP", errno.EINVAL),
            getattr(errno, "ENOSYS", errno.EINVAL),
        }
        if error.errno not in no_soportado:
            raise


def _exigir_bootstrap_pool():
    try:
        _leer_marker_bootstrap(MARCADOR_BOOTSTRAP_POOL)
    except Exception as error:
        raise _error_revision(
            "El pool está ausente; hace falta autorización one-shot de "
            "instalación fresca",
            "POOL_BOOTSTRAP_REQUIRED",
        ) from error


def _exigir_bootstrap_seguridad():
    try:
        _leer_marker_bootstrap(MARCADOR_BOOTSTRAP_SEGURIDAD)
    except Exception as error:
        raise _error_seguridad(
            "El registro de acceso está abierto; hace falta autorización "
            "one-shot de instalación fresca",
            "AUTH_BOOTSTRAP_REQUIRED", 503,
        ) from error


def _consumir_bootstrap_pool():
    if not os.path.lexists(MARCADOR_BOOTSTRAP_POOL):
        return
    try:
        _leer_marker_bootstrap(MARCADOR_BOOTSTRAP_POOL)
        os.unlink(MARCADOR_BOOTSTRAP_POOL)
        _sincronizar_directorio_de(MARCADOR_BOOTSTRAP_POOL)
    except Exception as error:
        raise _error_revision(
            "El pool convergió, pero no se pudo confirmar el consumo del "
            "testigo bootstrap",
            "POOL_BOOTSTRAP_MARKER_UNCERTAIN",
        ) from error


def _consumir_bootstrap_seguridad():
    if not os.path.lexists(MARCADOR_BOOTSTRAP_SEGURIDAD):
        return
    try:
        _leer_marker_bootstrap(MARCADOR_BOOTSTRAP_SEGURIDAD)
        os.unlink(MARCADOR_BOOTSTRAP_SEGURIDAD)
        _sincronizar_directorio_de(MARCADOR_BOOTSTRAP_SEGURIDAD)
    except Exception as error:
        raise _error_seguridad(
            "El acceso convergió, pero no se pudo confirmar el consumo del "
            "testigo bootstrap",
            "AUTH_BOOTSTRAP_MARKER_UNCERTAIN", 503,
        ) from error


def _validar_snapshot_cluster(snapshot, permitir_legacy=False):
    """Valida causalidad e identidades antes de confiar en datos de red."""
    pool_mod.Pool.huella(snapshot)
    _validar_pool_runtime(snapshot)
    revision = snapshot.get("revision") or {}
    reloj = revision.get("clock") or {}
    autor = revision.get("author")
    if not reloj:
        if (permitir_legacy and autor == "legacy"
                and isinstance(revision.get("legacy_base"), str)):
            return snapshot
        raise _error_revision(
            "Una réplica de red no puede introducir un estado legacy",
            "POOL_REPLICA_LEGACY_REJECTED",
        )
    escritor = _escritor_cluster()
    if autor != escritor or set(reloj) != {escritor}:
        raise _error_revision(
            "La revisión del pool no pertenece al escritor lógico del clúster",
            "POOL_REPLICA_IDENTITY_INVALID",
        )
    return snapshot


def _validar_vip_runtime(valor):
    """Rechaza direcciones no-host y colisiones con la gestión del clúster."""
    try:
        direccion = ipaddress.IPv4Address(valor)
    except (ipaddress.AddressValueError, TypeError) as error:
        raise pool_mod.ErrorPool(f"La VIP {valor!r} no es una IPv4 válida") from error
    red = ipaddress.IPv4Network(f"{direccion}/24", strict=False)
    if (direccion.is_unspecified or direccion.is_loopback
            or direccion.is_multicast or direccion.is_link_local
            or direccion.is_reserved
            or direccion in {red.network_address, red.broadcast_address}):
        raise pool_mod.ErrorPool(
            f"La VIP {direccion} no es una dirección unicast de host válida /24")
    gestion = {nodo.get("ip") for nodo in local.NODOS}
    if str(direccion) in gestion:
        raise pool_mod.ErrorPool(
            f"La VIP {direccion} coincide con la dirección de gestión de un nodo")
    return str(direccion)


def _validar_pool_runtime(snapshot):
    for entrada in snapshot.get("direcciones") or []:
        if isinstance(entrada, dict):
            _validar_vip_runtime(entrada.get("ip"))
    return snapshot


POOL = pool_mod.Pool(
    os.path.join(DIR_DATOS, "pool.json"), autor=local.YO,
    validador=_validar_pool_runtime)


def _descifrar_snapshot(respuesta, permitir_legacy=True):
    mensaje = PROTOCOLO.descifrar((respuesta or {}).get("payload"))
    if not isinstance(mensaje, dict):
        raise ValueError("el mensaje interno no es un objeto")
    nodo = mensaje.get("nodo")
    snapshot = mensaje.get("snapshot")
    inicializado = mensaje.get("initialized")
    if (mensaje.get("capability") != CAPACIDAD_POOL_V2
            or not isinstance(nodo, str) or not isinstance(snapshot, dict)
            or not isinstance(inicializado, bool)):
        raise ValueError(
            "el mensaje interno no demuestra la capacidad causal v2")
    _validar_snapshot_cluster(snapshot, permitir_legacy=permitir_legacy)
    return nodo, snapshot, inicializado


def _estado_pool_local():
    """Lee contenido y existencia como una sola observación en este proceso."""
    return POOL.leer_con_estado()


def _consultar_snapshots_pool():
    """Obtiene un snapshot por identidad lógica; endpoints duplicados no votan."""
    configurados = {nodo["nombre"] for nodo in local.NODOS}
    agrupados = {nombre: [] for nombre in configurados if nombre != local.YO}
    errores = 0

    def consultar(base):
        try:
            respuesta = _pedir_interno(base, RUTA_POOL_V2)
            nodo, snapshot, inicializado = _descifrar_snapshot(
                respuesta, permitir_legacy=True)
            return base, nodo, snapshot, inicializado, None
        except Exception as error:  # noqa: BLE001
            return base, None, None, None, type(error).__name__

    if PARES:
        with ThreadPoolExecutor(max_workers=len(PARES)) as ejecutor:
            for base, nodo, snapshot, inicializado, error in ejecutor.map(
                    consultar, PARES):
                if error or nodo not in agrupados:
                    errores += 1
                    continue
                agrupados[nodo].append((base, snapshot, inicializado))

    snapshot_local, inicializado_local = _estado_pool_local()
    respuestas = {local.YO: {
        "snapshot": snapshot_local, "initialized": inicializado_local}}
    capacidades = {}
    duplicadas = []
    for nodo, candidatos in agrupados.items():
        if len(candidatos) == 1:
            base, snapshot, inicializado = candidatos[0]
            respuestas[nodo] = {
                "snapshot": snapshot, "initialized": inicializado}
            capacidades[nodo] = base
        elif len(candidatos) > 1:
            duplicadas.append(nodo)
    return {
        "respuestas": respuestas,
        "snapshots": {
            nodo: valor["snapshot"] for nodo, valor in respuestas.items()
            if valor["initialized"]
        },
        "capacidades": capacidades,
        "identidades": sorted(respuestas),
        "duplicadas": sorted(duplicadas),
        "errores": errores,
        "quorum": _quorum_pool(),
    }


def _propagar(datos, capacidades, exigir_quorum=True):
    """Replica cifrado y cuenta ACK únicos por identidad lógica, nunca por URL."""
    huella = pool_mod.Pool.huella(datos)
    sobre = PROTOCOLO.cifrar({
        "capability": CAPACIDAD_POOL_V2,
        "nodo": local.YO,
        "snapshot": datos,
    })
    configurados = {nodo["nombre"] for nodo in local.NODOS}
    confirmados = [local.YO]
    errores = 0

    def enviar(destino):
        esperado, base = destino
        try:
            respuesta = _pedir_interno(
                base, RUTA_REPLICA_POOL_V2, {"payload": sobre}, "POST")
            ack = PROTOCOLO.descifrar((respuesta or {}).get("payload"))
            if (not isinstance(ack, dict) or ack.get("estado") != "ok"
                    or ack.get("capability") != CAPACIDAD_POOL_V2
                    or ack.get("nodo") != esperado):
                raise ValueError("ACK de réplica no válido")
            if ack.get("huella") != huella:
                raise ValueError("ACK para otro snapshot")
            return esperado, None
        except Exception as error:  # noqa: BLE001
            return esperado, type(error).__name__

    destinos = sorted((nodo, base) for nodo, base in capacidades.items()
                      if nodo in configurados and nodo != local.YO)
    if destinos:
        with ThreadPoolExecutor(max_workers=len(destinos)) as ejecutor:
            for nodo, error in ejecutor.map(enviar, destinos):
                if error:
                    errores += 1
                    continue
                confirmados.append(nodo)
    resultado = {
        "ok": len(confirmados) >= _quorum_pool(),
        "complete": len(confirmados) == len(configurados),
        "acknowledged": len(confirmados),
        "quorum": _quorum_pool(),
        "nodos": sorted(confirmados),
        "errores": errores,
    }
    if exigir_quorum and not resultado["ok"]:
        raise _error_revision(
            "No hay quorum de identidades lógicas para confirmar el pool",
            "POOL_QUORUM_UNAVAILABLE",
        )
    return resultado


def reconciliar_pool(aplicar_configuracion=False):
    """Converge al único snapshot causal dominante con quorum de identidades."""
    consulta = _consultar_snapshots_pool()
    try:
        _observar_protocolo_v2("pool", consulta["capacidades"])
    except Exception as error:
        raise _error_revision(
            "La evidencia durable del protocolo causal v2 no es segura",
            "CLUSTER_PROTOCOL_MARKER_INVALID",
        ) from error
    if len(consulta["respuestas"]) < consulta["quorum"]:
        raise _error_revision(
            "No hay quorum de identidades lógicas para reconciliar el pool",
            "POOL_QUORUM_UNAVAILABLE",
        )
    presentes = [
        valor["snapshot"] for valor in consulta["respuestas"].values()
        if valor["initialized"]
    ]
    escritor = _escritor_cluster()
    if presentes and len(presentes) < consulta["quorum"]:
        # Única excepción segura: un fresh install pudo caer después del
        # replace causal inicial y antes de replicarlo/consumir el marker. El
        # snapshot debe ser exactamente el vacío {writer:1}; el marker intacto
        # autoriza reanudar, no cualquier estado minoritario.
        reanudar_bootstrap = (
            local.YO == escritor
            and all(
                pool_mod.Pool.es_bootstrap_inicial(valor, escritor)
                or pool_mod.Pool.es_bootstrap_legacy(valor)
                for valor in presentes)
            and len({
                (valor.get("revision") or {}).get("legacy_base")
                for valor in presentes
            }) == 1
        )
        if reanudar_bootstrap:
            _exigir_bootstrap_pool()
        else:
            raise _error_revision(
                "No hay quorum de estados materializados para reconciliar el pool",
                "POOL_QUORUM_UNAVAILABLE",
            )
    # Un disco reemplazado no aporta una rama vacía. Si todos los miembros
    # responsivos son nuevos, sólo el escritor materializa el vacío sintético.
    candidatos = presentes or [POOL.leer()]
    ganador = pool_mod.Pool.seleccionar_dominante(
        candidatos)
    _validar_pool_runtime(ganador)
    revision = ganador.get("revision") or {}
    if not (revision.get("clock") or {}):
        # Sólo la ausencia total exige el testigo de instalación fresca. Un
        # quorum de ficheros legacy ya materializados es evidencia persistente
        # suficiente y se migra conservando legacy_base.
        if local.YO != escritor:
            raise _error_revision(
                "El coordinador todavía no ha inicializado el pool",
                "POOL_BOOTSTRAP_PENDING",
            )
        if not presentes:
            _exigir_bootstrap_pool()
        ganador = POOL.inicializar_desde_candidato(ganador)
    else:
        _validar_snapshot_cluster(ganador)
        POOL.aplicar_replica(ganador)
        ganador = POOL.leer()

    propagacion = _propagar(
        ganador, consulta["capacidades"], exigir_quorum=True)
    if pool_mod.Pool.huella(POOL.leer()) != pool_mod.Pool.huella(ganador):
        raise _error_revision(
            "El pool cambió durante la reconciliación; se reintentará",
            "POOL_RECONCILIATION_RACE",
        )
    _consumir_bootstrap_pool()
    aplicado = aplicar(ganador) if aplicar_configuracion else None
    return {
        "snapshot": ganador,
        "identidades": consulta["identidades"],
        "capacidades": consulta["capacidades"],
        "quorum": consulta["quorum"],
        "propagacion": propagacion,
        "aplicado": aplicado,
    }


def _error_seguridad(mensaje, codigo, http=409):
    return seguridad.ErrorAcceso(mensaje, codigo, http)


def _exigir_cluster_v2_seguridad(capacidades):
    try:
        marcador = _marker_protocolo_v2_valido()
    except Exception as error:
        raise _error_seguridad(
            "La evidencia durable del protocolo causal v2 no es segura",
            "CLUSTER_PROTOCOL_MARKER_INVALID", 503,
        ) from error
    if marcador:
        return
    if _cluster_v2_completo(capacidades):
        _observar_protocolo_v2("security", capacidades)
        return
    raise _error_seguridad(
        "Hay nodos que aún no demostraron security causal v2; las mutaciones "
        "de acceso quedan congeladas hasta completar la actualización",
        "CLUSTER_UPGRADE_IN_PROGRESS", 503,
    )


def _validar_snapshot_seguridad_cluster(snapshot, permitir_legacy=False):
    """Limita el historial causal al único escritor lógico configurado."""
    CUENTAS.huella(snapshot)
    revision = snapshot.get("revision") or {}
    reloj = revision.get("clock") or {}
    if not reloj:
        if (permitir_legacy and revision.get("author") == "legacy"
                and isinstance(revision.get("legacy_base"), str)):
            return snapshot
        raise _error_seguridad(
            "Una réplica de acceso no puede introducir un estado legacy",
            "AUTH_REPLICA_LEGACY_REJECTED",
        )
    escritor = _escritor_cluster()
    if revision.get("author") != escritor or set(reloj) != {escritor}:
        raise _error_seguridad(
            "La revisión de acceso no pertenece al escritor lógico del clúster",
            "AUTH_REPLICA_IDENTITY_INVALID",
        )
    return snapshot


def _es_bootstrap_seguridad_inicial(snapshot, escritor):
    """Reconoce sólo el registro vacío causal que autoriza fresh-install."""
    if not isinstance(snapshot, dict):
        return False
    revision = snapshot.get("revision") or {}
    vacio = CUENTAS._vacio()
    return (
        snapshot.get("schema") == 1
        and snapshot.get("users") == []
        and snapshot.get("api_keys", []) == []
        and revision.get("clock") == {escritor: 1}
        and revision.get("author") == escritor
        and revision.get("legacy_base")
        == (vacio.get("revision") or {}).get("legacy_base")
    )


def _es_bootstrap_seguridad_legacy(snapshot):
    if not isinstance(snapshot, dict):
        return False
    revision = snapshot.get("revision") or {}
    vacio = CUENTAS._vacio()
    return (
        snapshot.get("schema") == 1
        and snapshot.get("users") == []
        and snapshot.get("api_keys", []) == []
        and revision.get("clock") == {}
        and revision.get("author") == "legacy"
        and revision.get("legacy_base")
        == (vacio.get("revision") or {}).get("legacy_base")
    )


def _descifrar_snapshot_seguridad(respuesta):
    mensaje = PROTOCOLO.descifrar((respuesta or {}).get("payload"))
    if not isinstance(mensaje, dict):
        raise ValueError("el mensaje de acceso interno no es un objeto")
    nodo = mensaje.get("nodo")
    snapshot = mensaje.get("snapshot")
    inicializado = mensaje.get("initialized")
    if (mensaje.get("capability") != CAPACIDAD_SEGURIDAD_V2
            or not isinstance(nodo, str) or not isinstance(snapshot, dict)
            or not isinstance(inicializado, bool)):
        raise ValueError(
            "el mensaje interno no demuestra la capacidad de acceso v2")
    _validar_snapshot_seguridad_cluster(snapshot, permitir_legacy=True)
    return nodo, snapshot, inicializado


def _estado_seguridad_local():
    """Evita publicar `initialized` y snapshot de instantes distintos."""
    return CUENTAS.leer_con_estado()


def _consultar_snapshots_seguridad():
    """Descubre peers v2 y separa ausencia real de un estado vacío."""
    configurados = {nodo["nombre"] for nodo in local.NODOS}
    agrupados = {nombre: [] for nombre in configurados if nombre != local.YO}
    errores = 0

    def consultar(base):
        try:
            respuesta = _pedir_interno(base, RUTA_SEGURIDAD_V2)
            nodo, snapshot, inicializado = _descifrar_snapshot_seguridad(
                respuesta)
            return base, nodo, snapshot, inicializado, None
        except Exception as error:  # noqa: BLE001
            return base, None, None, None, type(error).__name__

    if PARES:
        with ThreadPoolExecutor(max_workers=len(PARES)) as ejecutor:
            for base, nodo, snapshot, inicializado, error in ejecutor.map(
                    consultar, PARES):
                if error or nodo not in agrupados:
                    errores += 1
                    continue
                agrupados[nodo].append((base, snapshot, inicializado))

    snapshot_local, inicializado_local = _estado_seguridad_local()
    respuestas = {local.YO: {
        "snapshot": snapshot_local, "initialized": inicializado_local}}
    capacidades = {}
    duplicadas = []
    for nodo, candidatos in agrupados.items():
        if len(candidatos) == 1:
            base, snapshot, inicializado = candidatos[0]
            respuestas[nodo] = {
                "snapshot": snapshot, "initialized": inicializado}
            capacidades[nodo] = base
        elif len(candidatos) > 1:
            duplicadas.append(nodo)
    return {
        "respuestas": respuestas,
        "capacidades": capacidades,
        "identidades": sorted(respuestas),
        "duplicadas": sorted(duplicadas),
        "errores": errores,
        "quorum": _quorum_pool(),
    }


def _propagar_seguridad(snapshot, capacidades, exigir_quorum=True):
    """Replica sólo a endpoints que demostraron security-causal-v2 por GET."""
    _validar_snapshot_seguridad_cluster(snapshot, permitir_legacy=False)
    huella = CUENTAS.huella(snapshot)
    sobre = PROTOCOLO.cifrar({
        "capability": CAPACIDAD_SEGURIDAD_V2,
        "nodo": local.YO,
        "snapshot": snapshot,
    })
    configurados = {nodo["nombre"] for nodo in local.NODOS}
    confirmados = [local.YO]
    errores = 0

    def enviar(destino):
        esperado, base = destino
        try:
            respuesta = _pedir_interno(
                base, RUTA_REPLICA_SEGURIDAD_V2,
                {"payload": sobre}, "POST")
            ack = PROTOCOLO.descifrar((respuesta or {}).get("payload"))
            if (not isinstance(ack, dict) or ack.get("estado") != "ok"
                    or ack.get("capability") != CAPACIDAD_SEGURIDAD_V2
                    or ack.get("nodo") != esperado or ack.get("huella") != huella):
                raise ValueError("ACK de acceso no válido")
            return esperado, None
        except Exception as error:  # noqa: BLE001
            return esperado, type(error).__name__

    destinos = sorted((nodo, base) for nodo, base in capacidades.items()
                      if nodo in configurados and nodo != local.YO)
    if destinos:
        with ThreadPoolExecutor(max_workers=len(destinos)) as ejecutor:
            for nodo, error in ejecutor.map(enviar, destinos):
                if error:
                    errores += 1
                else:
                    confirmados.append(nodo)
    resultado = {
        "ok": len(confirmados) >= _quorum_pool(),
        "complete": len(confirmados) == len(configurados),
        "acknowledged": len(confirmados),
        "quorum": _quorum_pool(),
        "nodos": sorted(confirmados),
        "errores": errores,
    }
    if exigir_quorum and not resultado["ok"]:
        raise _error_seguridad(
            "No hay quorum de identidades lógicas para confirmar el acceso",
            "AUTH_QUORUM_UNAVAILABLE", 503)
    return resultado


def _reconciliar_seguridad_bloqueado():
    """Converge credenciales sin tratar un disco nuevo como una rama vacía."""
    with _candado_seguridad:
        consulta = _consultar_snapshots_seguridad()
        try:
            _observar_protocolo_v2("security", consulta["capacidades"])
        except Exception as error:
            raise _error_seguridad(
                "La evidencia durable del protocolo causal v2 no es segura",
                "CLUSTER_PROTOCOL_MARKER_INVALID", 503,
            ) from error
        if len(consulta["respuestas"]) < consulta["quorum"]:
            raise _error_seguridad(
                "No hay quorum de identidades lógicas para reconciliar el acceso",
                "AUTH_QUORUM_UNAVAILABLE", 503)
        presentes = [
            valor["snapshot"] for valor in consulta["respuestas"].values()
            if valor["initialized"]
        ]
        escritor = _escritor_cluster()
        if presentes and len(presentes) < consulta["quorum"]:
            reanudar_bootstrap = (
                local.YO == escritor
                and all(
                    _es_bootstrap_seguridad_inicial(valor, escritor)
                    or _es_bootstrap_seguridad_legacy(valor)
                    for valor in presentes)
                and len({
                    (valor.get("revision") or {}).get("legacy_base")
                    for valor in presentes
                }) == 1
            )
            if reanudar_bootstrap:
                _exigir_bootstrap_seguridad()
            else:
                raise _error_seguridad(
                    "No hay quorum de estados materializados para reconciliar el acceso",
                    "AUTH_QUORUM_UNAVAILABLE", 503)
        # Si todos los nodos responsivos son nuevos, sus vacíos sintéticos son
        # equivalentes; sólo el coordinador los materializa. Si existe al menos
        # un fichero real, los ausentes no participan en la elección.
        candidatos = presentes or [CUENTAS.leer()]
        ganador = CUENTAS.seleccionar_dominante(candidatos)
        revision = ganador.get("revision") or {}
        # El testigo autoriza exclusivamente crear estado donde no existe
        # ningún security.json materializado. Una vez hay un vacío vectorial
        # confirmado, el registro inicial permanece abierto por ese estado, no
        # por la presencia continuada del testigo.
        if not presentes:
            if local.YO != escritor:
                raise _error_seguridad(
                    "El escritor todavía no ha inicializado el estado de acceso",
                    "AUTH_BOOTSTRAP_PENDING", 503)
            _exigir_bootstrap_seguridad()
        if not (revision.get("clock") or {}):
            if local.YO != escritor:
                raise _error_seguridad(
                    "El escritor todavía no ha inicializado el estado de acceso",
                    "AUTH_BOOTSTRAP_PENDING", 503)
            ganador = CUENTAS.inicializar_desde_candidato(
                ganador, actor="system")
        else:
            _validar_snapshot_seguridad_cluster(ganador)
            CUENTAS.aplicar_replica(ganador)
            ganador = CUENTAS.leer()

        if local.YO == escritor:
            propagacion = _propagar_seguridad(
                ganador, consulta["capacidades"], exigir_quorum=True)
        else:
            # Un no-writer converge por GET y aplicación local. Nunca hace POST:
            # dos workers cruzados no pueden sostener su barrera auth esperando
            # el endpoint de réplica del otro.
            propagacion = {
                "ok": True,
                "complete": False,
                "acknowledged": 1,
                "quorum": consulta["quorum"],
                "nodos": [local.YO],
                "errores": 0,
                "skipped": "non-writer",
            }
        if CUENTAS.huella(CUENTAS.leer()) != CUENTAS.huella(ganador):
            raise _error_seguridad(
                "El estado de acceso cambió durante la reconciliación",
                "AUTH_RECONCILIATION_RACE", 409)
        # Cada nodo puede tener su propio marker de fresh-install. Sólo se
        # consume tras adoptar una revisión causal del writer con quorum.
        if (ganador.get("revision") or {}).get("clock"):
            _consumir_bootstrap_seguridad()
        return {
            "snapshot": ganador,
            "identidades": consulta["identidades"],
            "capacidades": consulta["capacidades"],
            "quorum": consulta["quorum"],
            "propagacion": propagacion,
        }


def reconciliar_seguridad():
    # Orden global: ControlAcceso -> candado de reconciliación -> almacén.
    with AUTH_HTTP.bloquear_estado_seguridad():
        return _reconciliar_seguridad_bloqueado()


def preflight_mutacion_seguridad():
    _exigir_deploy_no_congelado_seguridad()
    escritor = _escritor_cluster()
    if not escritor or local.YO != escritor:
        raise _error_seguridad(
            f"Las mutaciones de acceso deben enviarse al nodo escritor «{escritor}»",
            "AUTH_WRITER_REQUIRED", 409)
    resultado = reconciliar_seguridad()
    _exigir_cluster_v2_seguridad(resultado["capacidades"])
    # El marker puede aparecer mientras se consultaban peers. Esta segunda
    # lectura queda inmediatamente antes de que ControlAcceso invoque almacén.
    _exigir_deploy_no_congelado_seguridad()
    return resultado


def _replicar_seguridad_bloqueado(snapshot):
    """Confirma una escritura ya persistida o declara resultado incierto."""
    try:
        with _candado_seguridad:
            _validar_snapshot_seguridad_cluster(snapshot)
            consulta = _consultar_snapshots_seguridad()
            if len(consulta["respuestas"]) < consulta["quorum"]:
                raise _error_seguridad(
                    "No hay quorum para confirmar el acceso",
                    "AUTH_QUORUM_UNAVAILABLE", 503)
            presentes = [
                valor["snapshot"]
                for valor in consulta["respuestas"].values()
                if valor["initialized"]
            ]
            ganador = CUENTAS.seleccionar_dominante(presentes)
            if CUENTAS.huella(ganador) != CUENTAS.huella(snapshot):
                raise _error_seguridad(
                    "La mutación fue superada antes de confirmarse",
                    "AUTH_MUTATION_SUPERSEDED", 409)
            resultado = _propagar_seguridad(
                snapshot, consulta["capacidades"], exigir_quorum=True)
            if (snapshot.get("revision") or {}).get("clock"):
                _consumir_bootstrap_seguridad()
            return resultado
    except seguridad.ErrorAcceso as error:
        if error.codigo in {
                "AUTH_COMMIT_UNCERTAIN",
                "AUTH_BOOTSTRAP_MARKER_UNCERTAIN",
        }:
            raise
        raise _error_seguridad(
            "La revisión de acceso quedó persistida localmente, pero no se pudo "
            f"confirmar ({error.codigo}); consulta el estado antes de reintentar",
            "AUTH_COMMIT_UNCERTAIN", 503) from error


def replicar_seguridad(snapshot):
    with AUTH_HTTP.bloquear_estado_seguridad():
        return _replicar_seguridad_bloqueado(snapshot)


AUTH_HTTP = auth_http.ControlAcceso(
    CUENTAS, PROTECCION, SESIONES, reconciliar_seguridad, replicar_seguridad,
    preflight_mutacion=preflight_mutacion_seguridad)


# ── cálculo del cuadro ──────────────────────────────────────────────────
def cuadro(datos_pool):
    """Cada dirección con su portador real y la salud en todos los nodos."""
    vistas = vistas_de_todos(datos_pool)
    orden = [n["nombre"] for n in local.NODOS] or sorted(vistas)
    filas = []

    for d in datos_pool.get("direcciones", []):
        serv = d.get("servicio")
        fila = dict(d)
        fila["portador"] = None
        fila["nodos"] = {}
        for nombre in orden:
            v = vistas.get(nombre)
            if not v:
                continue
            if not v.get("alcanzable"):
                fila["nodos"][nombre] = {"alcanzable": False}
                continue
            s = (v.get("servicios") or {}).get(serv or "", {})
            puesta = d.get("ip") in (v.get("direcciones_puestas") or [])
            fila["nodos"][nombre] = {
                "alcanzable": True,
                "sostenida": puesta,
                "sano": s.get("sano"),
                "drenando": s.get("drenando", False),
                "detalle": s.get("detalle"),
                "respuesta_ms": s.get("respuesta_ms"),
                "prioridad": v.get("prioridad"),
            }
        # Dos nodos con la misma dirección son un split-brain: ambos contestan
        # al ARP y el switch decide de forma imprevisible dónde entrega el
        # tráfico. Se conserva la lista completa y no se presenta uno de ellos
        # como portador singular cuando la propiedad es ambigua.
        fila["portadores"] = [n for n, v in fila["nodos"].items() if v.get("sostenida")]
        fila["duplicada"] = len(fila["portadores"]) > 1
        fila["portador"] = (
            fila["portadores"][0] if len(fila["portadores"]) == 1 else None
        )

        # El servidor donde descansa esta dirección sale SOLO del registro, que
        # es donde queda lo que alguien haya elegido en la pantalla. Si nadie ha
        # elegido nada, no hay preferente y se dice; antes se rellenaba con una
        # variable de arranque y la pantalla acababa enseñando un servidor
        # distinto del que se estaba aplicando de verdad.
        fila["preferente"] = d.get("preferente")
        fila["en_su_sitio"] = (fila["preferente"] is None) or (fila["portador"] == fila["preferente"])

        # Quién la recogería si el portador se fuera: el de mayor prioridad,
        # entre los demás, que esté sano. Es lo que convierte una parada por
        # mantenimiento en algo que haces sabiendo qué va a pasar.
        fila["posibles_sucesores"] = []
        fila["sin_red"] = False
        candidatos = []
        if d.get("estado") == "en_uso":
            portadores = set(fila["portadores"])
            candidatos = [n for n in orden
                          if n not in portadores
                          and n not in (datos_pool.get("mantenimiento") or [])
                          and fila["nodos"].get(n, {}).get("alcanzable")
                          and fila["nodos"][n].get("sano") is True]
            fila["posibles_sucesores"] = candidatos
            fila["sin_red"] = not candidatos
        filas.append(fila)

    return {"yo": local.YO, "direcciones": filas, "vistas": vistas, "orden_nodos": orden,
            "mantenimiento": list(datos_pool.get("mantenimiento") or []),
            "asignado": reparto_previsto(datos_pool), "version": version_info()}


def resumen_nodos(datos_pool):
    """Por nodo: qué sostiene y qué pasaría si lo paras."""
    c = cuadro(datos_pool)
    salida = []
    en_servicio = [n for n in c["orden_nodos"]
                   if n not in set(c.get("mantenimiento") or [])]
    for nombre in c["orden_nodos"]:
        v = c["vistas"].get(nombre, {})
        sostiene, consecuencias = [], []
        for f in c["direcciones"]:
            if nombre not in (f.get("portadores") or []):
                continue
            sostiene.append(f["ip"])
            estado_local = (f.get("nodos") or {}).get(nombre, {})
            consecuencias.append({
                "ip": f["ip"],
                "servicio": f.get("servicio"),
                "posibles_sucesores": f.get("posibles_sucesores", []),
                "sin_red": f.get("sin_red", False),
                "sano": estado_local.get("sano"),
                "detalle": estado_local.get("detalle"),
                "respuesta_ms": estado_local.get("respuesta_ms"),
            })
        salida.append({
            "nodo": nombre,
            "ip": v.get("ip"),
            "prioridad": v.get("prioridad"),
            "alcanzable": v.get("alcanzable", False),
            "sostiene": sostiene,
            "si_lo_paras": consecuencias,
            "seguro_parar": all(not x["sin_red"] for x in consecuencias),
            "ultimo_en_servicio": nombre in en_servicio and len(en_servicio) == 1,
            "drenajes": v.get("drenajes", []),
        })
    return salida


def riesgos_mantenimiento_pendientes(seguridad, aceptadas):
    """Direcciones sin respaldo cuyo riesgo no fue aceptado por su IP."""
    aceptadas = set(aceptadas or [])
    return [x for x in (seguridad or {}).get("si_lo_paras", [])
            if x.get("sin_red") and x.get("ip") not in aceptadas]


# ── aplicar: llevar el registro a la realidad ───────────────────────────
#
# El panel manda sobre la colocacion. Cuando cambias el servidor de referencia
# de una direccion o pones un servidor en mantenimiento, se regenera la
# configuracion de keepalived y se le pide que la relea. Comprobado: recargar
# NO suelta las direcciones que ya estan puestas.
#
# Cada nodo genera SU configuracion a partir del mismo registro. El reparto es
# determinista, asi que todos llegan a la misma conclusion sin negociar.
RUTA_CONF = os.path.join(DIR_DATOS, "keepalived.conf")


def _validar_retardo_vuelta(valor):
    if (isinstance(valor, bool) or not isinstance(valor, int)
            or not 0 <= valor <= 1000):
        raise RuntimeError("FIP_RETARDO debe ser un entero entre 0 y 1000")
    return valor


def _retardo_vuelta_entorno():
    crudo = os.environ.get("FIP_RETARDO", "45")
    if not re.fullmatch(r"0|[1-9][0-9]*", crudo):
        raise RuntimeError(
            "FIP_RETARDO debe ser decimal canónico entre 0 y 1000")
    return _validar_retardo_vuelta(int(crudo))


RETARDO_VUELTA = _retardo_vuelta_entorno()
_config_recarga_pendiente = False
_ultimo_error_aplicacion = None
_candado_aplicacion = threading.RLock()


def _pid_keepalived():
    for entrada in os.listdir("/proc"):
        if not entrada.isdigit():
            continue
        try:
            with open(f"/proc/{entrada}/comm", "r") as f:
                if f.read().strip() == "keepalived":
                    return int(entrada)
        except OSError:
            continue
    return None


def _crear_temporal_config(texto):
    """Crea un candidato aleatorio 0600 dentro de un directorio 0700."""
    directorio = os.path.dirname(RUTA_CONF) or "."
    pool_mod._comprobar_directorio(directorio)
    fd, temporal = tempfile.mkstemp(
        prefix=".keepalived.", suffix=".tmp", dir=directorio)
    try:
        pool_mod._normalizar_descriptor(fd, temporal)
        with os.fdopen(fd, "w", encoding="utf-8") as fichero:
            fd = -1
            fichero.write(texto)
            fichero.flush()
            os.fsync(fichero.fileno())
        return temporal
    except Exception:
        try:
            os.unlink(temporal)
        except OSError:
            pass
        raise
    finally:
        if fd >= 0:
            os.close(fd)


def _validar_archivo_config(temporal):
    """Pide a keepalived validar exactamente el inode que se instalaría."""
    try:
        r = subprocess.run(  # nosec B603
            ["/usr/sbin/keepalived", "-t", "-f", temporal],
                           capture_output=True, text=True, timeout=15)
        salida = (r.stdout or "") + (r.stderr or "")
        malo = [l for l in salida.splitlines()
                if "error" in l.lower() or "unknown keyword" in l.lower()]
        return (r.returncode == 0 and not malo), "\n".join(malo[:5])
    except Exception as e:  # noqa: BLE001
        return False, f"{type(e).__name__}: {e}"


def _config_valida(texto):
    """Compatibilidad para validaciones aisladas sin publicar el candidato."""
    temporal = _crear_temporal_config(texto)
    try:
        return _validar_archivo_config(temporal)
    finally:
        try:
            os.unlink(temporal)
        except OSError:
            pass


def _leer_config_actual():
    """Lee el secreto sin seguir symlinks/FIFO ni aceptar hardlinks."""
    try:
        fd = pool_mod._abrir_regular_seguro(RUTA_CONF, os.O_RDONLY)
    except FileNotFoundError:
        return ""
    try:
        with os.fdopen(fd, "r", encoding="utf-8") as fichero:
            fd = -1
            return fichero.read(MAX_CUERPO + 1)
    finally:
        if fd >= 0:
            os.close(fd)


def _comprobar_destino_config():
    """Revalida tipo, inode, enlaces y permisos inmediatamente antes del rename."""
    try:
        fd = pool_mod._abrir_regular_seguro(RUTA_CONF, os.O_RDONLY)
    except FileNotFoundError:
        return
    os.close(fd)


def _sincronizar_directorio_config():
    _sincronizar_directorio_de(RUTA_CONF)


def _recargar_keepalived(resultado):
    pid = _pid_keepalived()
    if pid:
        try:
            os.kill(pid, signal.SIGHUP)
        except OSError as error:
            raise _error_revision(
                "La configuración ya es durable, pero no se pudo confirmar su "
                "recarga; el worker volverá a intentarlo",
                "POOL_CONFIG_RELOAD_UNCERTAIN",
            ) from error
        resultado["recargado"] = True
    else:
        # En el arranque seguro keepalived leerá este fichero confirmado justo
        # después de que entrypoint observe readiness.
        resultado["pendiente_arranque"] = True


def _aplicar_configuracion(datos_pool):
    """Regenera la configuracion de ESTE nodo y sincroniza el mantenimiento."""
    global _config_recarga_pendiente
    resultado = {"nodo": local.YO, "recargado": False, "mantenimiento": False}

    # 1) Modo mantenimiento: si este servidor lo esta, se le vacia entero
    #    haciendo fallar la comprobacion de todos sus servicios. Es lo que
    #    garantiza que no sostenga nada aunque el resto se caiga.
    en_mant = local.YO in (datos_pool.get("mantenimiento") or [])
    resultado["mantenimiento"] = en_mant
    servicios = [d.get("servicio") for d in datos_pool.get("direcciones", [])
                 if d.get("estado") == "en_uso" and d.get("servicio")]
    drenajes_deseados = set(servicios) if en_mant else set()
    drenajes_actuales = set(local.drenajes())
    # Entrar en drain es seguro incluso si la configuración posterior falla:
    # reduce anuncios. Salir de drain (incluido un servicio eliminado) espera
    # a que config+reload estén confirmados para no reactivar una VIP obsoleta.
    for servicio in sorted(drenajes_deseados - drenajes_actuales):
        local.marcar_drenaje(servicio, True)

    def confirmar_salida_drenaje():
        for servicio in sorted(drenajes_actuales - drenajes_deseados):
            local.marcar_drenaje(servicio, False)

    # 2) La configuracion.
    if not local.NODOS:
        resultado["error"] = "sin tabla de nodos (FIP_NODOS)"
        return resultado
    try:
        texto = plan.generar_conf(datos_pool, local.YO, local.NODOS, RETARDO_VUELTA)
    except ValueError as e:
        resultado["error"] = str(e)
        return resultado
    temporal = _crear_temporal_config(texto)
    try:
        ok, detalle = _validar_archivo_config(temporal)
        if not ok:
            resultado["error"] = (
                "la configuracion generada no es valida: " + detalle)
            return resultado

        anterior = _leer_config_actual()
        if anterior.strip() == texto.strip():
            if not _config_recarga_pendiente:
                resultado["sin_cambios"] = True
                confirmar_salida_drenaje()
                return resultado
            # Un rename anterior fue visible pero el fsync del directorio no se
            # confirmó. Se reintenta antes de permitir cualquier SIGHUP.
            try:
                _sincronizar_directorio_config()
            except OSError as error:
                raise _error_revision(
                    "La configuración puede estar visible, pero su persistencia "
                    "local sigue sin confirmarse",
                    "POOL_CONFIG_COMMIT_UNCERTAIN",
                ) from error
            _recargar_keepalived(resultado)
            _config_recarga_pendiente = False
            confirmar_salida_drenaje()
            return resultado

        _comprobar_destino_config()
        os.replace(temporal, RUTA_CONF)
        temporal = None
        _config_recarga_pendiente = True
        try:
            _sincronizar_directorio_config()
        except OSError as error:
            # El fichero nuevo puede ser visible: no se revierte ni se envía
            # SIGHUP. La siguiente vuelta reintenta la confirmación.
            raise _error_revision(
                "La configuración puede estar visible, pero no se pudo confirmar "
                "su persistencia local",
                "POOL_CONFIG_COMMIT_UNCERTAIN",
            ) from error
        _recargar_keepalived(resultado)
        _config_recarga_pendiente = False
        confirmar_salida_drenaje()
        return resultado
    finally:
        if temporal:
            try:
                os.unlink(temporal)
            except OSError:
                pass


def aplicar(datos_pool):
    """Aplica o falla con un código estable; nunca devuelve un falso éxito."""
    global _ultimo_error_aplicacion
    with _candado_aplicacion:
        try:
            resultado = _aplicar_configuracion(datos_pool)
            if resultado.get("error"):
                raise _error_revision(
                    "El pool está confirmado, pero su configuración local queda "
                    f"pendiente: {resultado['error']}",
                    "POOL_APPLY_PENDING",
                )
        except pool_mod.ErrorRevisionPool as error:
            _ultimo_error_aplicacion = error.codigo
            raise
        except (OSError, ValueError, pool_mod.ErrorPool) as error:
            pendiente = _error_revision(
                "El pool está confirmado, pero no se pudo aplicar su configuración "
                f"local ({type(error).__name__}); el worker volverá a intentarlo",
                "POOL_APPLY_PENDING",
            )
            _ultimo_error_aplicacion = pendiente.codigo
            raise pendiente from error
        _ultimo_error_aplicacion = None
        return resultado


def aplicar_y_propagar(datos, capacidades):
    """Confirma la réplica por quorum antes de aplicar la mutación local."""
    try:
        pares = _propagar(datos, capacidades, exigir_quorum=True)
    except pool_mod.ErrorRevisionPool as error:
        if error.codigo != "POOL_QUORUM_UNAVAILABLE":
            raise
        # No hay rollback seguro sin consenso: la escritura local ya tiene una
        # revisión causal. Se distingue del preflight fallido para que quien
        # llama consulte el pool antes de decidir si reintenta.
        raise _error_revision(
            "La revisión quedó persistida localmente, pero no se pudo confirmar "
            "por quorum; consulta el pool antes de reintentar",
            "POOL_COMMIT_UNCERTAIN",
        ) from error
    if pool_mod.Pool.huella(POOL.leer()) != pool_mod.Pool.huella(datos):
        raise _error_revision(
            "La mutación fue superada por otra revisión antes de aplicarse",
            "POOL_MUTATION_SUPERSEDED",
        )
    return {"local": aplicar(datos), "pares": pares}


def _esta_listo():
    return os.path.isfile(MARCADOR_LISTO)


def _retirar_marcador_listo():
    try:
        os.unlink(MARCADOR_LISTO)
    except FileNotFoundError:
        pass


def _degradar_readiness_pool(detener_keepalived=False):
    """Retira readiness; si disco/config divergen, deja de anunciar VIP."""
    _retirar_marcador_listo()
    if not detener_keepalived:
        return
    pid = _pid_keepalived()
    if pid:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass


def _publicar_marcador_listo(snapshot):
    """Publica readiness mediante fsync + rename; nunca deja un parcial."""
    directorio = os.path.dirname(MARCADOR_LISTO) or "."
    os.makedirs(directorio, exist_ok=True)
    fd, temporal = tempfile.mkstemp(dir=directorio, suffix=".ready.tmp")
    publicado = False
    try:
        if os.name != "nt" and hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fichero:
            json.dump({
                "nodo": local.YO,
                "huella": pool_mod.Pool.huella(snapshot),
            }, fichero, ensure_ascii=False, sort_keys=True)
            fichero.write("\n")
            fichero.flush()
            os.fsync(fichero.fileno())
        os.replace(temporal, MARCADOR_LISTO)
        publicado = True
        if hasattr(os, "O_DIRECTORY"):
            try:
                fd_dir = os.open(directorio, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(fd_dir)
                finally:
                    os.close(fd_dir)
            except OSError as error:
                no_soportado = {
                    errno.EBADF, errno.EINVAL,
                    getattr(errno, "ENOTSUP", errno.EINVAL),
                    getattr(errno, "EOPNOTSUPP", errno.EINVAL),
                }
                if error.errno not in no_soportado:
                    raise
    except Exception:
        try:
            os.unlink(MARCADOR_LISTO if publicado else temporal)
        except OSError:
            pass
        raise


def _trabajador_arranque(detener):
    """Arranque seguro y anti-entropía periódica de pool y acceso."""
    preparado = _esta_listo()
    while not detener.is_set():
        try:
            with _candado_mutacion:
                resultado = reconciliar_pool(aplicar_configuracion=True)
                aplicado = resultado.get("aplicado") or {}
                if aplicado.get("error"):
                    raise RuntimeError(aplicado["error"])
                if not preparado:
                    _publicar_marcador_listo(resultado["snapshot"])
                    preparado = True
            if preparado:
                print(
                    "  pool reconciliado: "
                    f"quorum={resultado['quorum']} "
                    f"nodos={len(resultado['identidades'])}",
                    flush=True,
                )
        except Exception as error:  # noqa: BLE001
            codigo_error = getattr(error, "codigo", type(error).__name__)
            estaba_preparado = preparado
            if estaba_preparado:
                _degradar_readiness_pool(detener_keepalived=codigo_error in {
                    "POOL_APPLY_PENDING",
                    "POOL_CONFIG_COMMIT_UNCERTAIN",
                    "POOL_CONFIG_RELOAD_UNCERTAIN",
                    "POOL_LOCAL_COMMIT_UNCERTAIN",
                })
                preparado = False
            print(
                ("  pool degradado; se conserva la configuración vigente: "
                 if estaba_preparado else "  pool aún no preparado: ")
                +
                f"{codigo_error}",
                flush=True,
            )
        try:
            acceso = reconciliar_seguridad()
            print(
                "  acceso reconciliado: "
                f"quorum={acceso['quorum']} "
                f"nodos={len(acceso['identidades'])}",
                flush=True,
            )
        except Exception as error:  # noqa: BLE001
            # El estado de acceso degradado no apaga VIP ya reconciliadas. Las
            # mutaciones sensibles siguen cerradas por su propio preflight.
            print(
                "  acceso degradado; no se admiten escrituras: "
                f"{getattr(error, 'codigo', type(error).__name__)}",
                flush=True,
            )
        detener.wait(
            INTERVALO_RECONCILIACION if preparado else REINTENTO_ARRANQUE)


def _ejecutar_mutacion(operacion):
    """Serializa preflight, mutación, réplica y aplicación en este nodo."""
    with _candado_mutacion:
        _exigir_deploy_no_congelado()
        # Falla antes incluso de reconciliar: sólo un autor lógico puede crear
        # revisiones, así no existen dos ramas que después haya que desempatar.
        _exigir_escritor_pool()
        if not _esta_listo():
            raise _error_revision(
                "El pool todavía no está preparado para aceptar mutaciones",
                "POOL_NOT_READY",
            )
        reconciliacion = reconciliar_pool(aplicar_configuracion=True)
        _exigir_cluster_v2_pool(reconciliacion["capacidades"])
        # También cubre Pools inyectados en pruebas/embebidos: la validación
        # runtime ocurre dentro de _escribir_atomico, antes de tocar bytes o
        # avanzar una revisión visible.
        POOL.validador = _validar_pool_runtime
        _exigir_deploy_no_congelado()
        valor = operacion()
        datos = valor[0] if isinstance(valor, tuple) else valor
        return valor, aplicar_y_propagar(
            datos, reconciliacion["capacidades"])


def reparto_previsto(datos_pool):
    """Donde deberia vivir cada direccion segun el registro. Es lo que el panel
    ensena como «servidor asignado», frente al que la sostiene de verdad."""
    activas = [d for d in datos_pool.get("direcciones", [])
               if d.get("estado") == "en_uso" and d.get("servicio")]
    return plan.repartir(activas, local.NODOS, set(datos_pool.get("mantenimiento") or []))


# ── HTTP ────────────────────────────────────────────────────────────────
class Manejador(BaseHTTPRequestHandler):
    server_version = "floating-ip-panel"
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def handle_one_request(self):
        # BaseHTTPRequestHandler reutiliza la misma instancia en conexiones
        # keep-alive. Ningún cuerpo/autorización de la petición anterior puede
        # sobrevivir a la siguiente ni dejar su framing real sin consumir.
        self.__dict__.pop("_cuerpo_cache", None)
        self.__dict__.pop("_auth_cuerpo_cache", None)
        self._token_cabeceras = self.server._iniciar_cabeceras(self.connection)
        try:
            return super().handle_one_request()
        finally:
            self._fin_cabeceras()

    def _fin_cabeceras(self):
        token = getattr(self, "_token_cabeceras", None)
        if token is not None:
            self.server._terminar_cabeceras(self.connection, token)
            self._token_cabeceras = None

    def parse_request(self):
        resultado = super().parse_request()
        # Desde este punto el watchdog ya no puede cerrar una operación válida
        # que tarde en consultar peers; sólo protegía request-line+cabeceras.
        self._fin_cabeceras()
        if not resultado:
            return False
        total = sum(
            len(nombre) + len(valor) + 4
            for nombre, valor in self.headers.raw_items())
        longitudes = self.headers.get_all("Content-Length") or []
        transferencias = self.headers.get_all("Transfer-Encoding") or []
        longitud_valida = (
            not longitudes
            or (len(longitudes) == 1
                and re.fullmatch(r"0|[1-9][0-9]*", longitudes[0] or "")))
        if (total > MAX_CABECERAS or len(longitudes) > 1
                or transferencias or not longitud_valida):
            self.close_connection = True
            self.send_error(400, "Cabeceras HTTP ambiguas o demasiado grandes")
            return False
        return True

    def log_message(self, formato, *args):
        pass  # el ruido de acceso no aporta nada aquí

    # -- utilidades --
    def _cabeceras_seguridad(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if AUTH_HTTP.cookie_segura:
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'self'",
        )

    def _json(self, datos, codigo=200, cabeceras=None):
        cuerpo = json.dumps(datos, ensure_ascii=False, indent=2).encode()
        self.send_response(codigo)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.send_header("Cache-Control", "no-store")
        try:
            cuerpo_pendiente = int(self.headers.get("Content-Length") or 0) > 0 \
                and not hasattr(self, "_cuerpo_cache")
        except ValueError:
            cuerpo_pendiente = True
        if cuerpo_pendiente:
            self.close_connection = True
            self.send_header("Connection", "close")
        self._cabeceras_seguridad()
        for nombre, valor in (cabeceras or {}).items():
            self.send_header(nombre, valor)
        self.end_headers()
        self.wfile.write(cuerpo)

    def _error(self, mensaje, codigo=400, code=None, detalle=None):
        salida = {"error": mensaje, "code": code or "REQUEST_ERROR"}
        if detalle:
            salida["detail"] = detalle
        self._json(salida, codigo)

    def _error_pool(self, error):
        codigo = getattr(error, "codigo", None)
        http = 503 if codigo in {
            "POOL_QUORUM_UNAVAILABLE",
            "POOL_NOT_READY",
            "POOL_BOOTSTRAP_PENDING",
            "POOL_BOOTSTRAP_REQUIRED",
            "POOL_BOOTSTRAP_MARKER_UNCERTAIN",
            "POOL_COMMIT_UNCERTAIN",
            "POOL_LOCAL_COMMIT_UNCERTAIN",
            "POOL_CONFIG_COMMIT_UNCERTAIN",
            "POOL_CONFIG_RELOAD_UNCERTAIN",
            "POOL_APPLY_PENDING",
            "CLUSTER_UPGRADE_IN_PROGRESS",
            "CLUSTER_PROTOCOL_MARKER_INVALID",
            "DEPLOY_FROZEN",
            "DEPLOY_FREEZE_INVALID",
        } else 409
        return self._error(str(error), http, codigo or "POOL_CONFLICT")

    def _cuerpo_crudo(self):
        if hasattr(self, "_cuerpo_cache"):
            return self._cuerpo_cache
        if self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            raise pool_mod.ErrorPool("Transfer-Encoding no está permitido")
        valores = self.headers.get_all("Content-Length") or []
        if len(valores) != 1:
            self.close_connection = True
            raise pool_mod.ErrorPool(
                "La petición debe contener un único Content-Length")
        longitud = valores[0]
        if not re.fullmatch(r"0|[1-9][0-9]*", longitud or ""):
            self.close_connection = True
            raise pool_mod.ErrorPool(
                "El cuerpo de la peticion tiene un Content-Length no valido")
        n = int(longitud)
        if n < 0 or n > MAX_CUERPO:
            self.close_connection = True
            raise pool_mod.ErrorPool("El cuerpo de la peticion es demasiado grande")
        partes = []
        recibido = 0
        plazo = time.monotonic() + TIEMPO_CUERPO
        lector = getattr(self.rfile, "read1", None) or self.rfile.read
        while recibido < n:
            restante = plazo - time.monotonic()
            if restante <= 0:
                self.close_connection = True
                raise pool_mod.ErrorPool(
                    "El cuerpo de la petición agotó su plazo total")
            self.connection.settimeout(max(0.001, restante))
            trozo = lector(min(64 * 1024, n - recibido))
            if not trozo:
                break
            partes.append(trozo)
            recibido += len(trozo)
        self.connection.settimeout(15)
        self._cuerpo_cache = b"".join(partes)
        if len(self._cuerpo_cache) != n:
            self.close_connection = True
            raise pool_mod.ErrorPool("El cuerpo de la petición llegó incompleto")
        return self._cuerpo_cache

    def _cuerpo(self):
        crudo = self._cuerpo_crudo()
        if not crudo:
            return {}
        # Se distinguen los dos fallos. Antes los dos decían «no es JSON válido»,
        # y con un JSON impecable enviado desde una consola que no habla UTF-8
        # eso manda a revisar las llaves y las comas, que es el sitio equivocado.
        try:
            texto = crudo.decode("utf-8")
        except UnicodeDecodeError:
            raise pool_mod.ErrorPool(
                "El cuerpo no viene en UTF-8. El JSON puede estar bien: suele pasar al "
                "mandarlo desde una consola con otra codificación y acentos dentro.")
        try:
            datos = json.loads(
                texto or "{}",
                object_pairs_hook=pool_mod._objeto_json_sin_duplicados,
                parse_constant=lambda valor: (_ for _ in ()).throw(
                    ValueError(f"constante JSON no válida: {valor}")),
            )
        except ValueError as e:
            raise pool_mod.ErrorPool(f"El cuerpo de la petición no es JSON válido: {e}")
        if not isinstance(datos, dict):
            raise pool_mod.ErrorPool(
                "La raíz del cuerpo de la petición debe ser un objeto JSON")
        return datos

    def _estatico(self, ruta):
        if ruta in ("/", ""):
            ruta = "/index.html"
        limpio = os.path.normpath(ruta).lstrip("/\\")
        raiz = os.path.realpath(DIR_WEB)
        destino = os.path.realpath(os.path.join(raiz, limpio))
        try:
            dentro = os.path.commonpath((raiz, destino)) == raiz
        except ValueError:
            dentro = False
        if not dentro or not os.path.isfile(destino):
            self._error("No existe", 404)
            return
        with open(destino, "rb") as f:
            cuerpo = f.read()
        self.send_response(200)
        self.send_header("Content-Type", TIPOS.get(os.path.splitext(destino)[1], "application/octet-stream"))
        self.send_header("Content-Length", str(len(cuerpo)))
        self.send_header("Cache-Control", "no-cache")
        self._cabeceras_seguridad()
        self.end_headers()
        self.wfile.write(cuerpo)

    def _verificar_interna(self, metodo, ruta):
        return PROTOCOLO.verificar(
            metodo, ruta, self._cuerpo_crudo() if metodo != "GET" else b"", self.headers)

    # -- rutas --
    def do_GET(self):
        r = self.path.split("?")[0]
        try:
            if AUTH_HTTP.manejar(self, "GET", r):
                return
            if r == "/api/health":
                # Liveness pública y compatible: readiness revela estado del
                # clúster y se expone sólo en /api/status autenticado.
                return self._json({"estado": "ok", "version": version_info()})
            if r == "/api/status":
                AUTH_HTTP.exigir(self, "reader")
                return self._json({
                    "estado": "ok",
                    "nodo": local.YO,
                    "nodos": len(local.NODOS),
                    "pares": len(PARES),
                    "version": version_info(),
                    "auth_configured": AUTH_HTTP.configurado,
                    "cluster_security_configured": PROTOCOLO.disponible,
                    "pool_ready": _esta_listo(),
                    "pool_writer": _escritor_cluster(),
                    "pool_writable": local.YO == _escritor_cluster(),
                    "pool_apply_pending": _ultimo_error_aplicacion is not None,
                    "pool_apply_error": _ultimo_error_aplicacion,
                })
            if r == "/api/settings":
                AUTH_HTTP.exigir(self, "admin")
                return self._json({
                    "settings": setup_config.settings(),
                    "restart_required": True,
                })
            if r == "/api/internal/local":
                self._verificar_interna("GET", r)
                return self._json({
                    "payload": PROTOCOLO.cifrar(local.vista_local(POOL.leer())),
                })
            if r == RUTA_POOL_V2:
                self._verificar_interna("GET", r)
                snapshot, inicializado = _estado_pool_local()
                return self._json({
                    "payload": PROTOCOLO.cifrar({
                        "capability": CAPACIDAD_POOL_V2,
                        "nodo": local.YO,
                        "initialized": inicializado,
                        "snapshot": snapshot,
                    }),
                })
            if r == RUTA_SEGURIDAD_V2:
                self._verificar_interna("GET", r)
                snapshot, inicializado = _estado_seguridad_local()
                return self._json({"payload": PROTOCOLO.cifrar({
                    "capability": CAPACIDAD_SEGURIDAD_V2,
                    "nodo": local.YO,
                    "initialized": inicializado,
                    "snapshot": snapshot,
                })})
            if r == "/api/pool":
                AUTH_HTTP.exigir(self, "reader")
                datos = POOL.leer()
                return self._json({
                    **datos,
                    "vrids_ocupados": pool_mod.vrids_ocupados(datos),
                    "vrid_sugerido": pool_mod.sugerir_vrid(datos),
                })
            if r == "/api/direcciones":
                AUTH_HTTP.exigir_api_o_usuario(self, "status:read")
                return self._json(cuadro(POOL.leer()))
            m = re.match(r"^/api/direcciones/(\d+\.\d+\.\d+\.\d+)$", r)
            if m:
                AUTH_HTTP.exigir_api_o_usuario(self, "status:read")
                c = cuadro(POOL.leer())
                for f in c["direcciones"]:
                    if f.get("ip") == m.group(1):
                        return self._json(f)
                return self._error("No está en el registro", 404)
            if r == "/api/nodos":
                AUTH_HTTP.exigir(self, "reader")
                return self._json({"nodos": resumen_nodos(POOL.leer())})
            if r.startswith("/api/"):
                return self._error("No existe", 404)
            return self._estatico(r)
        except pool_mod.ErrorPool as e:
            return self._error_pool(e)
        except seguridad.ErrorAcceso as e:
            return self._error(str(e), e.http, e.codigo)
        except Exception as e:  # noqa: BLE001
            return self._error("No se pudo completar la petición", 500,
                               "INTERNAL_ERROR", type(e).__name__)

    def do_POST(self):
        r = self.path.split("?")[0]
        try:
            _exigir_mutacion_no_congelada("POST", r)
            if AUTH_HTTP.manejar(self, "POST", r):
                return
            cuerpo = self._cuerpo()

            if r == "/api/settings":
                try:
                    with AUTH_HTTP.autorizar_mutacion(self, "admin"):
                        with _candado_configuracion:
                            anterior = setup_config.settings()
                            candidato = setup_config.candidate(cuerpo)
                            nuevo = setup_config.settings(candidato)
                            cambiado = nuevo != anterior
                            if cambiado:
                                setup_config.persist_settings(candidato)
                except setup_config.SetupError as error:
                    return self._error(str(error), 422, "INVALID_SETTINGS")
                self._json({
                    "ok": True,
                    "changed": cambiado,
                    "restarting": cambiado,
                })
                if cambiado:
                    reinicio = threading.Timer(
                        0.8, os.kill, args=(os.getpid(), signal.SIGTERM))
                    reinicio.daemon = True
                    reinicio.start()
                return None

            if r == RUTA_REPLICA_POOL_V2:
                fuente = self._verificar_interna("POST", r)
                # El ACK de pool implica dos hechos locales: snapshot durable y
                # configuración validada/aplicada. El candado de aplicación no
                # es el de mutaciones: una réplica interna puede seguir
                # resolviendo causalidad mientras una petición externa espera.
                with _candado_aplicacion:
                    try:
                        mensaje = PROTOCOLO.descifrar(cuerpo.get("payload"))
                        if not isinstance(mensaje, dict):
                            raise ValueError("el sobre no contiene un objeto")
                        if (mensaje.get("capability") != CAPACIDAD_POOL_V2
                                or mensaje.get("nodo") != fuente):
                            raise seguridad.ErrorAcceso(
                                "La capacidad o identidad cifrada no coincide con la firma",
                                "CLUSTER_IDENTITY_MISMATCH", 401)
                        snapshot = mensaje.get("snapshot")
                        _validar_snapshot_cluster(snapshot, permitir_legacy=False)
                        cambiado = POOL.aplicar_replica(snapshot)
                        actual = POOL.leer()
                        aplicar(actual)
                        ack = {
                            "capability": CAPACIDAD_POOL_V2,
                            "estado": "ok",
                            "nodo": local.YO,
                            "replica_aplicada": cambiado,
                            "huella": pool_mod.Pool.huella(actual),
                        }
                        return self._json({"payload": PROTOCOLO.cifrar(ack)})
                    except pool_mod.ErrorRevisionPool as error:
                        if error.codigo in {
                                "POOL_LOCAL_COMMIT_UNCERTAIN",
                                "POOL_CONFIG_COMMIT_UNCERTAIN",
                                "POOL_CONFIG_RELOAD_UNCERTAIN",
                                "POOL_APPLY_PENDING",
                        }:
                            _degradar_readiness_pool(detener_keepalived=True)
                        return self._error_pool(error)
                    except pool_mod.ErrorPool as error:
                        return self._error(str(error), 422, "POOL_REPLICA_INVALID")
                    except seguridad.ErrorAcceso:
                        raise
                    except ValueError as error:
                        return self._error(str(error), 400, "POOL_REPLICA_INVALID")

            if r == RUTA_REPLICA_SEGURIDAD_V2:
                # La misma barrera que protege autorización→mutación impide
                # instalar una revocación entre ambas fases. GET v2 no la toma,
                # para que reconciliaciones cruzadas nunca formen un deadlock.
                with AUTH_HTTP.bloquear_estado_seguridad():
                    with _candado_seguridad:
                        fuente = self._verificar_interna("POST", r)
                        mensaje = PROTOCOLO.descifrar(cuerpo.get("payload"))
                        if (not isinstance(mensaje, dict)
                                or mensaje.get("capability")
                                != CAPACIDAD_SEGURIDAD_V2
                                or mensaje.get("nodo") != fuente):
                            raise seguridad.ErrorAcceso(
                                "La capacidad o identidad de acceso no coincide "
                                "con la firma",
                                "CLUSTER_IDENTITY_MISMATCH", 401)
                        snapshot = mensaje.get("snapshot")
                        _validar_snapshot_seguridad_cluster(
                            snapshot, permitir_legacy=False)
                        aplicado = CUENTAS.aplicar_replica(snapshot)
                        actual = CUENTAS.leer()
                        if (actual.get("revision") or {}).get("clock"):
                            # El ACK sólo sale cuando estado y autorización
                            # one-shot quedaron persistidos en este receptor.
                            _consumir_bootstrap_seguridad()
                        ack = {
                            "capability": CAPACIDAD_SEGURIDAD_V2,
                            "estado": "ok",
                            "nodo": local.YO,
                            "replica_aplicada": aplicado,
                            "huella": CUENTAS.huella(actual),
                        }
                        return self._json({
                            "payload": PROTOCOLO.cifrar(ack)})

            if r == "/api/claims":
                clave = self.headers.get("Idempotency-Key")
                if not clave:
                    return self._error("Falta la cabecera Idempotency-Key")
                with AUTH_HTTP.autorizar_mutacion(
                        self, "operator", permiso_api="claims:write"):
                    valor, resultado = _ejecutar_mutacion(
                        lambda: POOL.reclamar(cuerpo, clave))
                datos, direccion, repetida = valor
                return self._json({
                    "reclamacion": direccion,
                    "repetida": repetida,
                    **resultado,
                }, 200 if repetida else 201)

            if r == "/api/pool":
                def alta_validada_runtime():
                    _validar_vip_runtime(cuerpo.get("ip"))
                    return POOL.alta(cuerpo)

                with AUTH_HTTP.autorizar_mutacion(self, "operator"):
                    datos, resultado = _ejecutar_mutacion(
                        alta_validada_runtime)
                return self._json({"pool": datos, **resultado}, 201)

            if r == "/api/mantenimiento":
                # Modo mantenimiento de un SERVIDOR. Es estado de todo el
                # cluster, asi que se apunta en el registro y se manda a los
                # tres: el que entra en mantenimiento se vacia, y los demas se
                # reparten sus direcciones de forma equilibrada.
                nodo = cuerpo.get("nodo")
                activo = cuerpo.get("activo")
                aceptadas = cuerpo.get("direcciones_sin_respaldo_aceptadas", [])
                if (not isinstance(aceptadas, list)
                        or any(not isinstance(ip, str) for ip in aceptadas)):
                    return self._error(
                        "direcciones_sin_respaldo_aceptadas debe ser una lista de IP")
                if not isinstance(activo, bool):
                    return self._error("activo debe ser booleano")
                if not nodo:
                    return self._error("Falta «nodo»")
                if local.NODOS and nodo not in [n["nombre"] for n in local.NODOS]:
                    return self._error(f"«{nodo}» no es uno de los servidores")
                observado = None
                estado_observado = None
                if activo:
                    # Autentica antes de exponer topología, pero no conserva
                    # ningún candado mientras consulta health local/remoto. La
                    # fase E2E posterior reautoriza y comprueba la misma revisión.
                    AUTH_HTTP.exigir(self, "operator")
                    observado = POOL.leer()
                    if nodo not in (observado.get("mantenimiento") or []):
                        estado_observado = next(
                            (x for x in resumen_nodos(observado)
                             if x.get("nodo") == nodo),
                            None,
                        )

                def mutar_mantenimiento():
                    datos = POOL.leer()
                    if activo:
                        if nodo not in (datos.get("mantenimiento") or []):
                            if (observado is None
                                    or pool_mod.Pool.huella(datos)
                                    != pool_mod.Pool.huella(observado)):
                                raise _error_revision(
                                    "El pool cambió mientras se comprobaba el "
                                    "riesgo de mantenimiento; vuelve a intentarlo",
                                    "POOL_PREFLIGHT_STALE",
                                )
                            if estado_observado is None:
                                raise pool_mod.ErrorPool(
                                    "No se pudo comprobar el estado del servidor")
                            pendientes = riesgos_mantenimiento_pendientes(
                                estado_observado, aceptadas)
                            if pendientes:
                                raise pool_mod.ErrorPool(
                                    "Confirma el riesgo de las direcciones sin respaldo: "
                                    + ", ".join(x["ip"] for x in pendientes))
                        disponibles = [n["nombre"] for n in local.NODOS
                                       if n["nombre"] not in (datos.get("mantenimiento") or [])]
                        if len(disponibles) <= 1 and nodo in disponibles:
                            raise pool_mod.ErrorPool(
                                "Es el ultimo servidor en servicio. Si tambien lo paras, "
                                "las direcciones se quedan sin nadie que las sostenga.")
                    pool_mod.marcar_mantenimiento(datos, nodo, activo)
                    return POOL.escribir(datos)

                with AUTH_HTTP.autorizar_mutacion(self, "operator"):
                    datos, resultado = _ejecutar_mutacion(mutar_mantenimiento)
                return self._json({"mantenimiento": datos["mantenimiento"],
                                   **resultado})


            return self._error("No existe", 404)
        except pool_mod.ErrorPool as e:
            return self._error_pool(e)
        except seguridad.ErrorAcceso as e:
            return self._error(str(e), e.http, e.codigo)
        except Exception as e:  # noqa: BLE001
            return self._error("No se pudo completar la petición", 500,
                               "INTERNAL_ERROR", type(e).__name__)

    def do_PUT(self):
        """En qué servidor descansa una dirección. Su propia puerta, a propósito.

        Separada del PATCH que usa quien coge una dirección: ése dice para qué la
        usa —servicio, puertos, cómo se comprueba— y eso es asunto suyo. Dónde
        descansa lo decide quien opera el clúster, desde la pantalla.
        """
        m = re.match(r"^/api/pool/(\d+\.\d+\.\d+\.\d+)/servidor$", self.path.split("?")[0])
        if not m:
            return self._error("No existe", 404)
        try:
            _exigir_mutacion_no_congelada("PUT", self.path.split("?")[0])
            cuerpo = self._cuerpo()
            nodo = cuerpo.get("servidor")
            validos = {n["nombre"] for n in local.NODOS}
            with AUTH_HTTP.autorizar_mutacion(self, "operator"):
                datos, resultado = _ejecutar_mutacion(
                    lambda: POOL.elegir_servidor(m.group(1), nodo, validos))
            return self._json({"pool": datos, **resultado})
        except pool_mod.ErrorPool as e:
            return self._error_pool(e)
        except seguridad.ErrorAcceso as e:
            return self._error(str(e), e.http, e.codigo)
        except Exception as e:  # noqa: BLE001
            return self._error("No se pudo completar la petición", 500,
                               "INTERNAL_ERROR", type(e).__name__)

    def do_PATCH(self):
        ruta = self.path.split("?")[0]
        try:
            _exigir_mutacion_no_congelada("PATCH", ruta)
            if AUTH_HTTP.manejar(self, "PATCH", ruta):
                return
            m = re.match(r"^/api/pool/(\d+\.\d+\.\d+\.\d+)$", ruta)
            if not m:
                return self._error("No existe", 404)
            cambios = self._cuerpo()
            with AUTH_HTTP.autorizar_mutacion(self, "operator"):
                datos, resultado = _ejecutar_mutacion(
                    lambda: POOL.modificar(m.group(1), cambios))
            return self._json({"pool": datos, **resultado})
        except pool_mod.ErrorPool as e:
            return self._error_pool(e)
        except seguridad.ErrorAcceso as e:
            return self._error(str(e), e.http, e.codigo)
        except Exception as e:  # noqa: BLE001
            return self._error("No se pudo completar la petición", 500,
                               "INTERNAL_ERROR", type(e).__name__)

    def do_DELETE(self):
        ruta = self.path.split("?")[0]
        try:
            _exigir_mutacion_no_congelada("DELETE", ruta)
            if AUTH_HTTP.manejar(self, "DELETE", ruta):
                return
        except pool_mod.ErrorPool as e:
            return self._error_pool(e)
        except seguridad.ErrorAcceso as e:
            return self._error(str(e), e.http, e.codigo)
        except Exception as e:  # noqa: BLE001
            return self._error("No se pudo completar la petición", 500,
                               "INTERNAL_ERROR", type(e).__name__)
        m_reclamacion = re.match(
            r"^/api/claims/([A-Za-z0-9][A-Za-z0-9._:-]{7,127})$", ruta)
        if m_reclamacion:
            try:
                with AUTH_HTTP.autorizar_mutacion(
                        self, "operator", permiso_api="claims:write"):
                    valor, resultado = _ejecutar_mutacion(
                        lambda: POOL.liberar_reclamacion(
                            m_reclamacion.group(1)))
                datos, ip, repetida = valor
                return self._json({
                    "ip": ip,
                    "liberada": True,
                    "repetida": repetida,
                    **resultado,
                })
            except pool_mod.ErrorPool as e:
                return self._error_pool(e)
            except seguridad.ErrorAcceso as e:
                return self._error(str(e), e.http, e.codigo)
            except Exception as e:  # noqa: BLE001
                return self._error("No se pudo completar la petición", 500,
                                   "INTERNAL_ERROR", type(e).__name__)

        m = re.match(r"^/api/pool/(\d+\.\d+\.\d+\.\d+)$", ruta)
        if not m:
            return self._error("No existe", 404)
        try:
            with AUTH_HTTP.autorizar_mutacion(self, "operator"):
                datos, resultado = _ejecutar_mutacion(
                    lambda: POOL.baja(m.group(1)))
            return self._json({"pool": datos, **resultado})
        except pool_mod.ErrorPool as e:
            return self._error_pool(e)
        except seguridad.ErrorAcceso as e:
            return self._error(str(e), e.http, e.codigo)
        except Exception as e:  # noqa: BLE001
            return self._error("No se pudo completar la petición", 500,
                               "INTERNAL_ERROR", type(e).__name__)


class Servidor(ThreadingHTTPServer):
    def __init__(self, *args, **kwargs):
        self._limite_http_total = threading.BoundedSemaphore(MAX_HTTP_TOTAL)
        self._limite_http_externo = threading.BoundedSemaphore(MAX_HTTP_EXTERNOS)
        self._candado_reservas_http = threading.Lock()
        self._reservas_http = {}
        self._candado_cabeceras = threading.Lock()
        self._cabeceras_pendientes = {}
        self._detener_watchdog = threading.Event()
        super().__init__(*args, **kwargs)
        self._watchdog = threading.Thread(
            target=self._vigilar_cabeceras,
            name="http-header-deadline", daemon=True)
        self._watchdog.start()

    @staticmethod
    def _es_cliente_local(client_address):
        try:
            return ipaddress.ip_address(client_address[0]).is_loopback
        except ValueError:
            return False

    @staticmethod
    def _rechazar_saturado(request):
        try:
            request.settimeout(0.2)
            request.sendall(
                b"HTTP/1.1 503 Service Unavailable\r\n"
                b"Connection: close\r\nContent-Length: 0\r\n\r\n")
        except OSError:
            pass
        try:
            request.close()
        except OSError:
            pass

    def process_request(self, request, client_address):
        externo = not self._es_cliente_local(client_address)
        if externo and not self._limite_http_externo.acquire(blocking=False):
            self._rechazar_saturado(request)
            return
        if not self._limite_http_total.acquire(blocking=False):
            if externo:
                self._limite_http_externo.release()
            self._rechazar_saturado(request)
            return
        with self._candado_reservas_http:
            self._reservas_http[id(request)] = externo
        try:
            super().process_request(request, client_address)
        except Exception:
            self._liberar_reserva(request)
            raise

    def _liberar_reserva(self, request):
        with self._candado_reservas_http:
            externo = self._reservas_http.pop(id(request), None)
        if externo is None:
            return
        self._limite_http_total.release()
        if externo:
            self._limite_http_externo.release()

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._liberar_reserva(request)

    def _iniciar_cabeceras(self, conexion):
        token = object()
        with self._candado_cabeceras:
            self._cabeceras_pendientes[id(conexion)] = (
                token, conexion, time.monotonic() + TIEMPO_CABECERAS)
        return token

    def _terminar_cabeceras(self, conexion, token):
        with self._candado_cabeceras:
            actual = self._cabeceras_pendientes.get(id(conexion))
            if actual and actual[0] is token:
                self._cabeceras_pendientes.pop(id(conexion), None)

    def _vigilar_cabeceras(self):
        while not self._detener_watchdog.wait(0.1):
            ahora = time.monotonic()
            caducadas = []
            with self._candado_cabeceras:
                for clave, (token, conexion, limite) in list(
                        self._cabeceras_pendientes.items()):
                    if limite <= ahora:
                        self._cabeceras_pendientes.pop(clave, None)
                        caducadas.append(conexion)
            for conexion in caducadas:
                try:
                    conexion.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def handle_error(self, request, client_address):
        # Un navegador que cierra la pestana provoca un ConnectionResetError.
        # Sin esto, cada uno escupe una traza que ahoga el log de keepalived —
        # que es justo lo que quieres leer cuando algo va mal.
        import sys, traceback
        exc = sys.exc_info()[0]
        if exc and issubclass(exc, (ConnectionResetError, BrokenPipeError, ConnectionAbortedError)):
            return
        traceback.print_exc()

    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def server_close(self):
        self._detener_watchdog.set()
        watchdog = getattr(self, "_watchdog", None)
        if watchdog and watchdog is not threading.current_thread():
            watchdog.join(timeout=1)
        super().server_close()


def main():
    validar_arranque()
    os.makedirs(DIR_DATOS, exist_ok=True)
    _retirar_marcador_listo()
    print(f"panel floating-ip · nodo={local.YO} puerto={PUERTO} datos={DIR_DATOS}", flush=True)
    print(f"  pares: {PARES or 0}", flush=True)
    print(f"  acceso: {'configurado' if AUTH_HTTP.configurado else 'FALTA CONFIGURAR'}", flush=True)
    # Construir el servidor ya deja el socket escuchando. Sólo entonces se
    # lanza el worker: los tres paneles pueden contestarse durante un arranque
    # frío aunque ninguno haya habilitado keepalived todavía.
    servidor = Servidor(("0.0.0.0", PUERTO), Manejador)  # nosec B104
    detener = threading.Event()
    worker = threading.Thread(
        target=_trabajador_arranque,
        args=(detener,),
        name="cluster-state-reconciliation",
        daemon=True,
    )
    worker.start()
    try:
        servidor.serve_forever()
    finally:
        detener.set()
        _retirar_marcador_listo()
        servidor.server_close()


if __name__ == "__main__":
    main()
