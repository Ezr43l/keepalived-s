"""Cuentas locales, sesiones, TOTP y protocolo interno de Keepalived.

La contraseña se deriva con scrypt. Los secretos TOTP se cifran con Fernet y
los códigos de recuperación sólo se conservan como HMAC. Las cookies son
autocontenidas y firmadas, pero cada petición vuelve a comprobar la versión y
el estado del usuario para que un cambio administrativo invalide sesiones.
"""
from __future__ import annotations

import base64
import errno
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import struct
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from urllib.parse import quote, urlencode

try:
    import fcntl
except ImportError:  # pragma: no cover - el runtime soportado es Linux.
    fcntl = None

from cryptography.fernet import Fernet, InvalidToken


COOKIE = "keepalived_session"
ROLES = ("reader", "operator", "admin")
NIVEL_ROL = {nombre: indice for indice, nombre in enumerate(ROLES)}
PERMISOS_API = ("status:read", "claims:write")
PATRON_USUARIO = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}")
PATRON_NODO = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
PATRON_SHA256 = re.compile(r"[0-9a-f]{64}")
PATRON_UUID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
PATRON_ID_CLAVE_API = re.compile(r"[0-9a-f]{32}")
CLAVES_COMUNES = {
    "123456789012", "administrador", "keepalived", "changeme1234", "password1234",
}

_MAX_ESTADO_ACCESO_BYTES = 512 * 1024
_MAX_USUARIOS = 256
_MAX_CLAVES_API = 1024
_MAX_CODIGOS_RECUPERACION = 32
_MAX_TEXTO_NOMBRE = 120
_MAX_ACTOR = 80
_MAX_MARCA_TIEMPO = 64
_MAX_HASH_CREDENCIAL = 2048
_MAX_PREFIJO_API = 128
_MAX_CONTADOR = 2**63 - 1
_MAX_AUTORES_REVISION = 64
_REVISION_SCHEMA = 1
_AUTOR_LEGACY = "legacy"
_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_SALT_BYTES = 16
_SCRYPT_DK_BYTES = 32
_MAX_NONCES_CLUSTER = 8192
_VENTANA_NONCE_CLUSTER = 120.0
_MAX_SOBRE_CLUSTER_BYTES = 1024 * 1024
_MAX_MENSAJE_CLUSTER_BYTES = 768 * 1024
_CAMPOS_ESTADO = {"schema", "revision", "users", "api_keys"}
_CAMPOS_REVISION_LEGACY = {"counter", "timestamp", "node", "actor"}
_CAMPOS_REVISION_VECTOR = {
    "schema", "clock", "author", "actor", "legacy_base",
}
_CAMPOS_USUARIO = {
    "id", "username", "display_name", "role", "status", "password_hash",
    "password_change_required", "session_version", "totp", "created_at",
    "updated_at", "updated_by",
}
_CAMPOS_TOTP = {
    "enabled", "secret", "pending_secret", "recovery_code_hashes",
}
_CAMPOS_CLAVE_API = {
    "id", "name", "prefix", "token_hash", "scopes", "status",
    "created_at", "created_by", "revoked_at", "revoked_by",
}
_ERRORES_FSYNC_DIR_NO_SOPORTADO = {
    errno.EINVAL,
    getattr(errno, "ENOTSUP", errno.EINVAL),
    getattr(errno, "EOPNOTSUPP", errno.EINVAL),
    getattr(errno, "ENOSYS", errno.EINVAL),
}


class ErrorAcceso(ValueError):
    def __init__(self, mensaje, codigo="INVALID_CREDENTIALS", http=401):
        super().__init__(mensaje)
        self.codigo = codigo
        self.http = http


def _json_canonico_acceso(datos):
    """Representación determinista, JSON estricto y con coste acotado."""
    try:
        crudo = json.dumps(
            datos,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError, OverflowError) as error:
        raise ErrorAcceso(
            f"El estado de acceso no contiene JSON canónico válido: {error}",
            "AUTH_STATE_INVALID", 409,
        ) from error
    if len(crudo) > _MAX_ESTADO_ACCESO_BYTES:
        raise ErrorAcceso(
            "El estado de acceso supera el máximo seguro de 512 KiB",
            "AUTH_STATE_TOO_LARGE", 409,
        )
    return crudo


def _objeto_json_sin_duplicados(pares):
    salida = {}
    for clave, valor in pares:
        if clave in salida:
            raise ValueError(f"campo JSON duplicado: {clave}")
        salida[clave] = valor
    return salida


def _abrir_directorio_seguro(ruta):
    try:
        estado = os.lstat(ruta)
    except FileNotFoundError:
        os.makedirs(ruta, mode=0o700, exist_ok=True)
        estado = os.lstat(ruta)
    if stat.S_ISLNK(estado.st_mode) or not stat.S_ISDIR(estado.st_mode):
        raise ErrorAcceso(
            "El directorio del estado de acceso no es un directorio real",
            "AUTH_STORAGE_ERROR", 503,
        )
    banderas = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        banderas |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        banderas |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        banderas |= os.O_NOFOLLOW
    try:
        fd = os.open(ruta, banderas)
    except OSError as error:
        raise ErrorAcceso(
            f"No se puede abrir de forma segura el directorio de acceso: {error}",
            "AUTH_STORAGE_ERROR", 503,
        ) from error
    try:
        abierto = os.fstat(fd)
        posterior = os.lstat(ruta)
        if (not stat.S_ISDIR(abierto.st_mode)
                or stat.S_ISLNK(posterior.st_mode)
                or not stat.S_ISDIR(posterior.st_mode)
                or (abierto.st_dev, abierto.st_ino)
                != (posterior.st_dev, posterior.st_ino)):
            raise ErrorAcceso(
                "El directorio del estado de acceso cambió mientras se abría",
                "AUTH_STORAGE_ERROR", 503,
            )
        if os.name == "posix":
            euid, egid = os.geteuid(), os.getegid()
            if abierto.st_uid != euid:
                if euid != 0:
                    raise ErrorAcceso(
                        "El directorio del estado de acceso pertenece a otro usuario",
                        "AUTH_STORAGE_ERROR", 503,
                    )
                os.fchown(fd, euid, egid)
            elif euid == 0 and abierto.st_gid != egid:
                os.fchown(fd, euid, egid)
            if stat.S_IMODE(abierto.st_mode) != 0o700:
                os.fchmod(fd, 0o700)
            final = os.fstat(fd)
            if final.st_uid != euid or stat.S_IMODE(final.st_mode) != 0o700:
                raise ErrorAcceso(
                    "No se pudieron asegurar propietario y modo 0700 del directorio de acceso",
                    "AUTH_STORAGE_ERROR", 503,
                )
        return fd
    except Exception:
        os.close(fd)
        raise


def _comprobar_directorio_seguro(ruta):
    fd = _abrir_directorio_seguro(ruta)
    os.close(fd)


def _estado_regular_seguro(ruta, permitir_ausente=False):
    try:
        estado = os.lstat(ruta)
    except FileNotFoundError:
        if permitir_ausente:
            return None
        raise
    if stat.S_ISLNK(estado.st_mode):
        raise ErrorAcceso(
            "El estado de acceso no puede ser un enlace simbólico",
            "AUTH_STORAGE_ERROR", 503,
        )
    if not stat.S_ISREG(estado.st_mode):
        raise ErrorAcceso(
            "El estado de acceso debe ser un fichero regular",
            "AUTH_STORAGE_ERROR", 503,
        )
    return estado


def _normalizar_descriptor_seguro(fd, ruta):
    """Exige fichero regular, sin hardlinks, del proceso y con modo 0600."""
    estado = os.fstat(fd)
    if not stat.S_ISREG(estado.st_mode):
        raise ErrorAcceso(
            "El estado de acceso debe ser un fichero regular",
            "AUTH_STORAGE_ERROR", 503,
        )
    if os.name == "posix":
        if estado.st_nlink != 1:
            raise ErrorAcceso(
                "El estado de acceso no puede compartir inode mediante enlaces duros",
                "AUTH_STORAGE_ERROR", 503,
            )
        euid, egid = os.geteuid(), os.getegid()
        if estado.st_uid != euid:
            if euid != 0:
                raise ErrorAcceso(
                    "El estado de acceso pertenece a otro usuario",
                    "AUTH_STORAGE_ERROR", 503,
                )
            os.fchown(fd, euid, egid)
        elif euid == 0 and estado.st_gid != egid:
            os.fchown(fd, euid, egid)
        if stat.S_IMODE(estado.st_mode) != 0o600:
            os.fchmod(fd, 0o600)
        final = os.fstat(fd)
        if final.st_uid != euid or stat.S_IMODE(final.st_mode) != 0o600:
            raise ErrorAcceso(
                f"No se pudieron asegurar propietario y modo 0600 de {ruta}",
                "AUTH_STORAGE_ERROR", 503,
            )
    return os.fstat(fd)


def _abrir_regular_seguro(ruta, flags, crear=False):
    previo = _estado_regular_seguro(ruta, permitir_ausente=crear)
    banderas = flags | (os.O_CREAT if crear else 0)
    if hasattr(os, "O_CLOEXEC"):
        banderas |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        banderas |= os.O_NOFOLLOW
    try:
        fd = os.open(ruta, banderas, 0o600)
    except OSError as error:
        if error.errno == getattr(errno, "ELOOP", None):
            raise ErrorAcceso(
                "El estado de acceso no puede ser un enlace simbólico",
                "AUTH_STORAGE_ERROR", 503,
            ) from error
        raise
    try:
        abierto = _normalizar_descriptor_seguro(fd, ruta)
        posterior = _estado_regular_seguro(ruta)
        if (abierto.st_dev, abierto.st_ino) != (posterior.st_dev, posterior.st_ino):
            raise ErrorAcceso(
                "El estado de acceso cambió mientras se abría",
                "AUTH_STORAGE_ERROR", 503,
            )
        if previo is not None and (
                (previo.st_dev, previo.st_ino) != (abierto.st_dev, abierto.st_ino)):
            raise ErrorAcceso(
                "El estado de acceso cambió mientras se abría",
                "AUTH_STORAGE_ERROR", 503,
            )
        return fd
    except Exception:
        os.close(fd)
        raise


def normalizar_usuario(valor):
    usuario = str(valor or "").strip()
    if not PATRON_USUARIO.fullmatch(usuario):
        raise ErrorAcceso(
            "El usuario debe tener entre 3 y 64 caracteres y usar letras, números, punto, guion o guion bajo",
            "INVALID_PROFILE", 422,
        )
    return usuario


def normalizar_nombre(valor):
    nombre = " ".join(str(valor or "").split())
    if not nombre or len(nombre) > 120:
        raise ErrorAcceso("El nombre debe tener entre 1 y 120 caracteres", "INVALID_PROFILE", 422)
    return nombre


def validar_rol(valor):
    rol = str(valor or "").strip().lower()
    if rol not in ROLES:
        raise ErrorAcceso("El permiso debe ser reader, operator o admin", "INVALID_ROLE", 422)
    return rol


def rol_permite(actual, necesario):
    return NIVEL_ROL.get(actual, -1) >= NIVEL_ROL.get(necesario, 99)


def _b64(datos):
    return base64.urlsafe_b64encode(datos).decode("ascii").rstrip("=")


def _b64d(valor):
    return base64.urlsafe_b64decode((valor + "=" * (-len(valor) % 4)).encode("ascii"))


def _parametros_hash_clave(valor):
    """Valida el formato scrypt antes de reservar CPU o memoria.

    La versión 1.0.0 siempre generó exactamente estos parámetros, 16 bytes de
    sal y 32 de derivada. Aceptar valores gobernados por el fichero permitiría
    convertir una réplica corrupta en un trabajo scrypt arbitrariamente caro.
    """
    if not isinstance(valor, str) or len(valor) > _MAX_HASH_CREDENCIAL:
        return None
    try:
        algoritmo, n, r, p, sal_b64, derivada_b64 = valor.split("$", 5)
        if (algoritmo != "scrypt"
                or n != str(_SCRYPT_N)
                or r != str(_SCRYPT_R)
                or p != str(_SCRYPT_P)
                or len(sal_b64) != 22
                or len(derivada_b64) != 43
                or not re.fullmatch(r"[A-Za-z0-9_-]+", sal_b64)
                or not re.fullmatch(r"[A-Za-z0-9_-]+", derivada_b64)):
            return None
        sal = _b64d(sal_b64)
        derivada = _b64d(derivada_b64)
        if (len(sal) != _SCRYPT_SALT_BYTES
                or len(derivada) != _SCRYPT_DK_BYTES
                or _b64(sal) != sal_b64
                or _b64(derivada) != derivada_b64):
            return None
        return sal, derivada
    except (ValueError, TypeError, UnicodeError, OverflowError):
        return None


def _copia(valor):
    return json.loads(json.dumps(valor, ensure_ascii=False))


def _ahora_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class ProteccionCuenta:
    def __init__(self, secreto, minimo=12, emisor="Keepalived"):
        self.secreto = str(secreto or "").strip()
        self.minimo = max(12, int(minimo))
        self.emisor = str(emisor or "Keepalived").strip() or "Keepalived"
        clave = base64.urlsafe_b64encode(hashlib.sha256(self.secreto.encode()).digest())
        self.fernet = Fernet(clave) if self.secreto else None
        self.clave_recuperacion = hashlib.sha256(
            ("recovery:" + self.secreto).encode()).digest()
        self.clave_api = hashlib.sha256(("api:" + self.secreto).encode()).digest()

    @property
    def disponible(self):
        return self.fernet is not None and len(self.secreto) >= 32

    def validar_clave(self, clave, usuario=""):
        if len(clave or "") < self.minimo:
            raise ErrorAcceso(
                f"La contraseña debe tener al menos {self.minimo} caracteres",
                "WEAK_PASSWORD", 422,
            )
        if len(clave) > 256:
            raise ErrorAcceso("La contraseña no puede superar 256 caracteres", "WEAK_PASSWORD", 422)
        compacta = clave.strip().casefold()
        if compacta in CLAVES_COMUNES or (usuario and compacta == usuario.casefold()):
            raise ErrorAcceso("La contraseña elegida es demasiado predecible", "WEAK_PASSWORD", 422)

    @staticmethod
    def hash_clave(clave):
        sal = secrets.token_bytes(_SCRYPT_SALT_BYTES)
        derivada = hashlib.scrypt(
            clave.encode(), salt=sal, n=_SCRYPT_N, r=_SCRYPT_R,
            p=_SCRYPT_P, dklen=_SCRYPT_DK_BYTES,
            maxmem=64 * 1024 * 1024,
        )
        return "$".join((
            "scrypt", str(_SCRYPT_N), str(_SCRYPT_R), str(_SCRYPT_P),
            _b64(sal), _b64(derivada),
        ))

    @staticmethod
    def comprobar_clave(clave, guardada):
        if not isinstance(clave, str) or len(clave) > 256:
            return False
        parametros = _parametros_hash_clave(guardada)
        if parametros is None:
            return False
        sal, esperada = parametros
        try:
            real = hashlib.scrypt(
                clave.encode(), salt=sal, n=_SCRYPT_N, r=_SCRYPT_R,
                p=_SCRYPT_P, dklen=_SCRYPT_DK_BYTES,
                maxmem=64 * 1024 * 1024,
            )
            return hmac.compare_digest(real, esperada)
        except (ValueError, TypeError, OverflowError, MemoryError, OSError):
            return False

    def cifrar(self, valor):
        if not self.fernet:
            raise ErrorAcceso("Falta FIP_SESSION_SECRET", "AUTH_NOT_CONFIGURED", 503)
        return "fernet:" + self.fernet.encrypt(valor.encode()).decode("ascii")

    def descifrar(self, valor):
        if not self.fernet or not valor or not str(valor).startswith("fernet:"):
            raise ErrorAcceso("El secreto 2FA almacenado no es válido", "TWO_FACTOR_INVALID", 409)
        try:
            return self.fernet.decrypt(str(valor)[7:].encode()).decode()
        except (InvalidToken, UnicodeError) as error:
            raise ErrorAcceso(
                "No se ha podido descifrar el secreto 2FA", "TWO_FACTOR_INVALID", 409,
            ) from error

    @staticmethod
    def generar_secreto_totp():
        return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")

    @staticmethod
    def _totp(secreto, contador, digitos=6):
        clave = base64.b32decode(
            (secreto + "=" * (-len(secreto) % 8)).encode(), casefold=True)
        resumen = hmac.new(clave, struct.pack(">Q", contador), hashlib.sha1).digest()
        offset = resumen[-1] & 0x0F
        valor = struct.unpack(">I", resumen[offset:offset + 4])[0] & 0x7FFFFFFF
        return str(valor % (10**digitos)).zfill(digitos)

    @classmethod
    def comprobar_totp(cls, secreto, codigo, instante=None, ventana=1):
        codigo = re.sub(r"\s+", "", str(codigo or ""))
        if not re.fullmatch(r"\d{6}", codigo):
            return False
        contador = int(instante if instante is not None else time.time()) // 30
        return any(hmac.compare_digest(codigo, cls._totp(secreto, contador + desfase))
                   for desfase in range(-ventana, ventana + 1))

    def uri_totp(self, usuario, secreto):
        etiqueta = quote(f"{self.emisor}:{usuario}", safe="")
        return "otpauth://totp/" + etiqueta + "?" + urlencode({
            "secret": secreto, "issuer": self.emisor, "algorithm": "SHA1",
            "digits": 6, "period": 30,
        })

    @staticmethod
    def qr_totp(uri):
        import io
        import qrcode
        from qrcode.image.svg import SvgPathFillImage
        imagen = qrcode.make(uri, image_factory=SvgPathFillImage, box_size=7, border=4)
        salida = io.BytesIO()
        imagen.save(salida)
        return "data:image/svg+xml;base64," + base64.b64encode(salida.getvalue()).decode()

    @staticmethod
    def generar_codigos(cantidad=10):
        salida = []
        for _ in range(cantidad):
            crudo = base64.b32encode(secrets.token_bytes(10)).decode().rstrip("=")
            salida.append("-".join(crudo[i:i + 4] for i in range(0, 16, 4)))
        return salida

    def hash_recuperacion(self, codigo):
        normal = re.sub(r"[^A-Za-z0-9]", "", str(codigo or "")).upper()
        return hmac.new(self.clave_recuperacion, normal.encode(), hashlib.sha256).hexdigest()

    def validar_factor(self, usuario, codigo):
        totp = usuario.get("totp") or {}
        if not totp.get("enabled"):
            return None
        secreto = self.descifrar(totp.get("secret"))
        if self.comprobar_totp(secreto, codigo):
            return ("totp", None)
        candidato = self.hash_recuperacion(codigo)
        for indice, esperado in enumerate(totp.get("recovery_code_hashes") or []):
            if hmac.compare_digest(candidato, esperado):
                return ("recovery", indice)
        return False

    def generar_clave_api(self):
        identificador = uuid.uuid4().hex
        secreto = secrets.token_urlsafe(32)
        token = f"fip_{identificador}_{secreto}"
        return identificador, token, hmac.new(
            self.clave_api, token.encode(), hashlib.sha256).hexdigest()

    def comprobar_clave_api(self, token, guardada):
        if not token or not guardada:
            return False
        calculada = hmac.new(
            self.clave_api, str(token).encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(calculada, str(guardada))


@dataclass(frozen=True)
class Identidad:
    usuario_id: str
    usuario: str
    nombre: str
    rol: str
    csrf: str
    vence: int
    version_sesion: int


class Sesiones:
    def __init__(self, secreto, horas=12):
        self.secreto = str(secreto or "").strip().encode()
        self.duracion = max(1, min(168, int(horas))) * 3600

    @property
    def disponible(self):
        return len(self.secreto) >= 32

    def crear(self, usuario):
        if not self.disponible:
            raise ErrorAcceso("Falta FIP_SESSION_SECRET", "AUTH_NOT_CONFIGURED", 503)
        ahora = int(time.time())
        datos = {
            "uid": usuario["id"], "sub": usuario["username"],
            "name": usuario.get("display_name") or usuario["username"],
            "role": usuario.get("role") or "reader",
            "sv": int(usuario.get("session_version") or 1),
            "csrf": secrets.token_urlsafe(24), "iat": ahora,
            "exp": ahora + self.duracion, "nonce": secrets.token_hex(12),
        }
        cuerpo = _b64(json.dumps(
            datos, separators=(",", ":"), ensure_ascii=False).encode())
        firma = _b64(hmac.new(self.secreto, cuerpo.encode("ascii"), hashlib.sha256).digest())
        return f"{cuerpo}.{firma}", Identidad(
            datos["uid"], datos["sub"], datos["name"], datos["role"],
            datos["csrf"], datos["exp"], datos["sv"],
        )

    def leer(self, token):
        if not token or not self.disponible or "." not in token:
            return None
        cuerpo, firma = token.split(".", 1)
        esperada = _b64(hmac.new(
            self.secreto, cuerpo.encode("ascii"), hashlib.sha256).digest())
        if not hmac.compare_digest(firma, esperada):
            return None
        try:
            d = json.loads(_b64d(cuerpo).decode())
            identidad = Identidad(
                str(d["uid"]), str(d["sub"]), str(d.get("name") or d["sub"]),
                validar_rol(d.get("role")), str(d["csrf"]), int(d["exp"]),
                int(d.get("sv") or 1),
            )
        except (ValueError, KeyError, TypeError, UnicodeError, ErrorAcceso):
            return None
        return identidad if identidad.vence > int(time.time()) else None


class AlmacenSeguridad:
    """Estado de credenciales con causalidad explícita y réplica fail-closed.

    Las revisiones antiguas 1.0.0 usaban un contador y una marca temporal. Esos
    valores no demuestran causalidad entre máquinas, por lo que al leerlos se
    convierten en un reloj vacío unido a la huella del contenido legacy. Dos
    contenidos legacy distintos quedan así en ramas incompatibles y nunca se
    desempatan por reloj de pared, nombre de nodo o hash.
    """

    def __init__(self, ruta, nodo):
        self.ruta = ruta
        self.ruta_candado = ruta + ".lock"
        # ``local`` conserva la importabilidad de herramientas/tests sin
        # entorno; el arranque real valida FIP_NODO contra la topología.
        self.nodo = str(nodo or "").strip() or "local"
        if (not PATRON_NODO.fullmatch(self.nodo)
                or self.nodo == _AUTOR_LEGACY):
            raise ErrorAcceso(
                "El autor del estado de acceso no es válido",
                "AUTH_REVISION_INVALID", 409,
            )
        self.candado = threading.RLock()

    def _vacio(self):
        datos = {"schema": 1, "users": [], "api_keys": []}
        datos["revision"] = self._revision_legacy(datos)
        return datos

    @staticmethod
    def _huella_contenido(datos):
        """Huella del contenido sensible, independiente de metadatos legacy."""
        contenido = _copia(datos)
        contenido.pop("revision", None)
        contenido.setdefault("api_keys", [])
        return hashlib.sha256(_json_canonico_acceso(contenido)).hexdigest()

    @classmethod
    def _revision_legacy(cls, datos):
        return {
            "schema": _REVISION_SCHEMA,
            "clock": {},
            "author": _AUTOR_LEGACY,
            "actor": None,
            "legacy_base": cls._huella_contenido(datos),
        }

    @classmethod
    def _normalizar_snapshot(cls, datos):
        """Copia y migra en memoria el formato escalar sin inventar historia."""
        cls.validar_snapshot(datos)
        normalizado = _copia(datos)
        normalizado.setdefault("api_keys", [])
        revision = normalizado.get("revision") or {}
        era_legacy = "counter" in revision
        if era_legacy:
            normalizado["revision"] = cls._revision_legacy(normalizado)
        cls.validar_snapshot(normalizado)
        _json_canonico_acceso(normalizado)
        return normalizado, era_legacy

    @contextmanager
    def _bloqueo_disco(self):
        directorio = os.path.dirname(self.ruta) or "."
        _comprobar_directorio_seguro(directorio)
        try:
            fd = _abrir_regular_seguro(
                self.ruta_candado, os.O_RDWR, crear=True)
        except ErrorAcceso:
            raise
        except OSError as error:
            raise ErrorAcceso(
                f"No se puede bloquear el estado de acceso: {error}",
                "AUTH_STORAGE_ERROR", 503,
            ) from error
        bloqueado = False
        try:
            if fcntl is not None:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                except OSError as error:
                    raise ErrorAcceso(
                        f"No se puede bloquear el estado de acceso: {error}",
                        "AUTH_STORAGE_ERROR", 503,
                    ) from error
                bloqueado = True
            yield
        finally:
            try:
                if fcntl is not None and bloqueado:
                    fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _leer(self):
        try:
            fd = _abrir_regular_seguro(self.ruta, os.O_RDONLY)
        except FileNotFoundError:
            return self._vacio()
        except ErrorAcceso:
            raise
        except OSError as error:
            raise ErrorAcceso(
                f"No se puede leer el estado de acceso: {error}", "AUTH_STORAGE_ERROR", 503,
            ) from error
        try:
            with os.fdopen(fd, "rb") as fichero:
                fd = -1
                if os.fstat(fichero.fileno()).st_size > _MAX_ESTADO_ACCESO_BYTES:
                    raise ErrorAcceso(
                        "El estado de acceso supera el máximo seguro de 512 KiB",
                        "AUTH_STATE_TOO_LARGE", 409,
                    )
                crudo = fichero.read(_MAX_ESTADO_ACCESO_BYTES + 1)
            if len(crudo) > _MAX_ESTADO_ACCESO_BYTES:
                raise ErrorAcceso(
                    "El estado de acceso supera el máximo seguro de 512 KiB",
                    "AUTH_STATE_TOO_LARGE", 409,
                )
            datos = json.loads(
                crudo.decode("utf-8"),
                object_pairs_hook=_objeto_json_sin_duplicados,
                parse_constant=lambda valor: (_ for _ in ()).throw(
                    ValueError(f"constante JSON no válida: {valor}")),
            )
        except ErrorAcceso:
            raise
        except (OSError, UnicodeError, ValueError, RecursionError) as error:
            raise ErrorAcceso(
                f"No se puede leer el estado de acceso: {error}",
                "AUTH_STORAGE_ERROR", 503,
            ) from error
        finally:
            if fd >= 0:
                os.close(fd)
        return self._normalizar_snapshot(datos)[0]

    @staticmethod
    def validar_snapshot(datos):
        _json_canonico_acceso(datos)

        def invalido(detalle):
            raise ErrorAcceso(
                f"El estado de acceso no tiene un formato válido: {detalle}",
                "AUTH_STATE_INVALID", 409,
            )

        def texto(valor, maximo, vacio=False):
            return isinstance(valor, str) and len(valor) <= maximo and (vacio or bool(valor))

        if not isinstance(datos, dict):
            invalido("la raíz debe ser un objeto")
        desconocidos = set(datos) - _CAMPOS_ESTADO
        if desconocidos:
            invalido("campos desconocidos en la raíz")
        if type(datos.get("schema")) is not int or datos.get("schema") != 1:
            invalido("schema desconocido")

        revision = datos.get("revision")
        if not isinstance(revision, dict):
            invalido("revision debe ser un objeto")
        if "counter" in revision:
            # Formato 1.0.0: se acepta sólo para migrarlo a un reloj vacío. El
            # timestamp nunca interviene en una elección entre contenidos.
            if set(revision) - _CAMPOS_REVISION_LEGACY:
                invalido("revision legacy contiene campos desconocidos")
            if not {"counter", "timestamp", "node"}.issubset(revision):
                invalido("revision legacy está incompleta")
            contador = revision.get("counter")
            instante = revision.get("timestamp")
            nodo, actor = revision.get("node"), revision.get("actor")
            if (type(contador) is not int or not 0 <= contador <= _MAX_CONTADOR
                    or type(instante) is not int
                    or not 0 <= instante <= _MAX_CONTADOR):
                invalido("contador o timestamp de revision no válidos")
            if contador == 0:
                if instante != 0 or nodo != "":
                    invalido("la revisión inicial debe ser vacía")
            elif (instante == 0 or not isinstance(nodo, str)
                  or not PATRON_NODO.fullmatch(nodo)):
                invalido("el nodo de revision no es válido")
            if actor is not None and not texto(actor, _MAX_ACTOR, vacio=False):
                invalido("el actor de revision no es válido")
        else:
            if set(revision) != _CAMPOS_REVISION_VECTOR:
                invalido(
                    "revision vectorial debe contener exactamente schema, "
                    "clock, author, actor y legacy_base")
            if (type(revision.get("schema")) is not int
                    or revision.get("schema") != _REVISION_SCHEMA):
                invalido("schema de revision desconocido")
            reloj = revision.get("clock")
            if not isinstance(reloj, dict) or len(reloj) > _MAX_AUTORES_REVISION:
                invalido("clock de revision no válido")
            for autor_reloj, contador in reloj.items():
                if (not isinstance(autor_reloj, str)
                        or not PATRON_NODO.fullmatch(autor_reloj)
                        or autor_reloj == _AUTOR_LEGACY
                        or type(contador) is not int
                        or not 1 <= contador <= _MAX_CONTADOR):
                    invalido("autor o contador del reloj no válido")
            autor = revision.get("author")
            actor = revision.get("actor")
            base = revision.get("legacy_base")
            if not isinstance(base, str) or not PATRON_SHA256.fullmatch(base):
                invalido("legacy_base de revision no es válido")
            if not reloj:
                if autor != _AUTOR_LEGACY or actor is not None:
                    invalido("la revisión causal inicial debe ser legacy")
                if base != AlmacenSeguridad._huella_contenido(datos):
                    invalido("legacy_base no corresponde al contenido inicial")
            else:
                if autor not in reloj:
                    invalido("el autor de revision no está en el reloj")
                if not texto(actor, _MAX_ACTOR, vacio=False):
                    invalido("el actor de revision no es válido")

        usuarios = datos.get("users")
        if not isinstance(usuarios, list):
            invalido("users debe ser una lista")
        if len(usuarios) > _MAX_USUARIOS:
            invalido(f"users supera {_MAX_USUARIOS} entradas")
        ids_usuarios, nombres_usuarios = set(), set()
        administrador_activo = False
        for usuario in usuarios:
            if not isinstance(usuario, dict):
                invalido("cada usuario debe ser un objeto")
            if set(usuario) != _CAMPOS_USUARIO:
                invalido("un usuario tiene campos ausentes o desconocidos")
            identificador = usuario.get("id")
            nombre_usuario = usuario.get("username")
            if (not isinstance(identificador, str)
                    or not PATRON_UUID.fullmatch(identificador)):
                invalido("identificador de usuario no válido")
            if not isinstance(nombre_usuario, str) or not PATRON_USUARIO.fullmatch(nombre_usuario):
                invalido("nombre de usuario no válido")
            if identificador in ids_usuarios or nombre_usuario.casefold() in nombres_usuarios:
                invalido("usuarios duplicados")
            ids_usuarios.add(identificador)
            nombres_usuarios.add(nombre_usuario.casefold())
            if not texto(usuario.get("display_name"), _MAX_TEXTO_NOMBRE):
                invalido("nombre visible no válido")
            if usuario.get("role") not in ROLES:
                invalido("rol de usuario no válido")
            if usuario.get("status") not in ("active", "disabled"):
                invalido("estado de usuario no válido")
            if (usuario.get("role") == "admin"
                    and usuario.get("status") == "active"):
                administrador_activo = True
            if _parametros_hash_clave(usuario.get("password_hash")) is None:
                invalido("hash de contraseña no válido")
            if type(usuario.get("password_change_required")) is not bool:
                invalido("password_change_required debe ser booleano")
            version_sesion = usuario.get("session_version")
            if (type(version_sesion) is not int
                    or not 1 <= version_sesion <= _MAX_CONTADOR):
                invalido("version de sesión no válida")
            for campo in ("created_at", "updated_at", "updated_by"):
                maximo = _MAX_ACTOR if campo == "updated_by" else _MAX_MARCA_TIEMPO
                if not texto(usuario.get(campo), maximo):
                    invalido(f"{campo} de usuario no válido")
            totp = usuario.get("totp")
            if not isinstance(totp, dict) or set(totp) != _CAMPOS_TOTP:
                invalido("totp no tiene el formato esperado")
            if type(totp.get("enabled")) is not bool:
                invalido("enabled de totp debe ser booleano")
            for campo in ("secret", "pending_secret"):
                secreto = totp.get(campo)
                if secreto is not None and not texto(secreto, _MAX_HASH_CREDENCIAL):
                    invalido(f"{campo} de totp no válido")
            codigos = totp.get("recovery_code_hashes")
            if (not isinstance(codigos, list)
                    or len(codigos) > _MAX_CODIGOS_RECUPERACION
                    or any(not isinstance(valor, str)
                           or not PATRON_SHA256.fullmatch(valor) for valor in codigos)
                    or len(codigos) != len(set(codigos))):
                invalido("códigos de recuperación no válidos")
            secreto = totp.get("secret")
            pendiente = totp.get("pending_secret")
            if totp["enabled"]:
                if secreto is None or pendiente is not None:
                    invalido("totp activo requiere secret y no admite pending_secret")
            elif secreto is not None or codigos:
                # Un setup aún no confirmado usa sólo pending_secret. El secreto
                # activo y los códigos nacen juntos al confirmar TOTP.
                invalido("totp inactivo no puede conservar secret ni códigos")

        if usuarios and not administrador_activo:
            invalido("debe existir al menos un administrador activo")

        claves = datos.get("api_keys", [])
        if not isinstance(claves, list):
            invalido("api_keys debe ser una lista")
        if len(claves) > _MAX_CLAVES_API:
            invalido(f"api_keys supera {_MAX_CLAVES_API} entradas")
        ids_claves, nombres_activas = set(), set()
        for clave in claves:
            if not isinstance(clave, dict) or set(clave) != _CAMPOS_CLAVE_API:
                invalido("una clave API tiene campos ausentes o desconocidos")
            identificador = clave.get("id")
            if (not isinstance(identificador, str)
                    or not PATRON_ID_CLAVE_API.fullmatch(identificador)
                    or identificador in ids_claves):
                invalido("identificador de clave API no válido o duplicado")
            ids_claves.add(identificador)
            nombre = clave.get("name")
            if not texto(nombre, _MAX_TEXTO_NOMBRE):
                invalido("nombre de clave API no válido")
            estado = clave.get("status")
            if estado not in ("active", "revoked"):
                invalido("estado de clave API no válido")
            if estado == "active":
                normalizado = nombre.casefold()
                if normalizado in nombres_activas:
                    invalido("nombres de claves API activas duplicados")
                nombres_activas.add(normalizado)
            if not texto(clave.get("prefix"), _MAX_PREFIJO_API):
                invalido("prefijo de clave API no válido")
            token_hash = clave.get("token_hash")
            if estado == "active":
                if (not isinstance(token_hash, str)
                        or not PATRON_SHA256.fullmatch(token_hash)):
                    invalido("hash de clave API activa no válido")
            elif token_hash is not None:
                invalido("una clave API revocada no debe conservar su hash")
            scopes = clave.get("scopes")
            if (not isinstance(scopes, list) or not scopes
                    or len(scopes) > len(PERMISOS_API)
                    or any(not isinstance(scope, str) for scope in scopes)
                    or len(scopes) != len(set(scopes))
                    or any(scope not in PERMISOS_API for scope in scopes)):
                invalido("permisos de clave API no válidos")
            for campo in ("created_at", "created_by"):
                maximo = _MAX_ACTOR if campo == "created_by" else _MAX_MARCA_TIEMPO
                if not texto(clave.get(campo), maximo):
                    invalido(f"{campo} de clave API no válido")
            for campo in ("revoked_at", "revoked_by"):
                valor = clave.get(campo)
                maximo = _MAX_ACTOR if campo == "revoked_by" else _MAX_MARCA_TIEMPO
                if valor is not None and not texto(valor, maximo):
                    invalido(f"{campo} de clave API no válido")
            revocada_en, revocada_por = (
                clave.get("revoked_at"), clave.get("revoked_by"))
            if estado == "active" and (
                    revocada_en is not None or revocada_por is not None):
                invalido("una clave API activa no puede tener datos de revocación")
            if estado == "revoked" and (
                    revocada_en is None or revocada_por is None):
                invalido("una clave API revocada requiere fecha y actor")

    def leer(self):
        with self.candado:
            with self._bloqueo_disco():
                return _copia(self._leer())

    def leer_con_estado(self):
        """Devuelve ``(snapshot, initialized)`` bajo un único flock.

        El sobre de réplica no puede obtener primero la existencia y después
        el contenido mediante dos aperturas independientes: durante un relevo
        de procesos podría anunciar un vacío sintético como fichero real (o al
        revés). Todas las instancias que respetan el lock observan aquí ambos
        valores como una sola lectura atómica.
        """
        with self.candado:
            with self._bloqueo_disco():
                if _estado_regular_seguro(
                        self.ruta, permitir_ausente=True) is None:
                    return _copia(self._vacio()), False
                return _copia(self._leer()), True

    def existe(self):
        """Distingue ausencia real de un fichero presente con estado vacío.

        El transporte usa esta señal para restaurar un nodo reemplazado sin
        convertir su vacío sintético en una rama legacy con derecho a voto.
        """
        with self.candado:
            with self._bloqueo_disco():
                if _estado_regular_seguro(
                        self.ruta, permitir_ausente=True) is None:
                    return False
                fd = _abrir_regular_seguro(self.ruta, os.O_RDONLY)
                os.close(fd)
                return True

    def _escribir(self, datos):
        datos, _ = self._normalizar_snapshot(datos)
        _json_canonico_acceso(datos)
        try:
            serializado = (json.dumps(
                datos, ensure_ascii=False, indent=2, sort_keys=True,
                allow_nan=False,
            ) + "\n").encode("utf-8")
        except (TypeError, ValueError, RecursionError, OverflowError) as error:
            raise ErrorAcceso(
                f"No se puede serializar el estado de acceso: {error}",
                "AUTH_STATE_INVALID", 409,
            ) from error
        if len(serializado) > _MAX_ESTADO_ACCESO_BYTES:
            raise ErrorAcceso(
                "El estado de acceso persistido supera el máximo seguro de 512 KiB",
                "AUTH_STATE_TOO_LARGE", 409,
            )
        directorio = os.path.dirname(self.ruta) or "."
        _comprobar_directorio_seguro(directorio)
        fd, temporal = tempfile.mkstemp(
            prefix=".security.", suffix=".tmp", dir=directorio)
        publicado = False
        try:
            _normalizar_descriptor_seguro(fd, temporal)
            with os.fdopen(fd, "wb") as fichero:
                fd = -1
                fichero.write(serializado)
                fichero.flush()
                os.fsync(fichero.fileno())
            _estado_regular_seguro(self.ruta, permitir_ausente=True)
            os.replace(temporal, self.ruta)
            publicado = True
            if hasattr(os, "O_DIRECTORY"):
                try:
                    fd_dir = _abrir_directorio_seguro(directorio)
                    try:
                        os.fsync(fd_dir)
                    finally:
                        os.close(fd_dir)
                except OSError as error:
                    if error.errno not in _ERRORES_FSYNC_DIR_NO_SOPORTADO:
                        raise
        except Exception as error:
            try:
                os.unlink(temporal)
            except OSError:
                pass
            if publicado:
                raise ErrorAcceso(
                    "El cambio de acceso ya es visible localmente, pero no se "
                    "pudo confirmar su durabilidad; consulta el estado antes "
                    "de reintentar",
                    "AUTH_COMMIT_UNCERTAIN", 503,
                ) from error
            raise
        finally:
            if fd >= 0:
                os.close(fd)

    @staticmethod
    def huella(datos):
        normalizado, _ = AlmacenSeguridad._normalizar_snapshot(datos)
        return hashlib.sha256(_json_canonico_acceso(normalizado)).hexdigest()

    @staticmethod
    def _reloj(datos):
        return dict((datos.get("revision") or {}).get("clock") or {})

    @staticmethod
    def _domina(reloj_a, reloj_b):
        autores = set(reloj_a) | set(reloj_b)
        return (
            all(reloj_a.get(autor, 0) >= reloj_b.get(autor, 0)
                for autor in autores)
            and any(reloj_a.get(autor, 0) > reloj_b.get(autor, 0)
                    for autor in autores)
        )

    @classmethod
    def _clasificar_normalizados(cls, actual, entrante):
        rev_actual = actual["revision"]
        rev_entrante = entrante["revision"]
        reloj_actual = cls._reloj(actual)
        reloj_entrante = cls._reloj(entrante)
        if rev_actual["legacy_base"] != rev_entrante["legacy_base"]:
            # Una revisión vectorial nacida de A no demuestra haber observado
            # un contenido legacy B. Considerarlas relacionadas perdería
            # credenciales silenciosamente durante una actualización parcial.
            return "conflicto_concurrente"
        if reloj_actual == reloj_entrante:
            if cls.huella(actual) == cls.huella(entrante):
                return "identica"
            return "conflicto_misma_revision"
        if cls._domina(reloj_entrante, reloj_actual):
            return "nueva"
        if cls._domina(reloj_actual, reloj_entrante):
            return "obsoleta"
        return "conflicto_concurrente"

    @classmethod
    def clasificar_replica(cls, actual, entrante):
        """Clasifica causalmente sin usar timestamps ni desempates arbitrarios."""
        actual_n, _ = cls._normalizar_snapshot(actual)
        entrante_n, _ = cls._normalizar_snapshot(entrante)
        return cls._clasificar_normalizados(actual_n, entrante_n)

    @classmethod
    def seleccionar_dominante(cls, candidatos):
        """Devuelve el único snapshot que domina causalmente a todos.

        El quorum pertenece al transporte. Esta función sólo evita que una
        mayoría numérica sustituya una rama concurrente o un legacy divergente.
        """
        normalizados = [cls._normalizar_snapshot(valor)[0]
                        for valor in candidatos]
        if not normalizados:
            raise ErrorAcceso(
                "No hay estados de acceso para reconciliar",
                "AUTH_RECONCILIATION_EMPTY", 409,
            )
        dominantes = {}
        for candidato in normalizados:
            if all(
                cls._clasificar_normalizados(otro, candidato)
                in ("identica", "nueva")
                for otro in normalizados
            ):
                dominantes[cls.huella(candidato)] = candidato
        if len(dominantes) != 1:
            raise ErrorAcceso(
                "Los estados de acceso son concurrentes o discrepan con la "
                "misma revisión; hace falta reconciliación manual",
                "AUTH_REPLICA_CONFLICT", 409,
            )
        return _copia(next(iter(dominantes.values())))

    @classmethod
    def clave_revision(cls, datos):
        """Representación estable para diagnóstico; no define orden causal."""
        normalizado, _ = cls._normalizar_snapshot(datos)
        return (tuple(sorted(cls._reloj(normalizado).items())),
                cls.huella(normalizado))

    def aplicar_replica(self, entrante):
        candidato, _ = self._normalizar_snapshot(entrante)
        with self.candado:
            with self._bloqueo_disco():
                if _estado_regular_seguro(
                        self.ruta, permitir_ausente=True) is None:
                    self._escribir(candidato)
                    return True
                actual = self._leer()
                relacion = self._clasificar_normalizados(actual, candidato)
                if relacion == "identica":
                    return False
                if relacion == "nueva":
                    self._escribir(candidato)
                    return True
                if relacion == "obsoleta":
                    raise ErrorAcceso(
                        "La réplica de acceso es anterior al estado local", "AUTH_REPLICA_STALE", 409,
                    )
                if relacion == "conflicto_misma_revision":
                    raise ErrorAcceso(
                        "La réplica de acceso tiene la misma revisión pero otro contenido",
                        "AUTH_REPLICA_EQUAL_REVISION_CONFLICT", 409,
                    )
                raise ErrorAcceso(
                    "La réplica y el estado local contienen mutaciones concurrentes",
                    "AUTH_REPLICA_CONCURRENT", 409,
                )

    def _avanzar_revision(self, datos, actor):
        rev = datos["revision"]
        reloj = dict(rev.get("clock") or {})
        if self.nodo not in reloj and len(reloj) >= _MAX_AUTORES_REVISION:
            raise ErrorAcceso(
                "La revisión contiene demasiados autores",
                "AUTH_REVISION_INVALID", 409,
            )
        contador = reloj.get(self.nodo, 0)
        if contador >= _MAX_CONTADOR:
            raise ErrorAcceso(
                "El contador del estado de acceso está agotado",
                "AUTH_REVISION_EXHAUSTED", 409,
            )
        reloj[self.nodo] = contador + 1
        datos["revision"] = {
            "schema": _REVISION_SCHEMA,
            "clock": dict(sorted(reloj.items())),
            "author": self.nodo,
            "actor": str(actor or "system")[:_MAX_ACTOR],
            "legacy_base": rev["legacy_base"],
        }

    def _mutar(self, actor, funcion):
        with self.candado:
            with self._bloqueo_disco():
                datos = self._leer()
                resultado = funcion(datos)
                self._avanzar_revision(datos, actor)
                self._escribir(datos)
                return _copia(resultado), _copia(datos)

    def inicializar_revision(self, actor="system"):
        """Convierte un legacy elegido por quorum en la primera revisión real.

        El servidor sólo debe llamarlo en el escritor lógico fijo y después de
        comprobar que un quorum observa exactamente el mismo contenido legacy.
        """
        with self.candado:
            with self._bloqueo_disco():
                actual = self._leer()
                if self._reloj(actual):
                    return _copia(actual)
                self._avanzar_revision(actual, actor)
                self._escribir(actual)
                return _copia(actual)

    def inicializar_desde_candidato(self, candidato, actor="system"):
        """Materializa un legacy elegido como una única escritura causal.

        El bootstrap no debe escribir primero el legacy y causalizarlo en un
        segundo rename: una caída entre ambos dejaría un único fichero con
        derecho a voto que no alcanza quorum. Esta operación avanza el reloj en
        memoria y sólo entonces publica. También es idempotente tras un commit
        incierto: si el rename causal ya quedó visible, devuelve esa revisión
        dominante sin incrementarla de nuevo.

        La capa de clúster sigue siendo responsable de exigir marker, escritor
        fijo, quorum y de reanudar la propagación mientras el marker exista.
        """
        candidato, _ = self._normalizar_snapshot(candidato)
        if self._reloj(candidato):
            raise ErrorAcceso(
                "La inicialización requiere un candidato legacy",
                "AUTH_REVISION_INVALID", 409,
            )
        with self.candado:
            with self._bloqueo_disco():
                if _estado_regular_seguro(
                        self.ruta, permitir_ausente=True) is None:
                    actual = candidato
                else:
                    actual = self._leer()
                    relacion = self._clasificar_normalizados(actual, candidato)
                    if relacion == "obsoleta" and self._reloj(actual):
                        # Reanudación tras rename visible/ACK pendiente. El
                        # actual demuestra haber observado este mismo legacy.
                        return _copia(actual)
                    if relacion != "identica":
                        codigo = (
                            "AUTH_REPLICA_EQUAL_REVISION_CONFLICT"
                            if relacion == "conflicto_misma_revision"
                            else "AUTH_REPLICA_CONCURRENT"
                        )
                        raise ErrorAcceso(
                            "El estado local no coincide con el legacy elegido "
                            "para inicializar",
                            codigo, 409,
                        )
                self._avanzar_revision(actual, actor)
                self._escribir(actual)
                return _copia(actual)

    @staticmethod
    def publico(usuario):
        totp = usuario.get("totp") or {}
        return {
            "id": usuario.get("id"), "username": usuario.get("username"),
            "display_name": usuario.get("display_name"),
            "role": usuario.get("role", "reader"), "status": usuario.get("status", "active"),
            "two_factor_enabled": bool(totp.get("enabled")),
            "two_factor_pending": bool(totp.get("pending_secret")),
            "recovery_codes_remaining": len(totp.get("recovery_code_hashes") or []),
            "password_change_required": bool(usuario.get("password_change_required")),
            "created_at": usuario.get("created_at"), "updated_at": usuario.get("updated_at"),
            "updated_by": usuario.get("updated_by"),
        }

    @staticmethod
    def _buscar(datos, usuario_id):
        return next((u for u in datos["users"] if u.get("id") == usuario_id), None)

    def tiene_usuarios(self):
        return bool(self.leer()["users"])

    def listar(self):
        return [self.publico(u) for u in self.leer()["users"]]

    @staticmethod
    def clave_api_publica(clave):
        return {
            "id": clave.get("id"), "name": clave.get("name"),
            "prefix": clave.get("prefix"), "scopes": list(clave.get("scopes") or []),
            "status": clave.get("status", "active"),
            "created_at": clave.get("created_at"), "created_by": clave.get("created_by"),
            "revoked_at": clave.get("revoked_at"), "revoked_by": clave.get("revoked_by"),
        }

    def listar_claves_api(self):
        return [self.clave_api_publica(c) for c in self.leer().get("api_keys", [])]

    def clave_api_por_id(self, identificador):
        for clave in self.leer().get("api_keys", []):
            if clave.get("id") == identificador:
                return _copia(clave)
        return None

    def crear_clave_api(self, identificador, nombre, prefijo, hash_token, permisos, actor):
        nombre = " ".join(str(nombre or "").split())
        if not nombre or len(nombre) > 120:
            raise ErrorAcceso(
                "El nombre de la aplicación debe tener entre 1 y 120 caracteres",
                "INVALID_API_KEY", 422,
            )
        permisos = list(dict.fromkeys(str(p) for p in (permisos or [])))
        if not permisos or any(p not in PERMISOS_API for p in permisos):
            raise ErrorAcceso(
                "La clave API debe tener al menos un permiso válido",
                "INVALID_API_SCOPE", 422,
            )

        def crear(datos):
            existente = next((
                c for c in datos.get("api_keys", [])
                if c.get("status", "active") == "active"
                and str(c.get("name") or "").casefold() == nombre.casefold()
            ), None)
            if existente:
                raise ErrorAcceso(
                    f"Ya existe una clave activa llamada «{existente.get('name')}»",
                    "API_KEY_CONFLICT", 409,
                )
            clave = {
                "id": identificador, "name": nombre, "prefix": prefijo,
                "token_hash": hash_token, "scopes": permisos, "status": "active",
                "created_at": _ahora_iso(), "created_by": actor,
                "revoked_at": None, "revoked_by": None,
            }
            datos.setdefault("api_keys", []).append(clave)
            return clave

        clave, snapshot = self._mutar(actor, crear)
        return self.clave_api_publica(clave), snapshot

    def revocar_clave_api(self, identificador, actor):
        def revocar(datos):
            clave = next((c for c in datos.get("api_keys", [])
                          if c.get("id") == identificador), None)
            if not clave:
                raise ErrorAcceso("La clave API no existe", "API_KEY_NOT_FOUND", 404)
            if clave.get("status") == "revoked":
                return clave
            clave.update({
                "status": "revoked", "revoked_at": _ahora_iso(), "revoked_by": actor,
                # None elimina el hash revocado; no es una credencial incrustada.
                "token_hash": None,  # nosec B105
            })
            return clave

        clave, snapshot = self._mutar(actor, revocar)
        return self.clave_api_publica(clave), snapshot

    def por_id(self, usuario_id):
        usuario = self._buscar(self.leer(), usuario_id)
        return _copia(usuario) if usuario else None

    def por_nombre(self, nombre):
        esperado = str(nombre or "").strip().casefold()
        for usuario in self.leer()["users"]:
            if str(usuario.get("username") or "").casefold() == esperado:
                return usuario
        return None

    @staticmethod
    def _nuevo(usuario, nombre, clave_hash, rol, actor, cambio_obligatorio):
        ahora = _ahora_iso()
        return {
            "id": str(uuid.uuid4()), "username": usuario, "display_name": nombre,
            "role": rol, "status": "active", "password_hash": clave_hash,
            "password_change_required": cambio_obligatorio, "session_version": 1,
            "totp": {
                "enabled": False,
                # None representa la ausencia deliberada de secretos TOTP.
                "secret": None,  # nosec B105
                "pending_secret": None,  # nosec B105
                "recovery_code_hashes": [],
            },
            "created_at": ahora, "updated_at": ahora, "updated_by": actor,
        }

    def crear_propietario(self, usuario, nombre, clave_hash):
        def crear(datos):
            if datos["users"]:
                raise ErrorAcceso(
                    "El registro inicial ya está cerrado", "REGISTRATION_COMPLETE", 409)
            nuevo = self._nuevo(usuario, nombre, clave_hash, "admin", usuario, False)
            datos["users"].append(nuevo)
            return nuevo
        usuario_nuevo, snapshot = self._mutar(usuario, crear)
        return usuario_nuevo, snapshot

    def crear_usuario(self, usuario, nombre, clave_hash, rol, actor):
        def crear(datos):
            if any(u["username"].casefold() == usuario.casefold() for u in datos["users"]):
                raise ErrorAcceso("Ese nombre de usuario ya está en uso", "USERNAME_CONFLICT", 409)
            nuevo = self._nuevo(usuario, nombre, clave_hash, rol, actor, True)
            datos["users"].append(nuevo)
            return nuevo
        nuevo, snapshot = self._mutar(actor, crear)
        return self.publico(nuevo), snapshot

    @staticmethod
    def _administradores_activos(datos):
        return [u for u in datos["users"]
                if u.get("role") == "admin" and u.get("status", "active") == "active"]

    def actualizar_acceso(self, usuario_id, actor, cambios):
        def cambiar(datos):
            usuario = self._buscar(datos, usuario_id)
            if not usuario:
                raise ErrorAcceso("La cuenta no existe", "USER_NOT_FOUND", 404)
            if "username" in cambios:
                nombre_usuario = normalizar_usuario(cambios["username"])
                if any(u["id"] != usuario_id and u["username"].casefold() == nombre_usuario.casefold()
                       for u in datos["users"]):
                    raise ErrorAcceso("Ese nombre de usuario ya está en uso", "USERNAME_CONFLICT", 409)
                usuario["username"] = nombre_usuario
            if "display_name" in cambios:
                usuario["display_name"] = normalizar_nombre(cambios["display_name"])
            rol = validar_rol(cambios["role"]) if "role" in cambios else usuario["role"]
            estado = str(cambios.get("status", usuario["status"]))
            if estado not in ("active", "disabled"):
                raise ErrorAcceso("El estado debe ser active o disabled", "INVALID_STATUS", 422)
            ultimo = (usuario.get("role") == "admin" and usuario.get("status") == "active"
                      and len(self._administradores_activos(datos)) == 1)
            if ultimo and (rol != "admin" or estado != "active"):
                raise ErrorAcceso(
                    "No se puede desactivar o degradar la última cuenta administradora",
                    "LAST_ADMIN_REQUIRED", 409,
                )
            usuario["role"], usuario["status"] = rol, estado
            usuario["session_version"] = int(usuario.get("session_version") or 1) + 1
            usuario["updated_at"], usuario["updated_by"] = _ahora_iso(), actor
            return usuario
        cambiado, snapshot = self._mutar(actor, cambiar)
        return self.publico(cambiado), snapshot

    def restablecer_usuario(self, usuario_id, clave_hash, actor):
        def cambiar(datos):
            usuario = self._buscar(datos, usuario_id)
            if not usuario:
                raise ErrorAcceso("La cuenta no existe", "USER_NOT_FOUND", 404)
            usuario["password_hash"] = clave_hash
            usuario["password_change_required"] = True
            usuario["session_version"] = int(usuario.get("session_version") or 1) + 1
            usuario["totp"] = {
                "enabled": False,
                # El restablecimiento borra ambos secretos TOTP.
                "secret": None,  # nosec B105
                "pending_secret": None,  # nosec B105
                "recovery_code_hashes": [],
            }
            usuario["updated_at"], usuario["updated_by"] = _ahora_iso(), actor
            return usuario
        cambiado, snapshot = self._mutar(actor, cambiar)
        return self.publico(cambiado), snapshot

    def actualizar_perfil(self, usuario_id, nombre, actor):
        def cambiar(datos):
            usuario = self._buscar(datos, usuario_id)
            usuario["display_name"] = normalizar_nombre(nombre)
            usuario["updated_at"], usuario["updated_by"] = _ahora_iso(), actor
            return usuario
        cambiado, snapshot = self._mutar(actor, cambiar)
        return self.publico(cambiado), snapshot

    def cambiar_clave(self, usuario_id, clave_hash, actor):
        def cambiar(datos):
            usuario = self._buscar(datos, usuario_id)
            usuario["password_hash"] = clave_hash
            usuario["password_change_required"] = False
            usuario["session_version"] = int(usuario.get("session_version") or 1) + 1
            usuario["updated_at"], usuario["updated_by"] = _ahora_iso(), actor
            return usuario
        cambiado, snapshot = self._mutar(actor, cambiar)
        return cambiado, snapshot

    def preparar_2fa(self, usuario_id, secreto_cifrado, actor):
        def cambiar(datos):
            usuario = self._buscar(datos, usuario_id)
            if usuario["totp"].get("enabled"):
                raise ErrorAcceso("2FA ya está activo", "TWO_FACTOR_ALREADY_ENABLED", 409)
            usuario["totp"]["pending_secret"] = secreto_cifrado
            return usuario
        return self._mutar(actor, cambiar)[1]

    def cancelar_2fa(self, usuario_id, actor):
        def cambiar(datos):
            usuario = self._buscar(datos, usuario_id)
            usuario["totp"]["pending_secret"] = None
            return usuario
        return self._mutar(actor, cambiar)[1]

    def activar_2fa(self, usuario_id, hashes, actor):
        def cambiar(datos):
            usuario = self._buscar(datos, usuario_id)
            pendiente = usuario["totp"].get("pending_secret")
            if not pendiente:
                raise ErrorAcceso(
                    "Inicia primero la configuración 2FA", "TWO_FACTOR_SETUP_MISSING", 409,
                )
            usuario["totp"].update({
                "enabled": True,
                "secret": pendiente,
                # Activar TOTP consume el secreto pendiente.
                "pending_secret": None,  # nosec B105
                "recovery_code_hashes": hashes,
            })
            usuario["session_version"] = int(usuario.get("session_version") or 1) + 1
            return usuario
        return self._mutar(actor, cambiar)

    def desactivar_2fa(self, usuario_id, actor):
        def cambiar(datos):
            usuario = self._buscar(datos, usuario_id)
            usuario["totp"] = {
                "enabled": False,
                # Desactivar TOTP borra ambos secretos.
                "secret": None,  # nosec B105
                "pending_secret": None,  # nosec B105
                "recovery_code_hashes": [],
            }
            usuario["session_version"] = int(usuario.get("session_version") or 1) + 1
            return usuario
        return self._mutar(actor, cambiar)

    def reemplazar_codigos(self, usuario_id, hashes, actor):
        def cambiar(datos):
            usuario = self._buscar(datos, usuario_id)
            usuario["totp"]["recovery_code_hashes"] = hashes
            return usuario
        return self._mutar(actor, cambiar)

    def consumir_codigo(self, usuario_id, indice, actor, hash_esperado=None):
        def cambiar(datos):
            usuario = self._buscar(datos, usuario_id)
            hashes = list(usuario["totp"].get("recovery_code_hashes") or [])
            if hash_esperado is not None:
                indice_encontrado = next((
                    posicion for posicion, valor in enumerate(hashes)
                    if hmac.compare_digest(valor, hash_esperado)
                ), None)
                if indice_encontrado is None:
                    raise ErrorAcceso(
                        "El código de recuperación ya no está disponible",
                        "RECOVERY_CODE_USED", 409,
                    )
                indice_local = indice_encontrado
            else:
                indice_local = indice
            if (type(indice_local) is not int
                    or indice_local < 0 or indice_local >= len(hashes)):
                raise ErrorAcceso(
                    "El código de recuperación ya no está disponible", "RECOVERY_CODE_USED", 409,
                )
            hashes.pop(indice_local)
            usuario["totp"]["recovery_code_hashes"] = hashes
            return usuario
        return self._mutar(actor, cambiar)


class ProtocoloCluster:
    """Firma anti-replay y cifrado de la réplica de cuentas entre nodos."""
    def __init__(self, token, nodo, nodos_validos):
        self.token = str(token or "").strip().encode()
        self.nodo = nodo
        self.nodos_validos = set(nodos_validos or [])
        clave = base64.urlsafe_b64encode(hashlib.sha256(self.token).digest())
        self.fernet = Fernet(clave) if len(self.token) >= 32 else None
        self.nonces = {}
        self.candado = threading.Lock()

    @property
    def disponible(self):
        return self.fernet is not None

    @staticmethod
    def _canonico(metodo, ruta, fuente, instante, nonce, cuerpo):
        return "\n".join((metodo.upper(), ruta, fuente, str(instante), nonce,
                          hashlib.sha256(cuerpo).hexdigest())).encode()

    def firmar(self, metodo, ruta, cuerpo=b""):
        if not self.disponible:
            raise ErrorAcceso("Falta FIP_CLUSTER_TOKEN", "CLUSTER_AUTH_NOT_CONFIGURED", 503)
        instante, nonce = int(time.time()), secrets.token_urlsafe(18)
        firma = hmac.new(
            self.token, self._canonico(metodo, ruta, self.nodo, instante, nonce, cuerpo),
            hashlib.sha256,
        ).hexdigest()
        return {"X-FIP-Node": self.nodo, "X-FIP-Timestamp": str(instante),
                "X-FIP-Nonce": nonce, "X-FIP-Signature": firma}

    def verificar(self, metodo, ruta, cuerpo, cabeceras):
        if not self.disponible:
            raise ErrorAcceso("Falta FIP_CLUSTER_TOKEN", "CLUSTER_AUTH_NOT_CONFIGURED", 503)
        fuente = str(cabeceras.get("X-FIP-Node") or "")
        nonce = str(cabeceras.get("X-FIP-Nonce") or "")
        firma = str(cabeceras.get("X-FIP-Signature") or "")
        try:
            instante = int(cabeceras.get("X-FIP-Timestamp") or 0)
        except ValueError as error:
            raise ErrorAcceso("Firma interna inválida", "INVALID_CLUSTER_SIGNATURE", 401) from error
        if (not fuente or (self.nodos_validos and fuente not in self.nodos_validos)
                or not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", nonce)
                or abs(int(time.time()) - instante) > 90):
            raise ErrorAcceso("Firma interna inválida o caducada", "INVALID_CLUSTER_SIGNATURE", 401)
        esperada = hmac.new(
            self.token, self._canonico(metodo, ruta, fuente, instante, nonce, cuerpo),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(firma, esperada):
            raise ErrorAcceso("Firma interna inválida", "INVALID_CLUSTER_SIGNATURE", 401)
        with self.candado:
            ahora_monotono = time.monotonic()
            limite = ahora_monotono - _VENTANA_NONCE_CLUSTER
            self.nonces = {
                valor: marca for valor, marca in self.nonces.items()
                if marca > limite
            }
            if nonce in self.nonces:
                raise ErrorAcceso("La petición interna ya fue utilizada", "CLUSTER_REPLAY", 409)
            if len(self.nonces) >= _MAX_NONCES_CLUSTER:
                raise ErrorAcceso(
                    "La protección anti-replay está temporalmente saturada",
                    "CLUSTER_REPLAY_CACHE_FULL", 503,
                )
            self.nonces[nonce] = ahora_monotono
        return fuente

    def cifrar(self, datos):
        if not self.fernet:
            raise ErrorAcceso("Falta FIP_CLUSTER_TOKEN", "CLUSTER_AUTH_NOT_CONFIGURED", 503)
        try:
            crudo = json.dumps(
                datos, ensure_ascii=False, separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError, RecursionError, OverflowError) as error:
            raise ErrorAcceso(
                "El mensaje interno no contiene JSON válido",
                "INVALID_SECURITY_REPLICA", 400,
            ) from error
        if len(crudo) > _MAX_MENSAJE_CLUSTER_BYTES:
            raise ErrorAcceso(
                "El mensaje interno supera el tamaño permitido",
                "INVALID_SECURITY_REPLICA", 400,
            )
        return self.fernet.encrypt(crudo).decode("ascii")

    def descifrar(self, sobre):
        if not self.fernet:
            raise ErrorAcceso("Falta FIP_CLUSTER_TOKEN", "CLUSTER_AUTH_NOT_CONFIGURED", 503)
        try:
            if (not isinstance(sobre, str)
                    or len(sobre.encode("utf-8")) > _MAX_SOBRE_CLUSTER_BYTES):
                raise ValueError("sobre cifrado demasiado grande")
            crudo = self.fernet.decrypt(sobre.encode())
            if len(crudo) > _MAX_MENSAJE_CLUSTER_BYTES:
                raise ValueError("mensaje cifrado demasiado grande")
            return json.loads(
                crudo.decode("utf-8"),
                object_pairs_hook=_objeto_json_sin_duplicados,
                parse_constant=lambda valor: (_ for _ in ()).throw(
                    ValueError(f"constante JSON no válida: {valor}")),
            )
        except (InvalidToken, ValueError, TypeError, UnicodeError,
                RecursionError) as error:
            raise ErrorAcceso(
                "La réplica de acceso no es válida", "INVALID_SECURITY_REPLICA", 400,
            ) from error
