"""El pool de direcciones flotantes: leer, validar y escribir el registro.

El registro vive en un JSON persistente dentro de FIP_DATOS. Dar de alta una
dirección aquí NO toca keepalived: es apuntar en una libreta. La dirección solo
existe en la red cuando un servicio la reclama y se despliega.

Las reglas de validación son las mismas que aplica deploy-floating-ip.sh antes de
escribir configuración, y por el mismo motivo: un vrid repetido no falla con un
error, hace que dos servicios se peleen en silencio por las direcciones del otro.
"""
import hashlib
import errno
import json
import os
import re
import stat
import tempfile
import threading
from contextlib import contextmanager
from copy import deepcopy
from datetime import datetime, timezone

try:
    import fcntl
except ImportError:  # pragma: no cover - el runtime soportado es Linux.
    fcntl = None

ESTADOS = ("libre", "reservada", "en_uso")

_IPV4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
_CLAVE_RECLAMACION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_SERVICIO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_RUTA_CHEQUEO = re.compile(r"^/[A-Za-z0-9._~:/?&=%+#-]*$")
_AUTOR_REVISION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_REVISION_SCHEMA = 1
_AUTOR_LEGACY = "legacy"
_MAX_AUTORES_REVISION = 64
_MAX_CONTADOR_REVISION = 2**63 - 1
_MAX_SNAPSHOT_BYTES = 512 * 1024
# Cada VIP activa un vrrp_script que puede crear un proceso de comprobación.
# 64 conserva holgura bajo el pids_limit=256 de la distribución v1.
_MAX_DIRECCIONES = 64
_MAX_MANTENIMIENTO = 64
_MAX_RECLAMACIONES = 2048
_MAX_RECLAMACIONES_ACTIVAS = _MAX_DIRECCIONES
# Una reclamación liberada puede conservar ~2,2 KiB de notas/reserva. Con 64
# VIP, 64 claims activos y 64 tombstones en sus máximos, el snapshot completo
# sigue dejando holgura bajo 512 KiB. Un límite por miles agotaría bytes mucho
# antes que entradas y no permitiría persistir la propia poda.
_MAX_TOMBSTONES_RECLAMACION = 64
_MAX_PUERTOS = 64
_MAX_DESCRIPCION = 200
_MAX_NOTAS = 2000
_MAX_RUTA_CHEQUEO = 256
_MAX_MARCA_TIEMPO = 64
_HUELLA_SHA256 = re.compile(r"^[0-9a-f]{64}$")

_CAMPOS_RAIZ = {
    "version", "actualizado", "revision", "dhcp_desde", "mantenimiento",
    "direcciones", "reclamaciones", "vrids_quemados",
}
_CAMPOS_DIRECCION = {
    "ip", "vrid", "estado", "servicio", "descripcion", "puertos",
    "chequeo", "preferente", "notas", "creada",
}
_CAMPOS_CHEQUEO = {"puerto", "ruta"}
_CAMPOS_RECLAMACION = {
    "schema", "ip", "servicio", "huella", "estado", "creada", "liberada",
    "reserva_anterior",
}
_CAMPOS_RESERVA_ANTERIOR = {
    "estado", "servicio", "descripcion", "notas", "preferente",
}
_ERRORES_FSYNC_DIR_NO_SOPORTADO = {
    errno.EINVAL,
    getattr(errno, "ENOTSUP", errno.EINVAL),
    getattr(errno, "EOPNOTSUPP", errno.EINVAL),
    getattr(errno, "ENOSYS", errno.EINVAL),
}


def _puerto_valido(puerto):
    return isinstance(puerto, int) and not isinstance(puerto, bool) and 1 <= puerto <= 65535


def identificador_vrrp(servicio):
    """Nombre exacto que usa keepalived para la instancia de un servicio."""
    return servicio.upper().replace("-", "_")


def ahora():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _vacio():
    datos = {
        "version": 1,
        "actualizado": ahora(),
        "dhcp_desde": 100,
        "mantenimiento": [],
        "direcciones": [],
        "reclamaciones": {},
    }
    datos["revision"] = _revision_legacy(datos)
    return datos


def _huella_base_legacy(datos):
    """Identifica el contenido heredado sin metadatos informativos."""
    contenido = deepcopy(datos)
    contenido.pop("revision", None)
    contenido.pop("actualizado", None)
    contenido.pop("vrids_quemados", None)
    canonico = json.dumps(
        contenido, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonico).hexdigest()


def _revision_legacy(datos):
    """Revisión causal común para registros anteriores a este contrato.

    El reloj vacío no afirma que un nodo haya escrito el registro. La primera
    mutación local lo convierte en una revisión normal del nodo que la realiza.
    """
    return {
        "schema": _REVISION_SCHEMA,
        "clock": {},
        "author": _AUTOR_LEGACY,
        "legacy_base": _huella_base_legacy(datos),
    }


class ErrorPool(Exception):
    """Un problema del registro que hay que contarle a quien llamó."""


class ErrorRevisionPool(ErrorPool):
    """Conflicto causal que el transporte no debe convertir en sobrescritura."""

    def __init__(self, mensaje, codigo):
        super().__init__(mensaje)
        self.codigo = codigo


class ErrorCommitPool(ErrorRevisionPool):
    """El rename fue visible, pero su durabilidad local no pudo confirmarse."""

    def __init__(self, mensaje=None):
        super().__init__(
            mensaje or (
                "El snapshot puede haber quedado visible, pero no se pudo "
                "confirmar su persistencia en el directorio"),
            "POOL_LOCAL_COMMIT_UNCERTAIN",
        )


def _json_canonico(datos):
    """Serializa JSON estricto y limita el coste antes de copiar/persistir."""
    try:
        contenido = json.dumps(
            datos,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError, OverflowError) as error:
        raise ErrorPool(f"El registro no contiene JSON canónico válido: {error}") from error
    if len(contenido) > _MAX_SNAPSHOT_BYTES:
        raise ErrorPool(
            "El registro supera el máximo seguro de 512 KiB; reduce notas, "
            "direcciones o reclamaciones antes de reintentarlo")
    return contenido


def _objeto_json_sin_duplicados(pares):
    """Rechaza claves JSON repetidas también dentro de objetos anidados."""
    objeto = {}
    for clave, valor in pares:
        if clave in objeto:
            raise ValueError(f"clave JSON duplicada: {clave}")
        objeto[clave] = valor
    return objeto


def _comprobar_directorio(ruta):
    """Crea y asegura el directorio sin seguir un enlace en su destino."""
    try:
        estado = os.lstat(ruta)
    except FileNotFoundError:
        os.makedirs(ruta, mode=0o700, exist_ok=True)
        estado = os.lstat(ruta)
    if stat.S_ISLNK(estado.st_mode) or not stat.S_ISDIR(estado.st_mode):
        raise ErrorPool(f"El directorio del registro no es un directorio real: {ruta}")
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
        if error.errno == getattr(errno, "ELOOP", None):
            raise ErrorPool(
                f"El directorio del registro no puede ser un enlace simbólico: {ruta}"
            ) from error
        raise
    try:
        abierto = os.fstat(fd)
        posterior = os.lstat(ruta)
        if (not stat.S_ISDIR(abierto.st_mode)
                or (abierto.st_dev, abierto.st_ino)
                != (posterior.st_dev, posterior.st_ino)):
            raise ErrorPool(
                f"El directorio del registro cambió mientras se abría: {ruta}")
        if os.name == "posix":
            euid, egid = os.geteuid(), os.getegid()
            if abierto.st_uid != euid:
                if euid != 0:
                    raise ErrorPool(
                        f"El directorio del registro pertenece a otro usuario: {ruta}")
                os.fchown(fd, euid, egid)
            elif euid == 0 and abierto.st_gid != egid:
                os.fchown(fd, euid, egid)
            if stat.S_IMODE(abierto.st_mode) != 0o700:
                os.fchmod(fd, 0o700)
            final = os.fstat(fd)
            if final.st_uid != euid or stat.S_IMODE(final.st_mode) != 0o700:
                raise ErrorPool(
                    f"No se pudieron asegurar propietario y modo 0700 de {ruta}")
    finally:
        os.close(fd)


def _estado_previo_regular(ruta, permitir_ausente=False):
    try:
        estado = os.lstat(ruta)
    except FileNotFoundError:
        if permitir_ausente:
            return None
        raise
    if stat.S_ISLNK(estado.st_mode):
        raise ErrorPool(f"El registro no puede ser un enlace simbólico: {ruta}")
    if not stat.S_ISREG(estado.st_mode):
        raise ErrorPool(f"El registro debe ser un fichero regular: {ruta}")
    return estado


def _normalizar_descriptor(fd, ruta):
    """Exige fichero regular, un solo enlace, dueño del proceso y modo 0600."""
    estado = os.fstat(fd)
    if not stat.S_ISREG(estado.st_mode):
        raise ErrorPool(f"El registro debe ser un fichero regular: {ruta}")
    if os.name == "posix":
        if estado.st_nlink != 1:
            raise ErrorPool(
                f"El registro no puede compartir inode mediante enlaces duros: {ruta}")
        euid = os.geteuid()
        egid = os.getegid()
        if estado.st_uid != euid:
            if euid != 0:
                raise ErrorPool(
                    f"El registro pertenece a otro usuario y no es seguro: {ruta}")
            os.fchown(fd, euid, egid)
        elif euid == 0 and estado.st_gid != egid:
            os.fchown(fd, euid, egid)
        if stat.S_IMODE(estado.st_mode) != 0o600:
            os.fchmod(fd, 0o600)
        final = os.fstat(fd)
        if final.st_uid != euid or stat.S_IMODE(final.st_mode) != 0o600:
            raise ErrorPool(
                f"No se pudieron asegurar propietario y modo 0600 de {ruta}")
    return os.fstat(fd)


def _abrir_regular_seguro(ruta, flags, crear=False):
    """Abre sin seguir symlinks y comprueba que lstat/open ven el mismo inode."""
    previo = _estado_previo_regular(ruta, permitir_ausente=crear)
    banderas = flags
    if crear:
        banderas |= os.O_CREAT
    if hasattr(os, "O_CLOEXEC"):
        banderas |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        banderas |= os.O_NOFOLLOW
    try:
        fd = os.open(ruta, banderas, 0o600)
    except OSError as error:
        if error.errno == getattr(errno, "ELOOP", None):
            raise ErrorPool(f"El registro no puede ser un enlace simbólico: {ruta}") from error
        raise
    try:
        abierto = _normalizar_descriptor(fd, ruta)
        posterior = _estado_previo_regular(ruta)
        if (abierto.st_dev, abierto.st_ino) != (posterior.st_dev, posterior.st_ino):
            raise ErrorPool(f"El registro cambió mientras se abría: {ruta}")
        if previo is not None and (
                (previo.st_dev, previo.st_ino) != (abierto.st_dev, abierto.st_ino)):
            raise ErrorPool(f"El registro cambió mientras se abría: {ruta}")
        return fd
    except Exception:
        os.close(fd)
        raise


def _normalizar_snapshot(datos, permitir_legacy_mutado=False):
    """Copia, completa y valida un snapshot sin modificar el objeto recibido."""
    if not isinstance(datos, dict):
        raise ErrorPool("La raiz del registro debe ser un objeto JSON")
    _json_canonico(datos)
    copia = deepcopy(datos)
    revision = copia.get("revision")
    era_legacy = (
        "revision" not in copia
        or (isinstance(revision, dict)
            and set(revision) == {"schema", "clock", "author"}
            and type(revision.get("schema")) is int
            and revision.get("schema") == _REVISION_SCHEMA
            and revision.get("clock") == {}
            and revision.get("author") == _AUTOR_LEGACY)
    )
    base = _vacio()
    base.update(copia)
    # Campo retirado de versiones anteriores. La primera escritura posterior a
    # la migración deja el registro en el formato actual.
    base.pop("vrids_quemados", None)
    if era_legacy:
        base["revision"] = _revision_legacy(base)
    problemas = validar(
        base, permitir_base_legacy_distinta=permitir_legacy_mutado)
    if problemas:
        raise ErrorPool("El registro no es valido: " + "; ".join(problemas[:8]))
    _json_canonico(base)
    return base, era_legacy


def _huella_normalizada(datos):
    # `actualizado` es informativo y puede diferir entre dos nodos que hayan
    # materializado el mismo vacío legacy. La revisión causal sí forma parte de
    # la identidad y nunca se excluye.
    contenido = deepcopy(datos)
    contenido.pop("actualizado", None)
    return hashlib.sha256(_json_canonico(contenido)).hexdigest()


def _reloj(datos):
    return dict((datos.get("revision") or {}).get("clock") or {})


def _domina(reloj_a, reloj_b):
    autores = set(reloj_a) | set(reloj_b)
    no_menor = all(reloj_a.get(a, 0) >= reloj_b.get(a, 0) for a in autores)
    estricta = any(reloj_a.get(a, 0) > reloj_b.get(a, 0) for a in autores)
    return no_menor and estricta


def _clasificar_normalizados(actual, entrante):
    """Clasifica `entrante` respecto de `actual` usando causalidad, no tiempo."""
    if (actual["revision"]["legacy_base"]
            != entrante["revision"]["legacy_base"]):
        return "conflicto_concurrente"
    reloj_actual, reloj_entrante = _reloj(actual), _reloj(entrante)
    if reloj_actual == reloj_entrante:
        if _huella_normalizada(actual) == _huella_normalizada(entrante):
            return "identica"
        return "conflicto_misma_revision"
    if _domina(reloj_entrante, reloj_actual):
        return "nueva"
    if _domina(reloj_actual, reloj_entrante):
        return "obsoleta"
    return "conflicto_concurrente"


def _inicial_causal_desde_legacy(legacy, autor):
    """Construye la primera revisión sin publicar antes el estado legacy."""
    if (not isinstance(autor, str) or not _AUTOR_REVISION.fullmatch(autor)
            or autor == _AUTOR_LEGACY):
        raise ErrorRevisionPool(
            "El autor del bootstrap causal no es válido",
            "POOL_BOOTSTRAP_AUTHOR_INVALID")
    candidato, _ = _normalizar_snapshot(legacy)
    if _reloj(candidato) or candidato["revision"]["author"] != _AUTOR_LEGACY:
        raise ErrorRevisionPool(
            "El candidato de bootstrap debe ser un snapshot legacy",
            "POOL_BOOTSTRAP_CANDIDATE_INVALID")
    candidato["revision"] = {
        "schema": _REVISION_SCHEMA,
        "clock": {autor: 1},
        "author": autor,
        "legacy_base": candidato["revision"]["legacy_base"],
    }
    return candidato


class Pool:
    """Registro local con revisión causal y réplica de snapshot completo.

    El reloj vectorial detecta escrituras concurrentes; no las fusiona ni elige
    una por hora, nombre de nodo o hash. Ese conflicto requiere reconciliación
    explícita en la capa de clúster y, si se exige disponibilidad de escritura,
    su correspondiente política de quorum.
    """

    def __init__(self, ruta, autor=None, validador=None):
        self.ruta = ruta
        self.ruta_candado = ruta + ".lock"
        candidato = str(
            autor if autor is not None else os.environ.get("FIP_NODO", "")
        ).strip() or "local"
        if (not _AUTOR_REVISION.fullmatch(candidato)
                or candidato == _AUTOR_LEGACY):
            raise ErrorPool(
                "El autor de revisión debe tener 1-64 caracteres y usar letras, "
                "números, punto, guion o guion bajo")
        self.autor = candidato
        self.validador = validador
        self._candado = threading.RLock()

    # ── lectura ─────────────────────────────────────────────────────────
    @contextmanager
    def _bloqueo_disco(self):
        """Bloqueo estable que coordina también otras instancias/procesos."""
        directorio = os.path.dirname(self.ruta) or "."
        _comprobar_directorio(directorio)
        fd = _abrir_regular_seguro(self.ruta_candado, os.O_RDWR, crear=True)
        bloqueado = False
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_EX)
                bloqueado = True
            yield
        finally:
            try:
                if fcntl is not None and bloqueado:
                    fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _leer_disco(self):
        try:
            fd = _abrir_regular_seguro(self.ruta, os.O_RDONLY)
        except FileNotFoundError:
            return _vacio(), False, False
        try:
            with os.fdopen(fd, "rb") as fichero:
                fd = -1
                if os.fstat(fichero.fileno()).st_size > _MAX_SNAPSHOT_BYTES:
                    raise ErrorPool(
                        "El registro supera el máximo seguro de 512 KiB")
                crudo = fichero.read(_MAX_SNAPSHOT_BYTES + 1)
            if len(crudo) > _MAX_SNAPSHOT_BYTES:
                raise ErrorPool("El registro supera el máximo seguro de 512 KiB")
            texto = crudo.decode("utf-8")
            datos = json.loads(
                texto,
                object_pairs_hook=_objeto_json_sin_duplicados,
                parse_constant=lambda valor: (_ for _ in ()).throw(
                    ValueError(f"constante JSON no válida: {valor}")),
            )
        except ErrorPool:
            raise
        except (OSError, UnicodeError, ValueError, RecursionError) as e:
            raise ErrorPool(f"No se pudo leer el registro ({self.ruta}): {e}")
        finally:
            if fd >= 0:
                os.close(fd)
        if not isinstance(datos, dict):
            raise ErrorPool(
                f"No se pudo leer el registro ({self.ruta}): "
                "la raiz debe ser un objeto JSON")
        base, era_legacy = _normalizar_snapshot(datos)
        return base, True, era_legacy

    def leer(self):
        """Devuelve una copia normalizada; un legacy migra al escribirlo."""
        with self._candado:
            with self._bloqueo_disco():
                datos, _, _ = self._leer_disco()
                return deepcopy(datos)

    def existe(self):
        """Distingue un disco nuevo del pool vacío ya materializado.

        Usa las mismas aperturas seguras y el mismo bloqueo que ``leer``; no
        crea ni migra ``pool.json`` como efecto lateral.
        """
        with self._candado:
            with self._bloqueo_disco():
                _, existe, _ = self._leer_disco()
                return existe

    def leer_con_estado(self):
        """Devuelve snapshot y existencia desde una sola sección con flock."""
        with self._candado:
            with self._bloqueo_disco():
                datos, existe, _ = self._leer_disco()
                return deepcopy(datos), existe

    @staticmethod
    def huella(datos):
        """Identidad determinista del snapshot completo normalizado."""
        normalizado, _ = _normalizar_snapshot(datos)
        return _huella_normalizada(normalizado)

    @staticmethod
    def clasificar_replica(actual, entrante):
        """Devuelve idéntica, nueva, obsoleta o uno de los dos conflictos."""
        actual_n, _ = _normalizar_snapshot(actual)
        entrante_n, _ = _normalizar_snapshot(entrante)
        return _clasificar_normalizados(actual_n, entrante_n)

    @staticmethod
    def seleccionar_dominante(candidatos):
        """Elige el único snapshot que domina causalmente a todos los demás.

        No cuenta votos ni constituye quorum. La capa HTTP debe decidir cuántos
        nodos necesita consultar y confirmar antes de habilitar una mutación.
        """
        normalizados = [_normalizar_snapshot(c)[0] for c in candidatos]
        if not normalizados:
            raise ErrorRevisionPool(
                "No hay snapshots del pool para reconciliar",
                "POOL_RECONCILIATION_EMPTY")

        dominantes = {}
        for candidato in normalizados:
            domina_todos = True
            for otro in normalizados:
                relacion = _clasificar_normalizados(otro, candidato)
                if relacion not in ("identica", "nueva"):
                    domina_todos = False
                    break
            if domina_todos:
                huella = _huella_normalizada(candidato)
                anterior = dominantes.get(huella)
                if (anterior is None
                        or str(candidato.get("actualizado") or "")
                        > str(anterior.get("actualizado") or "")):
                    dominantes[huella] = candidato
        if len(dominantes) != 1:
            raise ErrorRevisionPool(
                "Los snapshots del pool son concurrentes o discrepan con la "
                "misma revisión; hace falta reconciliación manual",
                "POOL_REPLICA_CONFLICT")
        return deepcopy(next(iter(dominantes.values())))

    # ── escritura, siempre atómica ──────────────────────────────────────
    def _escribir_atomico(self, datos):
        """Sincroniza fichero y renombrado para no publicar JSON parcial."""
        problemas = validar(datos)
        if problemas:
            raise ErrorPool("; ".join(problemas))
        if self.validador is not None:
            self.validador(deepcopy(datos))
        _json_canonico(datos)
        reemplazado = False
        try:
            serializado = (json.dumps(
                datos,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            ) + "\n").encode("utf-8")
        except (TypeError, ValueError, RecursionError, OverflowError) as error:
            raise ErrorPool(f"El registro no contiene JSON válido: {error}") from error
        if len(serializado) > _MAX_SNAPSHOT_BYTES:
            raise ErrorPool(
                "El registro persistido supera el máximo seguro de 512 KiB")
        directorio = os.path.dirname(self.ruta) or "."
        _comprobar_directorio(directorio)
        fd, tmp = tempfile.mkstemp(dir=directorio, suffix=".tmp")
        try:
            _normalizar_descriptor(fd, tmp)
            with os.fdopen(fd, "wb") as f:
                fd = -1
                f.write(serializado)
                f.flush()
                os.fsync(f.fileno())
            _estado_previo_regular(self.ruta, permitir_ausente=True)
            os.replace(tmp, self.ruta)
            reemplazado = True
            # fsync del fichero no basta ante un corte inmediatamente después
            # del rename: cuando el sistema lo permite, persiste la entrada del
            # directorio que apunta al snapshot nuevo.
            if hasattr(os, "O_DIRECTORY"):
                banderas = os.O_RDONLY | os.O_DIRECTORY
                if hasattr(os, "O_CLOEXEC"):
                    banderas |= os.O_CLOEXEC
                if hasattr(os, "O_NOFOLLOW"):
                    banderas |= os.O_NOFOLLOW
                try:
                    fd_dir = os.open(directorio, banderas)
                    try:
                        os.fsync(fd_dir)
                    finally:
                        os.close(fd_dir)
                except OSError as error:
                    if error.errno not in _ERRORES_FSYNC_DIR_NO_SOPORTADO:
                        raise
        except Exception as error:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            if reemplazado:
                raise ErrorCommitPool() from error
            raise
        finally:
            if fd >= 0:
                os.close(fd)

    @staticmethod
    def _actualizar_objeto(original, persistido):
        # Mantiene el contrato histórico de `escribir`: quien pasa el diccionario
        # ve la revisión y la hora efectivamente persistidas, pero sólo tras éxito.
        original.clear()
        original.update(deepcopy(persistido))
        return original

    def escribir(self, datos, marcar_hora=True):
        """Persiste una mutación local y avanza el reloj de este nodo.

        `datos` debe proceder de la revisión local vigente. Para instalar un
        snapshot de otro nodo se usa exclusivamente `aplicar_replica`.
        """
        candidato, _ = _normalizar_snapshot(
            datos, permitir_legacy_mutado=True)
        with self._candado:
            with self._bloqueo_disco():
                actual, existe, _ = self._leer_disco()
                if candidato["revision"] != actual["revision"]:
                    relacion = _clasificar_normalizados(actual, candidato)
                    codigo = (
                        "POOL_LOCAL_STALE" if relacion == "obsoleta"
                        else "POOL_LOCAL_BASE_MISMATCH")
                    raise ErrorRevisionPool(
                        "La mutación no parte de la revisión local vigente; vuelve "
                        "a leer el pool antes de modificarlo",
                        codigo)

                reloj = _reloj(actual if existe else candidato)
                if self.autor not in reloj and len(reloj) >= _MAX_AUTORES_REVISION:
                    raise ErrorRevisionPool(
                        "La revisión contiene demasiados autores",
                        "POOL_REVISION_INVALID")
                contador = reloj.get(self.autor, 0)
                if contador >= _MAX_CONTADOR_REVISION:
                    raise ErrorRevisionPool(
                        "El contador de revisión ha alcanzado su límite",
                        "POOL_REVISION_EXHAUSTED")
                reloj[self.autor] = contador + 1
                candidato["revision"] = {
                    "schema": _REVISION_SCHEMA,
                    "clock": dict(sorted(reloj.items())),
                    "author": self.autor,
                    "legacy_base": (
                        actual if existe else candidato
                    )["revision"]["legacy_base"],
                }
                if marcar_hora:
                    candidato["actualizado"] = ahora()
                problemas = validar(candidato)
                if problemas:
                    raise ErrorPool("; ".join(problemas))
                self._escribir_atomico(candidato)
                return self._actualizar_objeto(datos, candidato)

    @staticmethod
    def es_bootstrap_inicial(datos, autor):
        """Reconoce exclusivamente el vacío causal inicial de un fresh install."""
        try:
            esperado = _inicial_causal_desde_legacy(_vacio(), autor)
            candidato, _ = _normalizar_snapshot(datos)
        except ErrorPool:
            return False
        return _huella_normalizada(candidato) == _huella_normalizada(esperado)

    @staticmethod
    def es_bootstrap_legacy(datos):
        """Reconoce el vacío legacy que pudo dejar una versión anterior."""
        try:
            esperado, _ = _normalizar_snapshot(_vacio())
            candidato, _ = _normalizar_snapshot(datos)
        except ErrorPool:
            return False
        return _huella_normalizada(candidato) == _huella_normalizada(esperado)

    def inicializar_desde_candidato(self, legacy):
        """Materializa legacy→causal con una sola escritura reanudable.

        Un fallo después de ``replace`` puede devolver commit incierto, pero el
        reintento reconoce exactamente el snapshot causal ya visible y no crea
        una segunda revisión. Nunca deja como paso intermedio un fichero legacy.
        """
        candidato, _ = _normalizar_snapshot(legacy)
        esperado = _inicial_causal_desde_legacy(candidato, self.autor)
        with self._candado:
            with self._bloqueo_disco():
                actual, existe, _ = self._leer_disco()
                if existe and _reloj(actual):
                    if (_huella_normalizada(actual)
                            == _huella_normalizada(esperado)):
                        return deepcopy(actual)
                    raise ErrorRevisionPool(
                        "El pool ya contiene otra revisión causal; no se puede "
                        "reanudar el bootstrap",
                        "POOL_BOOTSTRAP_CONFLICT")
                if existe:
                    relacion = _clasificar_normalizados(actual, candidato)
                    if relacion != "identica":
                        raise ErrorRevisionPool(
                            "El candidato legacy no coincide con el pool local",
                            "POOL_BOOTSTRAP_CONFLICT")
                    # Conserva la marca informativa ya materializada; no forma
                    # parte de la identidad causal ni justifica otra escritura.
                    esperado["actualizado"] = actual.get("actualizado")
                self._escribir_atomico(esperado)
                return deepcopy(esperado)

    def aplicar_replica(self, entrante):
        """Instala un snapshot causalmente posterior sin crear otra revisión.

        Devuelve ``True`` si cambió el fichero y ``False`` si ya era idéntico.
        Rechaza tanto datos obsoletos como ramas concurrentes; nunca desempata
        silenciosamente una pérdida de actualizaciones.
        """
        candidato, _ = _normalizar_snapshot(entrante)
        with self._candado:
            with self._bloqueo_disco():
                actual, existe, actual_legacy = self._leer_disco()
                if not existe:
                    self._escribir_atomico(candidato)
                    return True

                relacion = _clasificar_normalizados(actual, candidato)
                if relacion == "identica":
                    # La normalización es también la migración determinista del
                    # formato legacy. No altera la revisión causal.
                    if actual_legacy:
                        self._escribir_atomico(actual)
                    return False
                if relacion == "nueva":
                    self._escribir_atomico(candidato)
                    return True
                if relacion == "obsoleta":
                    raise ErrorRevisionPool(
                        "La réplica del pool es anterior al estado local",
                        "POOL_REPLICA_STALE")
                if relacion == "conflicto_misma_revision":
                    raise ErrorRevisionPool(
                        "La réplica tiene la misma revisión pero otro contenido",
                        "POOL_REPLICA_EQUAL_REVISION_CONFLICT")
                raise ErrorRevisionPool(
                    "La réplica y el estado local contienen mutaciones concurrentes",
                    "POOL_REPLICA_CONCURRENT")

    # ── operaciones ─────────────────────────────────────────────────────
    def buscar(self, datos, ip):
        for d in datos["direcciones"]:
            if isinstance(d, dict) and d.get("ip") == ip:
                return d
        return None

    def alta(self, entrada):
        if not isinstance(entrada, dict):
            raise ErrorPool("El cuerpo del alta debe ser un objeto JSON")
        datos = self.leer()
        ip_cruda = entrada.get("ip") or ""
        if not isinstance(ip_cruda, str):
            raise ErrorPool("La direccion IP debe ser texto")
        ip = ip_cruda.strip()
        if self.buscar(datos, ip):
            raise ErrorPool(f"La dirección {ip} ya está en el registro")

        # El identificador se comprueba AQUI, ademas de en `validar`. Este es el
        # camino por el que llega una persona con un formulario delante, y la
        # sugerencia que tenia en pantalla pudo quedarse vieja mientras lo
        # rellenaba. `validar` lo pararia igual, pero diciendo lo que le pasa al
        # registro entero en vez de lo que le pasa a ESTE campo.
        vrid = entrada.get("vrid")
        if not isinstance(vrid, int) or isinstance(vrid, bool) or not 1 <= vrid <= 255:
            raise ErrorPool(f"El identificador {vrid!r} debe ser un entero entre 1 y 255")
        ocupados = {d.get("vrid"): d.get("ip") for d in datos["direcciones"]
                    if isinstance(d, dict)}
        if vrid in ocupados:
            raise ErrorPool(
                f"El identificador {vrid} ya lo usa {ocupados[vrid]}. Los identificadores "
                f"en uso ahora mismo son: {', '.join(str(v) for v in sorted(x for x in ocupados if x))}. "
                f"El primero libre es el {sugerir_vrid(datos)}.")
        nueva = {
            "ip": ip,
            "vrid": entrada.get("vrid"),
            "estado": entrada.get("estado") or "libre",
            "servicio": entrada.get("servicio") or None,
            "descripcion": entrada.get("descripcion") or "",
            "puertos": entrada.get("puertos") or [],
            "chequeo": entrada.get("chequeo") or None,
            # Nace SIN servidor elegido. Dar de alta una direccion es apartarla;
            # decidir donde descansa es otra cosa, y se hace en la pantalla.
            "preferente": None,
            "notas": entrada.get("notas") or "",
            "creada": ahora(),
        }
        datos["direcciones"].append(nueva)
        datos["direcciones"].sort(key=_orden)
        return self.escribir(datos)

    def modificar(self, ip, cambios):
        if not isinstance(cambios, dict):
            raise ErrorPool("El cuerpo de la modificacion debe ser un objeto JSON")
        datos = self.leer()
        d = self.buscar(datos, ip)
        if not d:
            raise ErrorPool(f"La dirección {ip} no está en el registro")
        if _reclamaciones_activas(datos, ip):
            raise ErrorPool(
                "La dirección tiene una reclamación activa; libérala mediante "
                "su Idempotency-Key antes de editarla manualmente")
        # EL SERVIDOR DONDE DESCANSA NO SE TOCA POR AQUI, y no es un capricho.
        #
        # Esta llamada la usa quien COGE una direccion libre, para decir a que
        # servicio sirve, en que puertos y como se comprueba que esta sano. Todo
        # eso es asunto suyo. Donde descansa la direccion NO lo es: eso lo decide
        # la persona que opera el clúster, en la pantalla, y para eso esta
        # `elegir_servidor`.
        #
        # Se rechaza en vez de ignorarlo en silencio: quien lo mande creeria
        # haber colocado la direccion, y no habria colocado nada.
        if "preferente" in cambios:
            raise ErrorPool(
                "El servidor donde descansa una dirección no se elige por aquí: lo decide "
                "una persona desde la pantalla del panel. Esta llamada sirve para decir qué "
                "servicio usa la dirección, en qué puertos y cómo comprobar que está sano.")
        for campo in ("vrid", "estado", "servicio", "descripcion", "puertos", "chequeo", "notas"):
            if campo in cambios:
                d[campo] = cambios[campo]
        # Liberar una dirección la desata de su servicio: dejar el dueño puesto
        # haría que el panel siguiera enseñando un propietario que ya no la usa.
        if d.get("estado") == "libre":
            d["servicio"] = None
            d["chequeo"] = None
            d["puertos"] = []
            d["preferente"] = None
        datos["direcciones"].sort(key=_orden)
        return self.escribir(datos)

    def reclamar(self, entrada, clave):
        """Coge una IP libre una sola vez para una operación identificada.

        El servidor HTTP llama a este método dentro de su candado. Elegir y
        escribir ocurren, por tanto, como una única operación frente a todas las
        peticiones que llegan a ese panel. Repetir la misma petición devuelve la
        misma IP; reutilizar la clave con otros datos se rechaza.
        """
        clave = validar_clave_reclamacion(clave)
        especificacion = normalizar_reclamacion(entrada)
        huella = _huella_reclamacion(especificacion)
        datos = self.leer()
        reclamaciones = datos.setdefault("reclamaciones", {})
        anterior = reclamaciones.get(clave)

        if anterior:
            if anterior.get("huella") != huella:
                raise ErrorPool(
                    "La clave de idempotencia ya se usó con una petición distinta. "
                    "No se ha tocado ninguna dirección.")
            if anterior.get("estado") == "liberada":
                raise ErrorPool(
                    "Esta reclamación ya fue liberada. Para una operación nueva usa "
                    "otra clave de idempotencia.")
            direccion = self.buscar(datos, anterior.get("ip"))
            if (not direccion
                    or direccion.get("estado") != "en_uso"
                    or direccion.get("servicio") != especificacion["servicio"]):
                raise ErrorPool(
                    "La reclamación existe, pero la dirección ya no conserva su "
                    "estado original. Hace falta revisión manual; no se ha reasignado.")
            return datos, dict(direccion), True

        _recortar_tombstones_reclamacion(reclamaciones)
        if len(_reclamaciones_activas(datos)) >= _MAX_RECLAMACIONES_ACTIVAS:
            raise ErrorPool(
                "Se alcanzó el máximo de reclamaciones activas del pool")

        for direccion in datos.get("direcciones", []):
            if (direccion.get("estado") == "en_uso"
                    and direccion.get("servicio") == especificacion["servicio"]):
                raise ErrorPool(
                    f"El servicio «{especificacion['servicio']}» ya usa la "
                    f"{direccion.get('ip')}. No se ha cogido otra dirección.")

        apartada = next(
            (d for d in datos.get("direcciones", [])
             if d.get("estado") == "reservada"
             and d.get("servicio") == especificacion["servicio"]),
            None,
        )
        disponibles = sorted(libres(datos), key=_orden)
        if apartada is not None:
            direccion = apartada
        elif not disponibles:
            raise ErrorPool("No quedan direcciones libres en el pool")
        else:
            direccion = disponibles[0]
        reserva_anterior = {
            "estado": direccion.get("estado"),
            "servicio": direccion.get("servicio"),
            "descripcion": direccion.get("descripcion") or "",
            "notas": direccion.get("notas") or "",
            "preferente": direccion.get("preferente"),
        }
        direccion.update({
            "estado": "en_uso",
            "servicio": especificacion["servicio"],
            "descripcion": especificacion["descripcion"],
            "puertos": especificacion["puertos"],
            "chequeo": especificacion["chequeo"],
            # Una aplicación puede decidir para qué sirve la IP, pero nunca en
            # qué nodo descansa. Esa colocación sigue siendo humana.
            "preferente": None,
        })
        reclamaciones[clave] = {
            "schema": 1,
            "ip": direccion["ip"],
            "servicio": especificacion["servicio"],
            "huella": huella,
            "estado": "activa",
            "creada": ahora(),
            "reserva_anterior": reserva_anterior,
        }
        self.escribir(datos)
        return datos, dict(direccion), False

    def liberar_reclamacion(self, clave):
        """Deshace de forma idempotente una IP cogida por `reclamar`.

        Nunca libera una IP que ya pertenezca a otro servicio. Es la puerta de
        rollback para una provisión que falle después de reclamarla.
        """
        clave = validar_clave_reclamacion(clave)
        datos = self.leer()
        reclamacion = (datos.get("reclamaciones") or {}).get(clave)
        if not reclamacion:
            raise ErrorPool("No existe una reclamación con esa clave")
        if reclamacion.get("estado") == "liberada":
            return datos, reclamacion.get("ip"), True

        otras = [
            otra_clave for otra_clave, otra in _reclamaciones_activas(
                datos, reclamacion.get("ip"))
            if otra_clave != clave
        ]
        if otras:
            raise ErrorPool(
                "La dirección figura en otra reclamación activa; no se ha "
                "liberado para evitar destruir una asignación posterior")

        direccion = self.buscar(datos, reclamacion.get("ip"))
        if not direccion:
            raise ErrorPool("La dirección de la reclamación ya no existe en el pool")
        if direccion.get("estado") != "libre":
            if direccion.get("servicio") != reclamacion.get("servicio"):
                raise ErrorPool(
                    "La dirección pertenece ahora a otro servicio. No se ha liberado.")
            direccion.update({
                "estado": "libre",
                "servicio": None,
                "chequeo": None,
                "puertos": [],
                "preferente": None,
            })
            previa = reclamacion.get("reserva_anterior") or {}
            if previa.get("estado") == "reservada":
                direccion.update({
                    "estado": "reservada",
                    "servicio": previa.get("servicio") or reclamacion.get("servicio"),
                    "descripcion": previa.get("descripcion") or "",
                    "puertos": [],
                    "chequeo": None,
                    "preferente": previa.get("preferente"),
                    "notas": previa.get("notas") or "",
                })
        # Conservamos una ventana acotada de idempotencia. Al rotar el
        # tombstone más antiguo evitamos agotar el registro de por vida, sin
        # tocar nunca reclamaciones activas.
        _recortar_tombstones_reclamacion(
            datos.setdefault("reclamaciones", {}),
            limite=max(0, _MAX_TOMBSTONES_RECLAMACION - 1),
        )
        reclamacion.pop("reserva_anterior", None)
        reclamacion["estado"] = "liberada"
        reclamacion["liberada"] = ahora()
        self.escribir(datos)
        return datos, reclamacion.get("ip"), False

    def elegir_servidor(self, ip, nodo, nodos_validos):
        """En que servidor descansa una direccion. LA UNICA puerta para esto.

        Existe separada de `modificar` a proposito: quien coge una direccion
        decide para que la usa, no donde vive. Donde vive lo decide quien opera
        el clúster.
        """
        datos = self.leer()
        d = self.buscar(datos, ip)
        if not d:
            raise ErrorPool(f"La dirección {ip} no está en el registro")
        if nodo in (None, "", "-"):
            d["preferente"] = None          # que se quede donde esté; nadie se la quita
        elif not isinstance(nodo, str) or nodo not in nodos_validos:
            raise ErrorPool(
                f"«{nodo}» no es ninguno de los servidores del clúster ({sorted(nodos_validos)}).")
        else:
            d["preferente"] = nodo
        return self.escribir(datos)

    def baja(self, ip):
        datos = self.leer()
        d = self.buscar(datos, ip)
        if not d:
            raise ErrorPool(f"La dirección {ip} no está en el registro")
        if _reclamaciones_activas(datos, ip):
            raise ErrorPool(
                "La dirección conserva una reclamación activa; libérala con "
                "su Idempotency-Key antes de eliminarla")
        if d.get("estado") != "libre":
            raise ErrorPool(
                f"{ip} no está libre. Libérala antes de eliminarla del registro."
            )
        datos["direcciones"] = [x for x in datos["direcciones"] if x.get("ip") != ip]
        return self.escribir(datos)


def _orden(d):
    ip = d.get("ip") or ""
    if not isinstance(ip, str):
        return (999, 999, 999, 999)
    m = _IPV4.match(ip)
    return tuple(int(x) for x in m.groups()) if m else (999, 999, 999, 999)


def _reclamaciones_activas(datos, ip=None):
    """Devuelve pares (clave, claim) activos, opcionalmente ligados a una IP."""
    reclamaciones = datos.get("reclamaciones") or {}
    if not isinstance(reclamaciones, dict):
        return []
    return [
        (clave, reclamacion)
        for clave, reclamacion in reclamaciones.items()
        if (isinstance(reclamacion, dict)
            and reclamacion.get("estado") == "activa"
            and (ip is None or reclamacion.get("ip") == ip))
    ]


def _recortar_tombstones_reclamacion(
        reclamaciones, limite=_MAX_TOMBSTONES_RECLAMACION):
    """Retiene los tombstones más recientes y jamás elimina claims activos."""
    liberadas = [
        (clave, reclamacion)
        for clave, reclamacion in reclamaciones.items()
        if isinstance(reclamacion, dict)
        and reclamacion.get("estado") == "liberada"
    ]
    exceso = len(liberadas) - limite
    if exceso <= 0:
        return 0
    liberadas.sort(key=lambda par: (
        par[1].get("liberada") or par[1].get("creada") or "", par[0]))
    for clave, _reclamacion in liberadas[:exceso]:
        reclamaciones.pop(clave, None)
    return exceso


def ip_valida(ip):
    if not isinstance(ip, str):
        return False
    m = _IPV4.match(ip or "")
    if not m:
        return False
    return all(0 <= int(x) <= 255 for x in m.groups())


def validar_clave_reclamacion(clave):
    clave = (clave or "").strip()
    if not _CLAVE_RECLAMACION.fullmatch(clave):
        raise ErrorPool(
            "Idempotency-Key debe tener entre 8 y 128 caracteres y usar solo "
            "letras, números, punto, guion, guion bajo o dos puntos")
    return clave


def normalizar_reclamacion(entrada):
    """Valida el contrato pequeño que una aplicación puede reclamar."""
    if not isinstance(entrada, dict):
        raise ErrorPool("El cuerpo de la reclamación debe ser un objeto JSON")

    servicio_crudo = entrada.get("servicio") or ""
    if not isinstance(servicio_crudo, str):
        raise ErrorPool("«servicio» debe ser texto")
    servicio = servicio_crudo.strip()
    if not _SERVICIO.fullmatch(servicio):
        raise ErrorPool(
            "«servicio» debe tener 1-64 caracteres: letras, números, guion o "
            "guion bajo, y empezar por letra o número")

    descripcion_cruda = entrada.get("descripcion") or ""
    if not isinstance(descripcion_cruda, str):
        raise ErrorPool("«descripcion» debe ser texto")
    descripcion = descripcion_cruda.strip()
    if len(descripcion) > _MAX_DESCRIPCION:
        raise ErrorPool(
            f"«descripcion» no puede superar {_MAX_DESCRIPCION} caracteres")

    puertos = entrada.get("puertos") or []
    if not isinstance(puertos, list):
        raise ErrorPool("«puertos» debe ser una lista")
    if len(puertos) > _MAX_PUERTOS:
        raise ErrorPool(
            f"«puertos» no puede contener más de {_MAX_PUERTOS} entradas")
    for puerto in puertos:
        if isinstance(puerto, bool) or not isinstance(puerto, int) or not (1 <= puerto <= 65535):
            raise ErrorPool(f"Puerto «{puerto}» fuera de rango")

    chequeo = entrada.get("chequeo")
    if not isinstance(chequeo, dict):
        raise ErrorPool("«chequeo» debe indicar «puerto» y «ruta»")
    puerto_chequeo = chequeo.get("puerto")
    ruta = chequeo.get("ruta")
    if (isinstance(puerto_chequeo, bool)
            or not isinstance(puerto_chequeo, int)
            or not (1 <= puerto_chequeo <= 65535)):
        raise ErrorPool("El puerto del chequeo está fuera de rango")
    if (not isinstance(ruta, str) or not ruta.startswith("/")
            or len(ruta) > _MAX_RUTA_CHEQUEO or any(ord(c) < 32 for c in ruta)):
        raise ErrorPool(
            "La ruta del chequeo debe empezar por «/», no contener controles y "
            f"tener como máximo {_MAX_RUTA_CHEQUEO} caracteres")

    puertos = sorted(set(puertos + [puerto_chequeo]))
    return {
        "servicio": servicio,
        "descripcion": descripcion,
        "puertos": puertos,
        "chequeo": {"puerto": puerto_chequeo, "ruta": ruta},
    }


def _huella_reclamacion(especificacion):
    canonico = json.dumps(
        especificacion, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonico.encode("utf-8")).hexdigest()


def _anadir_campos_desconocidos(problemas, objeto, permitidos, etiqueta):
    desconocidos = set(objeto) - permitidos
    if desconocidos:
        nombres = ", ".join(repr(x) for x in sorted(desconocidos, key=str))
        problemas.append(f"{etiqueta} contiene campos desconocidos: {nombres}")


def _texto_acotado(valor, maximo, permitir_vacio=True):
    return (isinstance(valor, str)
            and (permitir_vacio or bool(valor))
            and len(valor) <= maximo)


def _marca_iso_valida(valor):
    if not _texto_acotado(
            valor, _MAX_MARCA_TIEMPO, permitir_vacio=False):
        return False
    try:
        marca = datetime.fromisoformat(valor.replace("Z", "+00:00"))
    except ValueError:
        return False
    return marca.tzinfo is not None


def validar(datos, permitir_base_legacy_distinta=False):
    """Devuelve la lista de problemas. Vacía significa que se puede escribir.

    Se informan TODOS de una vez: descubrirlos de uno en uno obliga a corregir a
    ciegas, y el reparto es justo donde interesa ver el cuadro completo.
    """
    problemas = []
    if not isinstance(datos, dict):
        return ["la raiz del registro debe ser un objeto JSON"]

    _anadir_campos_desconocidos(
        problemas, datos, _CAMPOS_RAIZ, "el registro")
    version = datos.get("version", 1)
    if type(version) is not int or version != 1:
        problemas.append("«version» debe ser el entero 1")
    actualizado = datos.get("actualizado", "")
    if not _texto_acotado(actualizado, _MAX_MARCA_TIEMPO, permitir_vacio=False):
        problemas.append(
            f"«actualizado» debe ser texto de 1-{_MAX_MARCA_TIEMPO} caracteres")

    revision = datos.get("revision")
    # La ausencia completa identifica un fichero legacy y se admite para poder
    # migrarlo. Si el campo existe, en cambio, debe ser canónico: aceptar una
    # revisión parcialmente válida haría ambiguo el orden causal.
    if "revision" in datos:
        if not isinstance(revision, dict):
            problemas.append("«revision» debe ser un objeto")
        else:
            permitidos = {"schema", "clock", "author", "legacy_base"}
            if set(revision) != permitidos:
                problemas.append(
                    "«revision» debe contener exactamente schema, clock, "
                    "author y legacy_base")
            schema = revision.get("schema")
            if type(schema) is not int or schema != _REVISION_SCHEMA:
                problemas.append("schema de revisión desconocido")
            reloj = revision.get("clock")
            autor = revision.get("author")
            base_legacy = revision.get("legacy_base")
            if (not isinstance(base_legacy, str)
                    or not _HUELLA_SHA256.fullmatch(base_legacy)):
                problemas.append("legacy_base de revisión no es válida")
            if not isinstance(reloj, dict):
                problemas.append("el reloj de revisión debe ser un objeto")
                reloj = {}
            elif len(reloj) > _MAX_AUTORES_REVISION:
                problemas.append("el reloj de revisión contiene demasiados autores")
            else:
                for nombre, contador in reloj.items():
                    if (not isinstance(nombre, str)
                            or not _AUTOR_REVISION.fullmatch(nombre)
                            or nombre == _AUTOR_LEGACY):
                        problemas.append(
                            f"autor de revisión no válido: «{nombre}»")
                    if (not isinstance(contador, int) or isinstance(contador, bool)
                            or not 1 <= contador <= _MAX_CONTADOR_REVISION):
                        problemas.append(
                            f"contador de revisión no válido para «{nombre}»")
            if not isinstance(autor, str) or not _AUTOR_REVISION.fullmatch(autor):
                problemas.append("autor de la última revisión no válido")
            elif reloj:
                if autor == _AUTOR_LEGACY or autor not in reloj:
                    problemas.append(
                        "el autor de la última revisión debe figurar en su reloj")
            elif autor != _AUTOR_LEGACY:
                problemas.append(
                    "un reloj de revisión vacío debe identificarse como legacy")
            elif (not permitir_base_legacy_distinta
                  and isinstance(base_legacy, str)
                  and _HUELLA_SHA256.fullmatch(base_legacy)
                  and base_legacy != _huella_base_legacy(datos)):
                problemas.append(
                    "legacy_base no corresponde al contenido legacy inicial")

    direcciones = datos.get("direcciones", [])
    if not isinstance(direcciones, list):
        return ["«direcciones» debe ser una lista"]
    if len(direcciones) > _MAX_DIRECCIONES:
        problemas.append(
            f"«direcciones» no puede contener más de {_MAX_DIRECCIONES} entradas")

    mantenimiento = datos.get("mantenimiento", [])
    if not isinstance(mantenimiento, list):
        problemas.append("«mantenimiento» debe ser una lista")
        mantenimiento = []
    elif len(mantenimiento) > _MAX_MANTENIMIENTO:
        problemas.append(
            f"«mantenimiento» no puede contener más de {_MAX_MANTENIMIENTO} nodos")
    elif any(not isinstance(n, str) or not _SERVICIO.fullmatch(n) for n in mantenimiento):
        problemas.append("«mantenimiento» contiene nombres de servidor no validos")

    dhcp = datos.get("dhcp_desde", 100)
    if not isinstance(dhcp, int) or isinstance(dhcp, bool) or not 1 <= dhcp <= 255:
        problemas.append(f"dhcp_desde «{dhcp}» fuera del rango 1-255")
        dhcp = 100

    vistas_ip, vistos_vrid, vistos_serv = {}, {}, {}
    vistos_identificador_vrrp = {}
    for d in direcciones:
        if not isinstance(d, dict):
            problemas.append("hay una entrada de direccion que no es un objeto JSON")
            continue
        _anadir_campos_desconocidos(
            problemas, d, _CAMPOS_DIRECCION, "una dirección")
        ip = d.get("ip")
        etq = ip or "(sin dirección)"

        descripcion = d.get("descripcion", "")
        if not _texto_acotado(descripcion, _MAX_DESCRIPCION):
            problemas.append(
                f"{etq}: descripción debe ser texto de hasta {_MAX_DESCRIPCION} caracteres")
        notas = d.get("notas", "")
        if not _texto_acotado(notas, _MAX_NOTAS):
            problemas.append(
                f"{etq}: notas debe ser texto de hasta {_MAX_NOTAS} caracteres")
        creada = d.get("creada")
        if (creada is not None
                and not _texto_acotado(creada, _MAX_MARCA_TIEMPO, permitir_vacio=False)):
            problemas.append(
                f"{etq}: creada debe ser texto de hasta {_MAX_MARCA_TIEMPO} caracteres")

        if not ip_valida(ip):
            problemas.append(f"{etq}: no es una dirección IPv4 válida")
        else:
            ultimo = int(ip.rsplit(".", 1)[1])
            if ultimo >= dhcp:
                problemas.append(
                    f"{ip}: cae dentro del rango del DHCP (empieza en .{dhcp}). "
                    "Tarde o temprano el router la reparte y el conflicto es intermitente."
                )
            if ip in vistas_ip:
                problemas.append(f"{ip}: repetida en el registro")
            vistas_ip[ip] = d

        vrid = d.get("vrid")
        if not isinstance(vrid, int) or isinstance(vrid, bool) or not (1 <= vrid <= 255):
            problemas.append(f"{etq}: vrid «{vrid}» fuera del rango 1-255 de VRRP")
        else:
            if vrid in vistos_vrid:
                problemas.append(
                    f"{etq}: vrid {vrid} ya lo usa {vistos_vrid[vrid]}. Dos grupos VRRP "
                    "no pueden compartirlo: se pelearían por las direcciones del otro."
                )
            vistos_vrid[vrid] = etq

        estado = d.get("estado")
        if estado not in ESTADOS:
            problemas.append(f"{etq}: estado «{estado}» desconocido (usa: {', '.join(ESTADOS)})")

        serv = d.get("servicio")
        if estado in ("reservada", "en_uso"):
            if not isinstance(serv, str) or not serv:
                problemas.append(f"{etq}: está «{estado}» pero no dice qué servicio la usa")
            else:
                if not _SERVICIO.fullmatch(serv):
                    problemas.append(
                        f"{etq}: nombre de servicio «{serv}» no valido; usa letras, numeros, «-» o «_»")
                else:
                    identificador = identificador_vrrp(serv)
                    anterior = vistos_identificador_vrrp.get(identificador)
                    if anterior is not None and anterior != serv:
                        problemas.append(
                            f"{etq}: el servicio «{serv}» colisiona en keepalived "
                            f"con «{anterior}» (ambos generan {identificador})")
                    else:
                        vistos_identificador_vrrp[identificador] = serv
                if serv in vistos_serv:
                    problemas.append(f"{etq}: el servicio «{serv}» ya tiene la {vistos_serv[serv]}")
                else:
                    vistos_serv[serv] = etq
        elif estado == "libre" and serv:
            problemas.append(f"{etq}: una direccion «libre» no puede conservar el servicio «{serv}»")

        ch = d.get("chequeo")
        if ch is not None and not isinstance(ch, dict):
            problemas.append(f"{etq}: el chequeo debe ser un objeto JSON")
            ch = None
        elif isinstance(ch, dict):
            _anadir_campos_desconocidos(
                problemas, ch, _CAMPOS_CHEQUEO, f"{etq}: el chequeo")
        if estado == "en_uso":
            ch = ch or {}
            if not _puerto_valido(ch.get("puerto")) or not isinstance(ch.get("ruta"), str) or not ch.get("ruta"):
                problemas.append(
                    f"{etq}: está en uso pero no declara chequeo de salud. Sin él, keepalived "
                    "no sabría cuándo ceder la dirección."
                )
            elif (len(ch["ruta"]) > _MAX_RUTA_CHEQUEO
                    or not _RUTA_CHEQUEO.fullmatch(ch["ruta"])):
                problemas.append(f"{etq}: la ruta de chequeo contiene caracteres no permitidos")

        puertos = d.get("puertos") or []
        if not isinstance(puertos, list):
            problemas.append(f"{etq}: «puertos» debe ser una lista")
            puertos = []
        elif len(puertos) > _MAX_PUERTOS:
            problemas.append(
                f"{etq}: «puertos» no puede contener más de {_MAX_PUERTOS} entradas")
        for p in puertos:
            if not _puerto_valido(p):
                problemas.append(f"{etq}: puerto «{p}» fuera de rango")

        preferente = d.get("preferente")
        if (preferente is not None
                and (not isinstance(preferente, str)
                     or not _SERVICIO.fullmatch(preferente))):
            problemas.append(
                f"{etq}: el servidor por defecto debe ser un nombre válido o null")
    reclamaciones = datos.get("reclamaciones", {})
    if not isinstance(reclamaciones, dict):
        problemas.append("«reclamaciones» debe ser un objeto")
    else:
        if len(reclamaciones) > _MAX_RECLAMACIONES:
            problemas.append(
                f"«reclamaciones» no puede contener más de {_MAX_RECLAMACIONES} entradas")
        activas = sum(
            1 for reclamacion in reclamaciones.values()
            if isinstance(reclamacion, dict)
            and reclamacion.get("estado") == "activa")
        if activas > _MAX_RECLAMACIONES_ACTIVAS:
            problemas.append(
                "«reclamaciones» no puede contener más de "
                f"{_MAX_RECLAMACIONES_ACTIVAS} entradas activas")
        activas_por_ip = {}
        activas_por_servicio = {}
        for clave, reclamacion in reclamaciones.items():
            if not isinstance(clave, str) or not _CLAVE_RECLAMACION.fullmatch(clave):
                problemas.append(f"Clave de reclamación no válida: «{clave}»")
            if not isinstance(reclamacion, dict):
                problemas.append(f"Reclamación «{clave}»: debe ser un objeto")
                continue
            _anadir_campos_desconocidos(
                problemas, reclamacion, _CAMPOS_RECLAMACION,
                f"Reclamación «{clave}»")
            schema_claim = reclamacion.get("schema")
            legacy_claim = schema_claim is None
            if not legacy_claim and schema_claim != 1:
                problemas.append(
                    f"Reclamación «{clave}»: schema desconocido")
            estado_claim = reclamacion.get("estado")
            if estado_claim not in ("activa", "liberada"):
                problemas.append(
                    f"Reclamación «{clave}»: estado desconocido "
                    f"«{estado_claim}»")
            ip_claim = reclamacion.get("ip")
            servicio_claim = reclamacion.get("servicio")
            identidad_valida = True
            if not ip_claim or not servicio_claim:
                problemas.append(
                    f"Reclamación «{clave}»: faltan dirección o servicio")
                identidad_valida = False
            elif (not ip_valida(ip_claim)
                  or not isinstance(servicio_claim, str)
                  or not _SERVICIO.fullmatch(servicio_claim)):
                problemas.append(
                    f"Reclamación «{clave}»: dirección o servicio no válidos")
                identidad_valida = False
            huella = reclamacion.get("huella")
            if (huella is not None
                    and (not isinstance(huella, str)
                         or not _HUELLA_SHA256.fullmatch(huella))):
                problemas.append(f"Reclamación «{clave}»: huella no válida")
            creada = reclamacion.get("creada")
            liberada = reclamacion.get("liberada")
            valida_marca = _marca_iso_valida if not legacy_claim else (
                lambda valor: _texto_acotado(
                    valor, _MAX_MARCA_TIEMPO, permitir_vacio=False))
            if creada is not None and not valida_marca(creada):
                problemas.append(
                    f"Reclamación «{clave}»: creada no es válida")
            if not legacy_claim and creada is None:
                problemas.append(
                    f"Reclamación «{clave}»: falta creada")
            if estado_claim == "activa" and liberada is not None:
                problemas.append(
                    f"Reclamación «{clave}»: una activa no puede tener liberada")
            if estado_claim == "liberada" and not valida_marca(liberada):
                problemas.append(
                    f"Reclamación «{clave}»: una liberada exige timestamp válido")
            reserva = reclamacion.get("reserva_anterior")
            if reserva is not None:
                if not isinstance(reserva, dict):
                    problemas.append(
                        f"Reclamación «{clave}»: reserva_anterior debe ser un objeto")
                else:
                    _anadir_campos_desconocidos(
                        problemas, reserva, _CAMPOS_RESERVA_ANTERIOR,
                        f"Reclamación «{clave}»: reserva_anterior")
                    estado_anterior = reserva.get("estado")
                    if estado_anterior not in ("libre", "reservada"):
                        problemas.append(
                            f"Reclamación «{clave}»: estado anterior debe ser "
                            "libre o reservada")
                    servicio_anterior = reserva.get("servicio")
                    if (estado_anterior == "libre"
                            and servicio_anterior not in (None, "")):
                        problemas.append(
                            f"Reclamación «{clave}»: una reserva anterior libre "
                            "no puede tener servicio")
                    if (estado_anterior == "reservada"
                            and servicio_anterior != servicio_claim):
                        problemas.append(
                            f"Reclamación «{clave}»: la reserva anterior no "
                            "pertenece al mismo servicio")
                    if not _texto_acotado(
                            reserva.get("descripcion", ""), _MAX_DESCRIPCION):
                        problemas.append(
                            f"Reclamación «{clave}»: descripción anterior demasiado larga")
                    if not _texto_acotado(
                            reserva.get("notas", ""), _MAX_NOTAS):
                        problemas.append(
                            f"Reclamación «{clave}»: notas anteriores demasiado largas")
                    preferente_anterior = reserva.get("preferente")
                    if (preferente_anterior is not None
                            and (not isinstance(preferente_anterior, str)
                                 or not _SERVICIO.fullmatch(preferente_anterior))):
                        problemas.append(
                            f"Reclamación «{clave}»: servidor anterior no válido")
            if estado_claim == "activa":
                if identidad_valida:
                    anterior_ip = activas_por_ip.get(ip_claim)
                    if anterior_ip is not None:
                        problemas.append(
                            f"Reclamación «{clave}»: la IP {ip_claim} ya está "
                            f"activa en «{anterior_ip}»")
                    else:
                        activas_por_ip[ip_claim] = clave
                    anterior_servicio = activas_por_servicio.get(servicio_claim)
                    if anterior_servicio is not None:
                        problemas.append(
                            f"Reclamación «{clave}»: el servicio «{servicio_claim}» "
                            f"ya está activo en «{anterior_servicio}»")
                    else:
                        activas_por_servicio[servicio_claim] = clave
                    direccion_claim = vistas_ip.get(ip_claim)
                    if (not isinstance(direccion_claim, dict)
                            or direccion_claim.get("estado") != "en_uso"
                            or direccion_claim.get("servicio") != servicio_claim):
                        problemas.append(
                            f"Reclamación «{clave}»: una activa exige su dirección "
                            "existente, en_uso y ligada al mismo servicio")
                    else:
                        try:
                            especificacion = normalizar_reclamacion({
                                "servicio": direccion_claim.get("servicio"),
                                "descripcion": direccion_claim.get("descripcion") or "",
                                "puertos": direccion_claim.get("puertos") or [],
                                "chequeo": direccion_claim.get("chequeo"),
                            })
                            esperada = _huella_reclamacion(especificacion)
                            if huella is not None and huella != esperada:
                                problemas.append(
                                    f"Reclamación «{clave}»: la huella no "
                                    "corresponde a su dirección activa")
                        except ErrorPool:
                            # La propia dirección ya aporta sus errores; se
                            # conserva además el vínculo semántico anterior.
                            pass
                if not legacy_claim and huella is None:
                    problemas.append(
                        f"Reclamación «{clave}»: una activa causal exige huella")
                if not legacy_claim and not isinstance(reserva, dict):
                    problemas.append(
                        f"Reclamación «{clave}»: una activa causal exige "
                        "reserva_anterior")
                elif (not legacy_claim and isinstance(reserva, dict)
                      and set(reserva) != _CAMPOS_RESERVA_ANTERIOR):
                    problemas.append(
                        f"Reclamación «{clave}»: reserva_anterior incompleta")
            elif estado_claim == "liberada":
                if not legacy_claim and reserva is not None:
                    problemas.append(
                        f"Reclamación «{clave}»: una liberada no conserva "
                        "reserva_anterior activa")
                if not legacy_claim and huella is None:
                    problemas.append(
                        f"Reclamación «{clave}»: una liberada causal exige huella")

    return problemas


def libres(datos):
    return [d for d in datos.get("direcciones", []) if d.get("estado") == "libre"]


def vrids_ocupados(datos):
    """Identificadores usados por las direcciones que existen en el registro."""
    return sorted({d.get("vrid") for d in datos.get("direcciones", []) if d.get("vrid")})


# La sugerencia empieza en 1 y evita todos los VRID ya declarados. Quien opere
# el clúster debe comprobar también que no colisionen con otros equipos VRRP del
# mismo segmento, que quedan fuera del alcance de este registro.
VRID_DESDE = 1


def sugerir_vrid(datos, desde=None):
    """El primer identificador libre a partir del inicio configurado.

    Nunca uno que ya este declarado. Si no queda hueco por arriba se baja
    a buscar entre los pequeños hasta agotar el rango permitido por VRRP.
    """
    ocupados = set(vrids_ocupados(datos))
    inicio = VRID_DESDE if desde is None else desde
    for v in list(range(inicio, 256)) + list(range(1, inicio)):
        if v not in ocupados:
            return v
    return None


def mantenimiento(datos):
    return list(datos.get("mantenimiento") or [])


def marcar_mantenimiento(datos, nodo, activo):
    """Pone o quita un servidor del modo mantenimiento en el registro."""
    lista = [n for n in (datos.get("mantenimiento") or []) if n != nodo]
    if activo:
        lista.append(nodo)
    datos["mantenimiento"] = sorted(lista)
    return datos
