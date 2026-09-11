import errno
import json
import os
import stat
import sys
import tempfile
import threading
import unittest
from copy import deepcopy
from pathlib import Path
from unittest import mock


PANEL = Path(__file__).resolve().parents[1] / "panel"
sys.path.insert(0, str(PANEL))

import seguridad  # noqa: E402
import auth_http  # noqa: E402


SECRETO = "s" * 64
TOKEN_CLUSTER = "c" * 64
USUARIO_ID_PRUEBA = "00000000-0000-4000-8000-000000000001"


class ProteccionCuentaTest(unittest.TestCase):
    def setUp(self):
        self.proteccion = seguridad.ProteccionCuenta(SECRETO)

    def test_scrypt_no_guarda_la_clave_y_la_verifica(self):
        guardada = self.proteccion.hash_clave("Una-clave-segura-2026")

        self.assertNotIn("Una-clave-segura-2026", guardada)
        self.assertTrue(self.proteccion.comprobar_clave(
            "Una-clave-segura-2026", guardada))
        self.assertFalse(self.proteccion.comprobar_clave(
            "Una-clave-distinta", guardada))

    def test_rechaza_claves_cortas_y_predecibles(self):
        with self.assertRaisesRegex(seguridad.ErrorAcceso, "al menos"):
            self.proteccion.validar_clave("corta")
        with self.assertRaisesRegex(seguridad.ErrorAcceso, "predecible"):
            self.proteccion.validar_clave("password1234")

    def test_scrypt_rechaza_parametros_maliciosos_antes_de_derivar(self):
        maliciosos = [
            "scrypt$1073741824$8$1$" + "A" * 22 + "$" + "A" * 43,
            "scrypt$32768$8$999999999$" + "A" * 22 + "$" + "A" * 43,
            "scrypt$32768$8$1$A$" + "A" * 43,
            "scrypt$32768$8$1$" + "A" * 22 + "$" + "A" * 4000,
        ]
        with mock.patch.object(
                seguridad.hashlib, "scrypt",
                side_effect=AssertionError("no debe derivar")):
            for guardada in maliciosos:
                with self.subTest(guardada=guardada[:40]):
                    self.assertFalse(self.proteccion.comprobar_clave(
                        "Clave-inicial-2026", guardada))

    def test_scrypt_captura_overflow_del_runtime(self):
        canonico = "scrypt$32768$8$1$" + "A" * 22 + "$" + "A" * 43
        with mock.patch.object(
                seguridad.hashlib, "scrypt",
                side_effect=OverflowError("simulado")):
            self.assertFalse(self.proteccion.comprobar_clave(
                "Clave-inicial-2026", canonico))

    def test_totp_y_codigo_de_recuperacion(self):
        secreto = "JBSWY3DPEHPK3PXP"
        instante = 1_700_000_000
        codigo = self.proteccion._totp(secreto, instante // 30)
        self.assertTrue(self.proteccion.comprobar_totp(
            secreto, codigo, instante=instante, ventana=0))

        recuperacion = self.proteccion.generar_codigos(1)[0]
        usuario = {"totp": {
            "enabled": True,
            "secret": self.proteccion.cifrar(secreto),
            "recovery_code_hashes": [
                self.proteccion.hash_recuperacion(recuperacion)],
        }}
        self.assertEqual(
            ("recovery", 0),
            self.proteccion.validar_factor(usuario, recuperacion.lower()),
        )


class SesionesTest(unittest.TestCase):
    def test_firma_y_detecta_manipulacion(self):
        sesiones = seguridad.Sesiones(SECRETO)
        usuario = {
            "id": "id-1", "username": "operador", "display_name": "Operador",
            "role": "operator", "session_version": 3,
        }
        token, identidad = sesiones.crear(usuario)

        self.assertEqual("operador", sesiones.leer(token).usuario)
        self.assertEqual(identidad.csrf, sesiones.leer(token).csrf)
        cuerpo, firma = token.split(".", 1)
        primer_caracter = "A" if firma[0] != "A" else "B"
        self.assertIsNone(sesiones.leer(cuerpo + "." + primer_caracter + firma[1:]))


class AlmacenSeguridadTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ruta = str(Path(self.tmp.name) / "security.json")
        self.almacen = seguridad.AlmacenSeguridad(self.ruta, "node-a")
        self.proteccion = seguridad.ProteccionCuenta(SECRETO)

    def _alta_inicial(self):
        return self.almacen.crear_propietario(
            "admin", "Administrador",
            self.proteccion.hash_clave("Clave-inicial-2026"),
        )

    @staticmethod
    def _snapshot_valido():
        return {
            "schema": 1,
            "revision": {
                "counter": 1, "timestamp": 1, "node": "node-a",
                "actor": "admin",
            },
            "users": [{
                "id": USUARIO_ID_PRUEBA, "username": "admin",
                "display_name": "Administrador", "role": "admin",
                "status": "active", "password_hash": (
                    "scrypt$32768$8$1$" + "A" * 22 + "$" + "A" * 43),
                "password_change_required": False, "session_version": 1,
                "totp": {
                    "enabled": False, "secret": None,
                    "pending_secret": None, "recovery_code_hashes": [],
                },
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
                "updated_by": "admin",
            }],
            "api_keys": [],
        }

    @staticmethod
    def _clave_api(identificador, nombre):
        return {
            "id": identificador, "name": nombre, "prefix": "fip_prefijo...",
            "token_hash": "a" * 64, "scopes": ["status:read"],
            "status": "active", "created_at": "2026-01-01T00:00:00Z",
            "created_by": "admin", "revoked_at": None, "revoked_by": None,
        }

    def test_alta_inicial_y_permisos_no_exponen_secretos(self):
        usuario, _ = self._alta_inicial()
        publico = self.almacen.publico(usuario)

        self.assertEqual("admin", publico["role"])
        self.assertFalse(publico["password_change_required"])
        self.assertNotIn("password_hash", publico)
        self.assertNotIn("totp", publico)
        self.assertEqual(0o600, os.stat(self.ruta).st_mode & 0o777)

    def test_el_registro_inicial_se_cierra_tras_la_primera_cuenta(self):
        self._alta_inicial()
        with self.assertRaisesRegex(seguridad.ErrorAcceso, "cerrado"):
            self._alta_inicial()

    def test_protege_al_ultimo_administrador(self):
        usuario, _ = self._alta_inicial()
        with self.assertRaisesRegex(seguridad.ErrorAcceso, "última"):
            self.almacen.actualizar_acceso(
                usuario["id"], "admin", {"role": "operator"})

    def test_replica_solo_acepta_estado_mas_nuevo(self):
        _, snapshot = self._alta_inicial()
        replica = seguridad.AlmacenSeguridad(
            str(Path(self.tmp.name) / "replica.json"), "node-b")

        self.assertTrue(replica.aplicar_replica(snapshot))
        self.assertFalse(replica.aplicar_replica(snapshot))

    def test_legacy_identico_ignora_contador_timestamp_y_nodo(self):
        primero = self._snapshot_valido()
        segundo = deepcopy(primero)
        segundo["revision"] = {
            "counter": 98, "timestamp": 999999, "node": "node-b",
            "actor": "otro-admin",
        }

        self.assertEqual(
            "identica",
            seguridad.AlmacenSeguridad.clasificar_replica(primero, segundo),
        )
        self.assertEqual(
            seguridad.AlmacenSeguridad.huella(primero),
            seguridad.AlmacenSeguridad.huella(segundo),
        )
        ganador = seguridad.AlmacenSeguridad.seleccionar_dominante(
            [primero, segundo])
        self.assertEqual({}, ganador["revision"]["clock"])

    def test_legacy_divergente_falla_cerrado_sin_desempate_temporal(self):
        antiguo = self._snapshot_valido()
        supuesto_nuevo = deepcopy(antiguo)
        supuesto_nuevo["users"][0]["display_name"] = "Contenido distinto"
        supuesto_nuevo["revision"] = {
            "counter": 999, "timestamp": 999999999, "node": "node-z",
            "actor": "admin",
        }

        self.assertEqual(
            "conflicto_concurrente",
            seguridad.AlmacenSeguridad.clasificar_replica(
                antiguo, supuesto_nuevo),
        )
        with self.assertRaises(seguridad.ErrorAcceso) as error:
            seguridad.AlmacenSeguridad.seleccionar_dominante(
                [antiguo, supuesto_nuevo])
        self.assertEqual("AUTH_REPLICA_CONFLICT", error.exception.codigo)

    def test_reloj_vectorial_detecta_nueva_stale_misma_revision_y_concurrente(self):
        _, base = self._alta_inicial()
        replica_b = seguridad.AlmacenSeguridad(
            str(Path(self.tmp.name) / "node-b.json"), "node-b")
        replica_c = seguridad.AlmacenSeguridad(
            str(Path(self.tmp.name) / "node-c.json"), "node-c")
        replica_b.aplicar_replica(base)
        replica_c.aplicar_replica(base)

        _, rama_b = replica_b.actualizar_perfil(
            base["users"][0]["id"], "Nombre B", "admin")
        _, rama_c = replica_c.actualizar_perfil(
            base["users"][0]["id"], "Nombre C", "admin")
        misma_revision = deepcopy(rama_b)
        misma_revision["users"][0]["display_name"] = "Manipulado"

        self.assertEqual(
            "nueva",
            seguridad.AlmacenSeguridad.clasificar_replica(base, rama_b),
        )
        self.assertEqual(
            "obsoleta",
            seguridad.AlmacenSeguridad.clasificar_replica(rama_b, base),
        )
        self.assertEqual(
            "conflicto_misma_revision",
            seguridad.AlmacenSeguridad.clasificar_replica(
                rama_b, misma_revision),
        )
        self.assertEqual(
            "conflicto_concurrente",
            seguridad.AlmacenSeguridad.clasificar_replica(rama_b, rama_c),
        )
        with self.assertRaises(seguridad.ErrorAcceso) as error:
            replica_b.aplicar_replica(base)
        self.assertEqual("AUTH_REPLICA_STALE", error.exception.codigo)

    def test_migracion_conserva_base_legacy_y_no_domina_otro_contenido(self):
        Path(self.ruta).write_text(
            json.dumps(self._snapshot_valido()), encoding="utf-8")
        migrado = self.almacen.inicializar_revision("bootstrap")
        divergente = self._snapshot_valido()
        divergente["users"][0]["display_name"] = "Otra rama legacy"

        self.assertEqual({"node-a": 1}, migrado["revision"]["clock"])
        self.assertEqual(
            "conflicto_concurrente",
            seguridad.AlmacenSeguridad.clasificar_replica(
                migrado, divergente),
        )

    @unittest.skipUnless(os.name == "posix", "durabilidad de directorio POSIX")
    def test_bootstrap_causal_es_una_sola_escritura_y_reanudable(self):
        candidato = self._snapshot_valido()

        # Un fallo anterior al rename no puede dejar el legacy materializado.
        with mock.patch.object(
                seguridad.os, "replace",
                side_effect=OSError(errno.EIO, "fallo antes de publicar")):
            with self.assertRaises(OSError):
                self.almacen.inicializar_desde_candidato(
                    candidato, "bootstrap")
        self.assertFalse(self.almacen.existe())

        fsync_real = seguridad.os.fsync

        def fsync_con_eio_en_directorio(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(errno.EIO, "fallo tras rename")
            return fsync_real(fd)

        # Tras el rename incierto sólo puede verse ya la revisión causal.
        with mock.patch.object(
                seguridad.os, "fsync", side_effect=fsync_con_eio_en_directorio):
            with self.assertRaises(seguridad.ErrorAcceso) as error:
                self.almacen.inicializar_desde_candidato(
                    candidato, "bootstrap")
        self.assertEqual("AUTH_COMMIT_UNCERTAIN", error.exception.codigo)
        visible = self.almacen.leer()
        self.assertEqual({"node-a": 1}, visible["revision"]["clock"])

        # Reintentar con el mismo candidato reconoce el commit visible; no
        # crea otra revisión ni necesita volver a escribir el legacy.
        reanudado = self.almacen.inicializar_desde_candidato(
            candidato, "bootstrap")
        self.assertEqual(
            seguridad.AlmacenSeguridad.huella(visible),
            seguridad.AlmacenSeguridad.huella(reanudado),
        )
        self.assertEqual({"node-a": 1}, reanudado["revision"]["clock"])

    def test_ausencia_no_vota_como_vacio_y_acepta_restauracion(self):
        _, snapshot = self._alta_inicial()
        reemplazo = seguridad.AlmacenSeguridad(
            str(Path(self.tmp.name) / "reemplazo.json"), "node-b")

        sintetico, inicializado = reemplazo.leer_con_estado()
        self.assertFalse(inicializado)
        self.assertFalse(sintetico["users"])
        self.assertFalse(reemplazo.existe())
        self.assertTrue(reemplazo.aplicar_replica(snapshot))
        restaurado, inicializado = reemplazo.leer_con_estado()
        self.assertTrue(inicializado)
        self.assertTrue(reemplazo.existe())
        self.assertEqual(
            seguridad.AlmacenSeguridad.huella(snapshot),
            seguridad.AlmacenSeguridad.huella(restaurado),
        )

    @unittest.skipUnless(seguridad.fcntl is not None, "flock no disponible")
    def test_lectura_de_snapshot_y_existencia_es_atomica_entre_instancias(self):
        Path(self.ruta).write_text(
            json.dumps(self._snapshot_valido()), encoding="utf-8")
        lector = seguridad.AlmacenSeguridad(self.ruta, "node-a")
        escritor = seguridad.AlmacenSeguridad(self.ruta, "node-b")
        lectura_iniciada = threading.Event()
        liberar_lectura = threading.Event()
        mutacion_entro = threading.Event()
        errores = []
        resultado = []
        leer_real = lector._leer

        def leer_pausado():
            lectura_iniciada.set()
            if not liberar_lectura.wait(timeout=5):
                raise RuntimeError("timeout esperando liberar lectura atómica")
            return leer_real()

        def leer_en_hilo():
            try:
                resultado.append(lector.leer_con_estado())
            except Exception as error:  # noqa: BLE001 - se informa al hilo principal.
                errores.append(error)

        def mutar(datos):
            mutacion_entro.set()
            datos["users"][0]["display_name"] = "Después de la lectura"
            return datos["users"][0]

        def mutar_en_hilo():
            try:
                escritor._mutar("admin", mutar)
            except Exception as error:  # noqa: BLE001 - se informa al hilo principal.
                errores.append(error)

        with mock.patch.object(lector, "_leer", side_effect=leer_pausado):
            hilo_lector = threading.Thread(target=leer_en_hilo)
            hilo_lector.start()
            self.assertTrue(lectura_iniciada.wait(timeout=5))
            hilo_escritor = threading.Thread(target=mutar_en_hilo)
            hilo_escritor.start()
            self.assertFalse(mutacion_entro.wait(timeout=0.2))
            liberar_lectura.set()
            hilo_lector.join(timeout=10)
            hilo_escritor.join(timeout=10)

        self.assertFalse(hilo_lector.is_alive())
        self.assertFalse(hilo_escritor.is_alive())
        self.assertEqual([], errores)
        self.assertEqual(1, len(resultado))
        snapshot, inicializado = resultado[0]
        self.assertTrue(inicializado)
        self.assertEqual("Administrador", snapshot["users"][0]["display_name"])
        self.assertEqual(
            "Después de la lectura",
            escritor.leer()["users"][0]["display_name"],
        )

    def test_schema_booleano_no_es_entero_y_revision_vectorial_es_estricta(self):
        invalido = self._snapshot_valido()
        invalido["schema"] = True
        with self.assertRaises(seguridad.ErrorAcceso) as error:
            seguridad.AlmacenSeguridad.validar_snapshot(invalido)
        self.assertEqual("AUTH_STATE_INVALID", error.exception.codigo)

        _, vectorial = self._alta_inicial()
        vectorial["revision"]["desconocido"] = "no"
        with self.assertRaises(seguridad.ErrorAcceso) as error:
            seguridad.AlmacenSeguridad.validar_snapshot(vectorial)
        self.assertEqual("AUTH_STATE_INVALID", error.exception.codigo)

    def test_snapshot_rechaza_parametros_scrypt_no_canonicos(self):
        malicioso = self._snapshot_valido()
        malicioso["users"][0]["password_hash"] = (
            "scrypt$1073741824$8$1$" + "A" * 22 + "$" + "A" * 43)

        with self.assertRaises(seguridad.ErrorAcceso) as error:
            seguridad.AlmacenSeguridad.validar_snapshot(malicioso)

        self.assertEqual("AUTH_STATE_INVALID", error.exception.codigo)

    def test_snapshot_rechaza_invariantes_semanticas_imposibles(self):
        casos = {}

        sin_admin = self._snapshot_valido()
        sin_admin["users"][0]["role"] = "operator"
        casos["sin administrador activo"] = sin_admin

        id_usuario_no_canonico = self._snapshot_valido()
        id_usuario_no_canonico["users"][0]["id"] = "user-1"
        casos["id de usuario no UUID"] = id_usuario_no_canonico

        totp_sin_secreto = self._snapshot_valido()
        totp_sin_secreto["users"][0]["totp"]["enabled"] = True
        casos["totp activo sin secret"] = totp_sin_secreto

        totp_inactivo_con_secreto = self._snapshot_valido()
        totp_inactivo_con_secreto["users"][0]["totp"]["secret"] = "fernet:token"
        casos["totp inactivo con secret"] = totp_inactivo_con_secreto

        totp_inactivo_con_codigos = self._snapshot_valido()
        totp_inactivo_con_codigos["users"][0]["totp"][
            "recovery_code_hashes"] = ["a" * 64]
        casos["totp inactivo con recovery"] = totp_inactivo_con_codigos

        totp_dos_secretos = self._snapshot_valido()
        totp_dos_secretos["users"][0]["totp"].update({
            "enabled": True,
            "secret": "fernet:activo",
            "pending_secret": "fernet:pendiente",
        })
        casos["totp activo y pendiente"] = totp_dos_secretos

        codigos_duplicados = self._snapshot_valido()
        codigos_duplicados["users"][0]["totp"].update({
            "enabled": True,
            "secret": "fernet:activo",
            "recovery_code_hashes": ["a" * 64, "a" * 64],
        })
        casos["recovery duplicado"] = codigos_duplicados

        id_api_no_canonico = self._snapshot_valido()
        id_api_no_canonico["api_keys"] = [
            self._clave_api("key-a", "Aplicación")]
        casos["id API no hex32"] = id_api_no_canonico

        api_activa_revocada = self._snapshot_valido()
        activa = self._clave_api("a" * 32, "Aplicación")
        activa.update({
            "revoked_at": "2026-01-01T00:00:00Z", "revoked_by": "admin"})
        api_activa_revocada["api_keys"] = [activa]
        casos["API activa con revocación"] = api_activa_revocada

        api_revocada_incompleta = self._snapshot_valido()
        revocada = self._clave_api("b" * 32, "Aplicación")
        revocada.update({"status": "revoked", "token_hash": None})
        api_revocada_incompleta["api_keys"] = [revocada]
        casos["API revocada sin auditoría"] = api_revocada_incompleta

        for nombre, snapshot in casos.items():
            with self.subTest(nombre=nombre):
                with self.assertRaises(seguridad.ErrorAcceso) as error:
                    seguridad.AlmacenSeguridad.validar_snapshot(snapshot)
                self.assertEqual("AUTH_STATE_INVALID", error.exception.codigo)

    def test_claves_api_se_guardan_hasheadas_y_se_pueden_revocar(self):
        self._alta_inicial()
        identificador, token, hash_token = self.proteccion.generar_clave_api()
        publica, _ = self.almacen.crear_clave_api(
            identificador, "aplicacion-a", token[:20] + "...", hash_token,
            ["status:read", "claims:write"], "admin",
        )

        self.assertNotIn("token_hash", publica)
        guardada = self.almacen.clave_api_por_id(identificador)
        self.assertNotIn(token, Path(self.ruta).read_text(encoding="utf-8"))
        self.assertTrue(self.proteccion.comprobar_clave_api(
            token, guardada["token_hash"]))

        revocada, _ = self.almacen.revocar_clave_api(identificador, "admin")
        self.assertEqual("revoked", revocada["status"])

    def test_base_documental_no_colisiona_con_otras_aplicaciones(self):
        self._alta_inicial()
        for nombre in ("NPM Guardian", "Base Documental"):
            identificador, token, hash_token = self.proteccion.generar_clave_api()
            creada, _ = self.almacen.crear_clave_api(
                identificador, nombre, token[:20] + "...", hash_token,
                ["status:read"], "admin",
            )
            self.assertEqual(nombre, creada["name"])

        identificador, token, hash_token = self.proteccion.generar_clave_api()
        with self.assertRaises(seguridad.ErrorAcceso) as conflicto:
            self.almacen.crear_clave_api(
                identificador, "  base   documental  ", token[:20] + "...", hash_token,
                ["status:read"], "admin",
            )
        self.assertEqual("API_KEY_CONFLICT", conflicto.exception.codigo)
        self.assertIn("Base Documental", str(conflicto.exception))

    def test_compatibilidad_1_0_0_admite_api_keys_ausente(self):
        snapshot = self._snapshot_valido()
        snapshot.pop("api_keys")
        seguridad.AlmacenSeguridad.validar_snapshot(snapshot)
        Path(self.ruta).write_text(json.dumps(snapshot), encoding="utf-8")

        self.assertEqual([], self.almacen.leer()["api_keys"])

    def test_rechaza_nan_campos_desconocidos_y_colecciones_sobredimensionadas(self):
        nan = self._snapshot_valido()
        nan["revision"]["timestamp"] = float("nan")
        desconocido = self._snapshot_valido()
        desconocido["incrustado"] = "no"
        demasiados_usuarios = self._snapshot_valido()
        demasiados_usuarios["users"] = (
            demasiados_usuarios["users"] * (seguridad._MAX_USUARIOS + 1))
        demasiadas_claves = self._snapshot_valido()
        demasiadas_claves["api_keys"] = [
            self._clave_api(f"key-{indice}", f"Aplicación {indice}")
            for indice in range(seguridad._MAX_CLAVES_API + 1)
        ]

        for snapshot in (nan, desconocido, demasiados_usuarios, demasiadas_claves):
            with self.subTest(tipo=type(snapshot).__name__):
                with self.assertRaises(seguridad.ErrorAcceso) as error:
                    seguridad.AlmacenSeguridad.validar_snapshot(snapshot)
                self.assertIn(
                    error.exception.codigo,
                    ("AUTH_STATE_INVALID", "AUTH_STATE_TOO_LARGE"),
                )

    def test_limite_512_kib_se_aplica_al_entrante_y_al_fichero(self):
        enorme = self._snapshot_valido()
        enorme["users"][0]["display_name"] = (
            "x" * (seguridad._MAX_ESTADO_ACCESO_BYTES + 1))
        with self.assertRaises(seguridad.ErrorAcceso) as error:
            seguridad.AlmacenSeguridad.validar_snapshot(enorme)
        self.assertEqual("AUTH_STATE_TOO_LARGE", error.exception.codigo)

        Path(self.ruta).write_bytes(
            b" " * (seguridad._MAX_ESTADO_ACCESO_BYTES + 1))
        with self.assertRaises(seguridad.ErrorAcceso) as error:
            self.almacen.leer()
        self.assertEqual("AUTH_STATE_TOO_LARGE", error.exception.codigo)

    def test_json_duplicado_en_disco_falla_cerrado(self):
        crudo = json.dumps(self._snapshot_valido())
        crudo = crudo.replace(
            '{"schema": 1,', '{"schema": 1, "schema": 1,', 1)
        Path(self.ruta).write_text(crudo, encoding="utf-8")

        with self.assertRaises(seguridad.ErrorAcceso) as error:
            self.almacen.leer()
        self.assertEqual("AUTH_STORAGE_ERROR", error.exception.codigo)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink no disponible")
    def test_rechaza_security_json_symlink(self):
        victima = Path(self.tmp.name) / "victima.json"
        victima.write_text(json.dumps(self._snapshot_valido()), encoding="utf-8")
        Path(self.ruta).symlink_to(victima)

        with self.assertRaisesRegex(seguridad.ErrorAcceso, "enlace simbólico"):
            self.almacen.leer()

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO no disponible")
    def test_rechaza_fifo_antes_de_abrirlo(self):
        os.mkfifo(self.ruta)

        with self.assertRaisesRegex(seguridad.ErrorAcceso, "fichero regular"):
            self.almacen.leer()

    @unittest.skipUnless(hasattr(os, "link"), "hardlink no disponible")
    def test_rechaza_hardlink(self):
        victima = Path(self.tmp.name) / "victima.json"
        victima.write_text(json.dumps(self._snapshot_valido()), encoding="utf-8")
        os.link(victima, self.ruta)

        with self.assertRaisesRegex(seguridad.ErrorAcceso, "enlaces duros"):
            self.almacen.leer()

    @unittest.skipUnless(os.name == "posix", "permisos POSIX")
    def test_normaliza_directorio_ficheros_y_lock_a_permisos_privados(self):
        ruta = Path(self.ruta)
        ruta.write_text(json.dumps(self._snapshot_valido()), encoding="utf-8")
        os.chmod(self.tmp.name, 0o777)
        os.chmod(ruta, 0o644)
        if os.geteuid() == 0:
            os.chown(self.tmp.name, 12345, 12345)
            os.chown(ruta, 12345, 12345)

        self.almacen.leer()

        estado_dir = os.stat(self.tmp.name)
        self.assertEqual(os.geteuid(), estado_dir.st_uid)
        self.assertEqual(0o700, stat.S_IMODE(estado_dir.st_mode))
        for protegida in (ruta, Path(self.almacen.ruta_candado)):
            estado = protegida.stat()
            self.assertEqual(os.geteuid(), estado.st_uid)
            self.assertEqual(0o600, stat.S_IMODE(estado.st_mode))

    def test_temporal_es_aleatorio_0600_y_se_limpia_si_falla_replace(self):
        ruta = Path(self.ruta)
        ruta.write_text(json.dumps(self._snapshot_valido()), encoding="utf-8")
        anterior = ruta.read_bytes()
        temporales = []

        def reemplazo_fallido(origen, destino):
            temporales.append(Path(origen).name)
            self.assertNotEqual(ruta.name + ".tmp", Path(origen).name)
            if os.name == "posix":
                self.assertEqual(0o600, stat.S_IMODE(os.stat(origen).st_mode))
            raise OSError(errno.EIO, "fallo simulado")

        with mock.patch.object(
                seguridad.os, "replace", side_effect=reemplazo_fallido):
            with self.assertRaises(OSError):
                self.almacen.actualizar_perfil(
                    USUARIO_ID_PRUEBA, "Nombre nuevo", "admin")

        self.assertEqual(1, len(temporales))
        self.assertEqual(anterior, ruta.read_bytes())
        self.assertEqual([], list(Path(self.tmp.name).glob(".security.*.tmp")))

    @unittest.skipUnless(seguridad.fcntl is not None, "flock no disponible")
    def test_flock_serializa_dos_instancias_sobre_el_mismo_estado(self):
        Path(self.ruta).write_text(
            json.dumps(self._snapshot_valido()), encoding="utf-8")
        primero = seguridad.AlmacenSeguridad(self.ruta, "node-a")
        segundo = seguridad.AlmacenSeguridad(self.ruta, "node-b")
        entro_primero = threading.Event()
        liberar_primero = threading.Event()
        inicio_segundo = threading.Event()
        entro_segundo = threading.Event()
        errores = []

        def mutacion_uno(datos):
            entro_primero.set()
            if not liberar_primero.wait(timeout=5):
                raise RuntimeError("timeout esperando liberar primera mutación")
            datos["api_keys"].append(self._clave_api("a" * 32, "Aplicación A"))
            return datos["api_keys"][-1]

        def mutacion_dos(datos):
            entro_segundo.set()
            datos["api_keys"].append(self._clave_api("b" * 32, "Aplicación B"))
            return datos["api_keys"][-1]

        def ejecutar(almacen, actor, funcion, inicio=None):
            if inicio:
                inicio.set()
            try:
                almacen._mutar(actor, funcion)
            except Exception as error:  # noqa: BLE001 - se informa al hilo principal.
                errores.append(error)

        hilo_a = threading.Thread(
            target=ejecutar, args=(primero, "admin", mutacion_uno))
        hilo_a.start()
        self.assertTrue(entro_primero.wait(timeout=5))
        hilo_b = threading.Thread(
            target=ejecutar,
            args=(segundo, "admin", mutacion_dos, inicio_segundo),
        )
        hilo_b.start()
        self.assertTrue(inicio_segundo.wait(timeout=5))
        self.assertFalse(entro_segundo.wait(timeout=0.2))
        liberar_primero.set()
        hilo_a.join(timeout=10)
        hilo_b.join(timeout=10)
        self.assertFalse(hilo_a.is_alive())
        self.assertFalse(hilo_b.is_alive())
        self.assertEqual([], errores)
        final = self.almacen.leer()
        self.assertEqual(
            {"Aplicación A", "Aplicación B"},
            {clave["name"] for clave in final["api_keys"]},
        )
        self.assertEqual(
            {"node-a": 1, "node-b": 1},
            final["revision"]["clock"],
        )

    @unittest.skipUnless(os.name == "posix", "fsync de directorio POSIX")
    def test_fsync_eio_del_directorio_no_se_oculta(self):
        Path(self.ruta).write_text(
            json.dumps(self._snapshot_valido()), encoding="utf-8")
        fsync_real = seguridad.os.fsync

        def fsync_con_eio(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(errno.EIO, "fallo de almacenamiento")
            return fsync_real(fd)

        with mock.patch.object(seguridad.os, "fsync", side_effect=fsync_con_eio):
            with self.assertRaises(seguridad.ErrorAcceso) as error:
                self.almacen.actualizar_perfil(
                    USUARIO_ID_PRUEBA, "Nombre tras EIO", "admin")
        self.assertEqual("AUTH_COMMIT_UNCERTAIN", error.exception.codigo)
        self.assertEqual(503, error.exception.http)
        self.assertEqual(errno.EIO, error.exception.__cause__.errno)
        self.assertEqual(
            "Nombre tras EIO",
            self.almacen.por_id(USUARIO_ID_PRUEBA)["display_name"],
        )
        self.assertEqual([], list(Path(self.tmp.name).glob(".security.*.tmp")))

    @unittest.skipUnless(os.name == "posix", "fsync de directorio POSIX")
    def test_fsync_no_soportado_del_directorio_se_tolera(self):
        Path(self.ruta).write_text(
            json.dumps(self._snapshot_valido()), encoding="utf-8")
        fsync_real = seguridad.os.fsync

        def fsync_no_soportado(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(errno.EINVAL, "operación no soportada")
            return fsync_real(fd)

        with mock.patch.object(
                seguridad.os, "fsync", side_effect=fsync_no_soportado):
            self.almacen.actualizar_perfil(
                USUARIO_ID_PRUEBA, "Nombre persistido", "admin")
        self.assertEqual(
            "Nombre persistido",
            self.almacen.por_id(USUARIO_ID_PRUEBA)["display_name"])


class ProtocoloClusterTest(unittest.TestCase):
    def test_firma_cifrado_y_antireplay(self):
        emisor = seguridad.ProtocoloCluster(
            TOKEN_CLUSTER, "node-a", {"node-a", "node-b"})
        receptor = seguridad.ProtocoloCluster(
            TOKEN_CLUSTER, "node-b", {"node-a", "node-b"})
        cuerpo = b'{"estado":"ok"}'
        cabeceras = emisor.firmar("POST", "/api/internal/security", cuerpo)

        self.assertEqual(
            "node-a",
            receptor.verificar(
                "POST", "/api/internal/security", cuerpo, cabeceras),
        )
        with self.assertRaisesRegex(seguridad.ErrorAcceso, "ya fue utilizada"):
            receptor.verificar(
                "POST", "/api/internal/security", cuerpo, cabeceras)

        sobre = emisor.cifrar({"users": [], "schema": 1})
        self.assertEqual(1, receptor.descifrar(sobre)["schema"])

    def test_cache_antireplay_es_acotada_y_falla_cerrada(self):
        emisor = seguridad.ProtocoloCluster(
            TOKEN_CLUSTER, "node-a", {"node-a", "node-b"})
        receptor = seguridad.ProtocoloCluster(
            TOKEN_CLUSTER, "node-b", {"node-a", "node-b"})
        cuerpo = b"{}"

        with mock.patch.object(seguridad, "_MAX_NONCES_CLUSTER", 2), \
                mock.patch.object(
                    seguridad.time, "monotonic", return_value=1000):
            for _ in range(2):
                receptor.verificar(
                    "POST", "/api/internal/v2/security", cuerpo,
                    emisor.firmar(
                        "POST", "/api/internal/v2/security", cuerpo),
                )
            with self.assertRaises(seguridad.ErrorAcceso) as error:
                receptor.verificar(
                    "POST", "/api/internal/v2/security", cuerpo,
                    emisor.firmar(
                        "POST", "/api/internal/v2/security", cuerpo),
                )

        self.assertEqual("CLUSTER_REPLAY_CACHE_FULL", error.exception.codigo)
        self.assertEqual(2, len(receptor.nonces))

    def test_cache_antireplay_purga_por_reloj_monotono(self):
        emisor = seguridad.ProtocoloCluster(
            TOKEN_CLUSTER, "node-a", {"node-a", "node-b"})
        receptor = seguridad.ProtocoloCluster(
            TOKEN_CLUSTER, "node-b", {"node-a", "node-b"})
        cuerpo = b"{}"
        primera = emisor.firmar(
            "POST", "/api/internal/v2/security", cuerpo)
        segunda = emisor.firmar(
            "POST", "/api/internal/v2/security", cuerpo)

        with mock.patch.object(seguridad, "_MAX_NONCES_CLUSTER", 1), \
                mock.patch.object(
                    seguridad.time, "monotonic", side_effect=[1000, 1121]):
            receptor.verificar(
                "POST", "/api/internal/v2/security", cuerpo, primera)
            receptor.verificar(
                "POST", "/api/internal/v2/security", cuerpo, segunda)

        self.assertEqual({segunda["X-FIP-Nonce"]}, set(receptor.nonces))

    def test_descifrado_rechaza_duplicados_nan_y_sobres_sobredimensionados(self):
        protocolo = seguridad.ProtocoloCluster(
            TOKEN_CLUSTER, "node-a", {"node-a", "node-b"})
        duplicado = protocolo.fernet.encrypt(
            b'{"nodo":"node-a","nodo":"node-b"}').decode()
        nan = protocolo.fernet.encrypt(b'{"valor":NaN}').decode()

        for sobre in (duplicado, nan):
            with self.subTest(sobre=sobre[:20]):
                with self.assertRaises(seguridad.ErrorAcceso) as error:
                    protocolo.descifrar(sobre)
                self.assertEqual(
                    "INVALID_SECURITY_REPLICA", error.exception.codigo)

        with mock.patch.object(seguridad, "_MAX_SOBRE_CLUSTER_BYTES", 10):
            with self.assertRaises(seguridad.ErrorAcceso) as error:
                protocolo.descifrar(protocolo.cifrar({"estado": "ok"}))
        self.assertEqual("INVALID_SECURITY_REPLICA", error.exception.codigo)


class ClaveApiHttpTest(unittest.TestCase):
    class Peticion:
        def __init__(self, token):
            self.headers = {"Authorization": "Bearer " + token}

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.proteccion = seguridad.ProteccionCuenta(SECRETO)
        self.almacen = seguridad.AlmacenSeguridad(
            str(Path(self.tmp.name) / "security.json"), "node-a")
        self.almacen.crear_propietario(
            "admin", "Administrador",
            self.proteccion.hash_clave("Clave-inicial-2026"),
        )
        identificador, self.token, hash_token = self.proteccion.generar_clave_api()
        self.almacen.crear_clave_api(
            identificador, "lector", self.token[:20] + "...", hash_token,
            ["status:read"], "admin",
        )
        self.control = auth_http.ControlAcceso(
            self.almacen, self.proteccion, seguridad.Sesiones(SECRETO),
            lambda: None, lambda snapshot: {"ok": True},
        )

    def test_acepta_solo_el_scope_concedido(self):
        identidad = self.control.exigir_clave_api(
            self.Peticion(self.token), "status:read")
        self.assertEqual("lector", identidad["name"])

        with self.assertRaisesRegex(seguridad.ErrorAcceso, "no tiene permiso"):
            self.control.exigir_clave_api(
                self.Peticion(self.token), "claims:write")

    def test_rechaza_un_token_manipulado(self):
        manipulado = self.token[:-1] + ("x" if self.token[-1] != "x" else "y")
        with self.assertRaisesRegex(seguridad.ErrorAcceso, "no es válida"):
            self.control.exigir_clave_api(
                self.Peticion(manipulado), "status:read")


class ControlAccesoPreflightTest(unittest.TestCase):
    class PeticionLogin:
        headers = {}
        client_address = ("192.0.2.40", 12345)

        def __init__(self, cuerpo):
            self.cuerpo = cuerpo
            self.respuesta = None

        def _cuerpo(self):
            return dict(self.cuerpo)

        def _json(self, datos, *args, **kwargs):
            self.respuesta = datos
            return datos

        def _error(self, mensaje, http=400, codigo="INVALID_REQUEST", **_kwargs):
            self.respuesta = {"error": mensaje, "code": codigo, "http": http}
            return self.respuesta

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.proteccion = seguridad.ProteccionCuenta(SECRETO)
        self.almacen = seguridad.AlmacenSeguridad(
            str(Path(self.tmp.name) / "security.json"), "node-a")
        self.usuario, _ = self.almacen.crear_propietario(
            "admin", "Administrador",
            self.proteccion.hash_clave("Clave-inicial-2026"),
        )
        self.reconciliar = mock.Mock(return_value={"ok": True})
        self.replicar = mock.Mock(return_value={"ok": True})
        self.preflight = mock.Mock(return_value={"ok": True})
        self.control = auth_http.ControlAcceso(
            self.almacen, self.proteccion, seguridad.Sesiones(SECRETO),
            self.reconciliar, self.replicar, self.preflight,
        )

    def _snapshot_admin_deshabilitado(self):
        _, base = self.almacen.crear_usuario(
            "respaldo", "Administrador de respaldo",
            self.proteccion.hash_clave("Clave-respaldo-2026"),
            "admin", "admin",
        )
        remoto = seguridad.AlmacenSeguridad(
            str(Path(self.tmp.name) / "remote.json"), "node-b")
        remoto.aplicar_replica(base)
        _, snapshot = remoto.actualizar_acceso(
            self.usuario["id"], "respaldo", {"status": "disabled"})
        return snapshot

    def test_sin_quorum_preflight_no_ejecuta_operacion(self):
        operacion = mock.Mock()
        self.preflight.side_effect = seguridad.ErrorAcceso(
            "Sin quorum", "AUTH_QUORUM_UNAVAILABLE", 503)

        with self.assertRaises(seguridad.ErrorAcceso) as error:
            self.control._ejecutar_mutacion(operacion)

        self.assertEqual("AUTH_QUORUM_UNAVAILABLE", error.exception.codigo)
        operacion.assert_not_called()
        self.replicar.assert_not_called()

    def test_commit_incierto_se_expone_aunque_el_cambio_ya_persistio(self):
        self.replicar.side_effect = seguridad.ErrorAcceso(
            "Confirmación incierta", "AUTH_COMMIT_UNCERTAIN", 503)

        with self.assertRaises(seguridad.ErrorAcceso) as error:
            self.control._ejecutar_mutacion(
                lambda: self.almacen.actualizar_perfil(
                    self.usuario["id"], "Nombre persistido", "admin"))

        self.assertEqual("AUTH_COMMIT_UNCERTAIN", error.exception.codigo)
        self.assertEqual(
            "Nombre persistido",
            self.almacen.por_id(self.usuario["id"])["display_name"],
        )

    @unittest.skipUnless(os.name == "posix", "fsync de directorio POSIX")
    def test_ruta_con_fsync_eio_conserva_codigo_commit_incierto(self):
        token, identidad = self.control.sesiones.crear(
            self.almacen.por_id(self.usuario["id"]))
        peticion = self.PeticionLogin({"display_name": "Visible pero incierto"})
        peticion.headers = {
            "Cookie": f"{seguridad.COOKIE}={token}",
            "X-CSRF-Token": identidad.csrf,
        }
        fsync_real = seguridad.os.fsync

        def fsync_con_eio(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(errno.EIO, "fallo de almacenamiento")
            return fsync_real(fd)

        with mock.patch.object(
                seguridad.os, "fsync", side_effect=fsync_con_eio):
            self.control.manejar(peticion, "PATCH", "/api/profile")

        self.assertEqual("AUTH_COMMIT_UNCERTAIN", peticion.respuesta["code"])
        self.assertEqual(503, peticion.respuesta["http"])
        self.assertEqual(
            "Visible pero incierto",
            self.almacen.por_id(self.usuario["id"])["display_name"],
        )
        self.replicar.assert_not_called()

    def test_mutaciones_se_serializan_hasta_el_ack(self):
        primera_en_ack = threading.Event()
        liberar_primera = threading.Event()
        segunda_escritura = threading.Event()
        errores = []

        def replicar(snapshot):
            if snapshot["id"] == 1:
                primera_en_ack.set()
                if not liberar_primera.wait(timeout=5):
                    raise RuntimeError("timeout esperando ACK")
            return {"ok": True}

        self.control.replicar = replicar

        def ejecutar(identificador):
            try:
                def operacion():
                    if identificador == 2:
                        segunda_escritura.set()
                    return {"id": identificador}
                self.control._ejecutar_mutacion(operacion)
            except Exception as error:  # noqa: BLE001
                errores.append(error)

        primero = threading.Thread(target=ejecutar, args=(1,))
        segundo = threading.Thread(target=ejecutar, args=(2,))
        primero.start()
        self.assertTrue(primera_en_ack.wait(timeout=5))
        segundo.start()
        self.assertFalse(segunda_escritura.wait(timeout=0.2))
        liberar_primera.set()
        primero.join(timeout=5)
        segundo.join(timeout=5)

        self.assertEqual([], errores)
        self.assertTrue(segunda_escritura.is_set())

    def test_autorizacion_y_mutacion_pool_bloquean_revocacion_concurrente(self):
        operador, _ = self.almacen.crear_usuario(
            "operador", "Operador",
            self.proteccion.hash_clave("Clave-operador-2026"),
            "operator", "admin",
        )
        token, identidad = self.control.sesiones.crear(
            self.almacen.por_id(operador["id"]))
        peticion = self.PeticionLogin({})
        peticion.headers = {
            "Cookie": f"{seguridad.COOKIE}={token}",
            "X-CSRF-Token": identidad.csrf,
        }
        autorizada = threading.Event()
        liberar = threading.Event()
        revocada = threading.Event()
        pool_mutado = threading.Event()
        errores = []

        def mutar_pool():
            try:
                with self.control.autorizar_mutacion(
                        peticion, rol="operator",
                        permitir_cambio_pendiente=True):
                    autorizada.set()
                    if not liberar.wait(timeout=5):
                        raise RuntimeError("timeout de prueba")
                    pool_mutado.set()
            except Exception as error:  # noqa: BLE001
                errores.append(error)

        def revocar():
            try:
                self.control._ejecutar_mutacion(
                    lambda: self.almacen.actualizar_acceso(
                        operador["id"], "admin", {"status": "disabled"}))
                revocada.set()
            except Exception as error:  # noqa: BLE001
                errores.append(error)

        hilo_pool = threading.Thread(target=mutar_pool)
        hilo_revocacion = threading.Thread(target=revocar)
        hilo_pool.start()
        self.assertTrue(autorizada.wait(timeout=5))
        hilo_revocacion.start()
        self.assertFalse(revocada.wait(timeout=0.2))
        liberar.set()
        hilo_pool.join(timeout=5)
        hilo_revocacion.join(timeout=5)

        self.assertFalse(hilo_pool.is_alive())
        self.assertFalse(hilo_revocacion.is_alive())
        self.assertEqual([], errores)
        self.assertTrue(pool_mutado.is_set())
        self.assertTrue(revocada.is_set())
        self.assertEqual(
            "disabled",
            self.almacen.por_id(operador["id"])["status"],
        )

    def test_autorizacion_pool_bloquea_instalacion_de_replica_concurrente(self):
        operador, base = self.almacen.crear_usuario(
            "operador", "Operador",
            self.proteccion.hash_clave("Clave-operador-2026"),
            "operator", "admin",
        )
        remoto = seguridad.AlmacenSeguridad(
            str(Path(self.tmp.name) / "remote-race.json"), "node-b")
        remoto.aplicar_replica(base)
        _, snapshot_revocado = remoto.actualizar_acceso(
            operador["id"], "admin", {"status": "disabled"})
        token, identidad = self.control.sesiones.crear(
            self.almacen.por_id(operador["id"]))
        peticion = self.PeticionLogin({})
        peticion.headers = {
            "Cookie": f"{seguridad.COOKIE}={token}",
            "X-CSRF-Token": identidad.csrf,
        }
        autorizada = threading.Event()
        liberar = threading.Event()
        replica_instalada = threading.Event()
        pool_mutado = threading.Event()
        errores = []

        def mutar_pool():
            try:
                with self.control.autorizar_mutacion(
                        peticion, rol="operator",
                        permitir_cambio_pendiente=True):
                    autorizada.set()
                    if not liberar.wait(timeout=5):
                        raise RuntimeError("timeout de prueba")
                    pool_mutado.set()
            except Exception as error:  # noqa: BLE001
                errores.append(error)

        def instalar_replica():
            try:
                with self.control.bloquear_estado_seguridad():
                    self.almacen.aplicar_replica(snapshot_revocado)
                replica_instalada.set()
            except Exception as error:  # noqa: BLE001
                errores.append(error)

        hilo_pool = threading.Thread(target=mutar_pool)
        hilo_replica = threading.Thread(target=instalar_replica)
        hilo_pool.start()
        self.assertTrue(autorizada.wait(timeout=5))
        hilo_replica.start()
        self.assertFalse(replica_instalada.wait(timeout=0.2))
        liberar.set()
        hilo_pool.join(timeout=5)
        hilo_replica.join(timeout=5)

        self.assertFalse(hilo_pool.is_alive())
        self.assertFalse(hilo_replica.is_alive())
        self.assertEqual([], errores)
        self.assertTrue(pool_mutado.is_set())
        self.assertTrue(replica_instalada.is_set())
        self.assertEqual(
            "disabled",
            self.almacen.por_id(operador["id"])["status"],
        )

    def test_fase_e2e_admite_bearer_solo_con_permiso_explicito(self):
        identificador, token, hash_token = self.proteccion.generar_clave_api()
        self.almacen.crear_clave_api(
            identificador, "automatización", token[:20] + "...", hash_token,
            ["claims:write"], "admin",
        )
        peticion = self.PeticionLogin({})
        peticion.headers = {"Authorization": "Bearer " + token}

        with self.control.autorizar_mutacion(
                peticion, rol="operator",
                permiso_api="claims:write") as identidad:
            self.assertEqual(identificador, identidad["id"])

        self.reconciliar.assert_called_once_with()

    def test_ruta_mutante_hace_preflight_antes_de_autorizar(self):
        orden = []
        self.control.preflight_mutacion = lambda: orden.append("preflight")
        peticion = self.PeticionLogin({})
        peticion._cuerpo = lambda: orden.append("cuerpo") or {}
        with mock.patch.object(
                self.control, "_manejar",
                side_effect=lambda *_args: orden.append("autorizar")):
            self.control.manejar(peticion, "PATCH", "/api/profile")

        self.assertEqual(["cuerpo", "preflight", "autorizar"], orden)

    def test_cuerpo_lento_no_retiene_barrera_y_se_lee_una_sola_vez(self):
        lectura_iniciada = threading.Event()
        liberar_lectura = threading.Event()
        candado_disponible = threading.Event()
        llamadas = []
        vistas = []
        errores = []
        peticion = self.PeticionLogin({})

        def cuerpo_lento():
            llamadas.append("leer")
            lectura_iniciada.set()
            if not liberar_lectura.wait(timeout=5):
                raise RuntimeError("timeout esperando liberar el cuerpo")
            return {"display_name": "Vista fijada"}

        peticion._cuerpo = cuerpo_lento

        def manejar_interno(manejador, *_args):
            # Simula el handler real, que consulta el cuerpo ya dentro de la
            # barrera. Debe recibir exactamente el objeto precargado.
            vistas.append(self.control._cuerpo(manejador))
            return True

        def ejecutar_peticion():
            try:
                self.control.manejar(peticion, "PATCH", "/api/profile")
            except Exception as error:  # noqa: BLE001
                errores.append(error)

        def probar_candado():
            try:
                with self.control.bloquear_estado_seguridad():
                    candado_disponible.set()
            except Exception as error:  # noqa: BLE001
                errores.append(error)

        with mock.patch.object(
                self.control, "_manejar", side_effect=manejar_interno):
            hilo_lento = threading.Thread(target=ejecutar_peticion)
            hilo_candado = threading.Thread(target=probar_candado)
            hilo_lento.start()
            self.assertTrue(lectura_iniciada.wait(timeout=5))
            hilo_candado.start()
            self.assertTrue(candado_disponible.wait(timeout=1))
            self.preflight.assert_not_called()
            liberar_lectura.set()
            hilo_lento.join(timeout=5)
            hilo_candado.join(timeout=5)

        self.assertFalse(hilo_lento.is_alive())
        self.assertFalse(hilo_candado.is_alive())
        self.assertEqual([], errores)
        self.assertEqual(["leer"], llamadas)
        self.assertEqual([{"display_name": "Vista fijada"}], vistas)
        self.preflight.assert_called_once_with()

    def test_cuerpo_cacheado_elimina_relectura_y_toctou(self):
        token, identidad = self.control.sesiones.crear(
            self.almacen.por_id(self.usuario["id"]))
        peticion = self.PeticionLogin({})
        peticion.headers = {
            "Cookie": f"{seguridad.COOKIE}={token}",
            "X-CSRF-Token": identidad.csrf,
        }
        cuerpos = [
            {"display_name": "Nombre autorizado"},
            {"display_name": "Valor TOCTOU"},
        ]
        llamadas = []

        def cuerpo_cambiante():
            posicion = len(llamadas)
            llamadas.append(posicion)
            return dict(cuerpos[min(posicion, len(cuerpos) - 1)])

        peticion._cuerpo = cuerpo_cambiante
        self.control.manejar(peticion, "PATCH", "/api/profile")

        self.assertEqual([0], llamadas)
        self.assertEqual(
            "Nombre autorizado",
            self.almacen.por_id(self.usuario["id"])["display_name"],
        )
        self.assertEqual("Nombre autorizado", peticion.respuesta["profile"]["display_name"])

    def test_login_sin_quorum_falla_antes_de_leer_credenciales(self):
        self.reconciliar.side_effect = seguridad.ErrorAcceso(
            "Sin quorum", "AUTH_QUORUM_UNAVAILABLE", 503)
        peticion = self.PeticionLogin({
            "username": "admin", "password": "Clave-inicial-2026",
        })

        with self.assertRaises(seguridad.ErrorAcceso) as error:
            self.control._login(peticion)

        self.assertEqual("AUTH_QUORUM_UNAVAILABLE", error.exception.codigo)
        self.preflight.assert_not_called()

    def test_login_normal_funciona_en_no_writer_tras_reconciliar(self):
        self.preflight.side_effect = seguridad.ErrorAcceso(
            "Sólo escritor", "AUTH_WRITER_REQUIRED", 503)
        peticion = self.PeticionLogin({
            "username": "admin", "password": "Clave-inicial-2026",
        })

        self.control._login(peticion)

        self.reconciliar.assert_called_once_with()
        self.preflight.assert_not_called()
        self.assertEqual("password", peticion.respuesta["login_method"])

    def test_preflight_revoca_admin_antes_de_autorizar_ruta_mutante(self):
        remoto = self._snapshot_admin_deshabilitado()
        sesiones = self.control.sesiones
        usuario_local = self.almacen.por_id(self.usuario["id"])
        token, identidad = sesiones.crear(usuario_local)
        peticion = self.PeticionLogin({"display_name": "No debe escribirse"})
        peticion.headers = {
            "Cookie": f"{seguridad.COOKIE}={token}",
            "X-CSRF-Token": identidad.csrf,
        }
        self.control.preflight_mutacion = (
            lambda: self.almacen.aplicar_replica(remoto))

        self.control.manejar(peticion, "PATCH", "/api/profile")

        self.assertEqual("SESSION_INVALIDATED", peticion.respuesta["code"])
        self.assertNotEqual(
            "No debe escribirse",
            self.almacen.por_id(self.usuario["id"])["display_name"],
        )
        self.replicar.assert_not_called()

    def test_login_reconciliado_rechaza_cuenta_deshabilitada_remota(self):
        remoto = self._snapshot_admin_deshabilitado()
        self.control.reconciliar = lambda: self.almacen.aplicar_replica(remoto)
        peticion = self.PeticionLogin({
            "username": "admin", "password": "Clave-inicial-2026",
        })

        with self.assertRaises(seguridad.ErrorAcceso) as error:
            self.control._login(peticion)

        self.assertEqual("INVALID_CREDENTIALS", error.exception.codigo)
        self.preflight.assert_not_called()

    def test_mutacion_pool_rechaza_usuario_revocado_tras_reconciliar(self):
        remoto = self._snapshot_admin_deshabilitado()
        token, identidad = self.control.sesiones.crear(
            self.almacen.por_id(self.usuario["id"]))
        peticion = self.PeticionLogin({})
        peticion.headers = {
            "Cookie": f"{seguridad.COOKIE}={token}",
            "X-CSRF-Token": identidad.csrf,
        }
        self.control.reconciliar = lambda: self.almacen.aplicar_replica(remoto)

        with self.assertRaises(seguridad.ErrorAcceso) as error:
            self.control.exigir(peticion, "operator", mutacion=True)

        self.assertEqual("SESSION_INVALIDATED", error.exception.codigo)
        self.preflight.assert_not_called()

    def test_mutacion_pool_rechaza_api_revocada_tras_reconciliar(self):
        identificador, token, hash_token = self.proteccion.generar_clave_api()
        _, base = self.almacen.crear_clave_api(
            identificador, "automatización", token[:20] + "...", hash_token,
            ["claims:write"], "admin",
        )
        remoto = seguridad.AlmacenSeguridad(
            str(Path(self.tmp.name) / "remote-api.json"), "node-b")
        remoto.aplicar_replica(base)
        _, revocado = remoto.revocar_clave_api(identificador, "admin")
        self.control.reconciliar = lambda: self.almacen.aplicar_replica(revocado)
        peticion = self.PeticionLogin({})
        peticion.headers = {"Authorization": "Bearer " + token}

        with self.assertRaises(seguridad.ErrorAcceso) as error:
            self.control.exigir_api_o_usuario(
                peticion, "claims:write", "operator", mutacion=True)

        self.assertEqual("INVALID_API_KEY", error.exception.codigo)
        self.preflight.assert_not_called()

    def test_limitador_acota_origenes_y_falla_cerrado_al_saturarse(self):
        with mock.patch.object(auth_http, "_MAX_ORIGENES_FALLOS", 3), \
                mock.patch.object(auth_http, "_MAX_FALLOS_POR_ORIGEN", 2), \
                mock.patch.object(auth_http.time, "monotonic", return_value=1000):
            for origen in ("192.0.2.1", "192.0.2.2", "192.0.2.3"):
                self.control._fallar(origen)
            self.control._fallar("192.0.2.4")

            self.assertEqual(3, len(self.control._fallos))
            self.assertNotIn("192.0.2.4", self.control._fallos)
            self.assertTrue(self.control._limitado("192.0.2.4"))
            for _ in range(10):
                self.control._fallar("192.0.2.1")
            self.assertEqual(2, len(self.control._fallos["192.0.2.1"]))

    def test_limitador_purga_globalmente_origenes_caducados(self):
        self.control._fallos = {
            "192.0.2.1": [1],
            "192.0.2.2": [950],
        }
        with mock.patch.object(auth_http.time, "monotonic", return_value=1000):
            self.assertFalse(self.control._limitado("192.0.2.3"))

        self.assertNotIn("192.0.2.1", self.control._fallos)
        self.assertIn("192.0.2.2", self.control._fallos)


if __name__ == "__main__":
    unittest.main()
