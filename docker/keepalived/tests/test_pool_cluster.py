import errno
import http.client
import json
import os
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from copy import deepcopy
from pathlib import Path
from unittest import mock


PANEL = Path(__file__).resolve().parents[1] / "panel"
sys.path.insert(0, str(PANEL))

import local  # noqa: E402
import pool  # noqa: E402
import seguridad  # noqa: E402
import servidor  # noqa: E402


NODOS = [
    {"nombre": "node-a", "ip": "192.0.2.10", "interfaz": "eth0", "prioridad": 150},
    {"nombre": "node-b", "ip": "192.0.2.11", "interfaz": "eth0", "prioridad": 100},
    {"nombre": "node-c", "ip": "192.0.2.12", "interfaz": "eth0", "prioridad": 90},
]
HASH_CLAVE_PRUEBA = (
    "scrypt$32768$8$1$AAAAAAAAAAAAAAAAAAAAAA$"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)


def crear_marker_bootstrap(ruta):
    ruta = Path(ruta)
    ruta.write_bytes(servidor.CONTENIDO_BOOTSTRAP)
    ruta.chmod(0o600)
    return ruta


def crear_marker_freeze(ruta):
    ruta = Path(ruta)
    ruta.write_bytes(servidor.CONTENIDO_DEPLOY_FREEZE)
    ruta.chmod(0o600)
    return ruta


class ProtocoloClaro:
    disponible = True

    @staticmethod
    def firmar(_metodo, _ruta, _cuerpo=b""):
        return {}

    @staticmethod
    def cifrar(valor):
        return valor

    @staticmethod
    def descifrar(valor):
        return valor


class RespuestaInternaFalsa:
    def __init__(self, cuerpo=b"", content_length=None, trozo=None):
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = str(content_length)
        self.cuerpo = cuerpo
        self.trozo = trozo
        self.posicion = 0
        self.lecturas = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read1(self, limite):
        self.lecturas += 1
        if self.posicion >= len(self.cuerpo):
            return b""
        cantidad = min(limite, self.trozo or limite)
        salida = self.cuerpo[self.posicion:self.posicion + cantidad]
        self.posicion += len(salida)
        return salida


class ClusterPoolTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.raiz = Path(self.tmp.name)

    def registro(self, nombre, autor):
        return pool.Pool(str(self.raiz / f"{nombre}.json"), autor=autor)

    @staticmethod
    def red(registros, caidos=()):
        endpoints = {f"http://{nombre}:6060": nombre for nombre in registros}
        caidos = set(caidos)

        def pedir(base, ruta, datos=None, metodo=None, tiempo=None):
            nombre = endpoints[base]
            if nombre in caidos:
                raise TimeoutError(nombre)
            registro = registros[nombre]
            if ruta == servidor.RUTA_POOL_V2:
                return {"payload": {
                    "capability": servidor.CAPACIDAD_POOL_V2,
                    "nodo": nombre, "initialized": registro.existe(),
                    "snapshot": registro.leer()}}
            if ruta == servidor.RUTA_REPLICA_POOL_V2:
                mensaje = datos["payload"]
                registro.aplicar_replica(mensaje["snapshot"])
                actual = registro.leer()
                return {"payload": {
                    "capability": servidor.CAPACIDAD_POOL_V2,
                    "estado": "ok", "nodo": nombre,
                    "huella": pool.Pool.huella(actual),
                }}
            raise AssertionError(ruta)

        return endpoints, pedir

    def contexto(self, yo, registro_local, pares, pedir):
        return mock.patch.multiple(
            servidor,
            POOL=registro_local,
            PARES=pares,
            PROTOCOLO=ProtocoloClaro(),
            _pedir_interno=pedir,
            MARCADOR_PROTOCOLO_V2=str(
                self.raiz / ".cluster-protocol-v2"),
            _observaciones_protocolo_v2={"pool": None, "security": None},
        ), mock.patch.object(local, "NODOS", NODOS), mock.patch.object(local, "YO", yo)

    def test_arranque_frio_inicializa_una_sola_rama_y_converge(self):
        registros = {nombre: self.registro(nombre, nombre)
                     for nombre in ("node-a", "node-b", "node-c")}
        endpoints, pedir = self.red(registros)
        parches = self.contexto(
            "node-a", registros["node-a"],
            [base for base, nombre in endpoints.items() if nombre != "node-a"],
            pedir)
        marker = crear_marker_bootstrap(self.raiz / ".bootstrap-pool")
        with parches[0], parches[1], parches[2], \
                mock.patch.object(
                    servidor, "MARCADOR_BOOTSTRAP_POOL", str(marker)), \
                mock.patch.object(servidor, "aplicar", return_value={"pendiente_arranque": True}):
            resultado = servidor.reconciliar_pool(aplicar_configuracion=True)

        self.assertEqual({"node-a": 1}, resultado["snapshot"]["revision"]["clock"])
        huellas = {pool.Pool.huella(registro.leer())
                   for registro in registros.values()}
        self.assertEqual(1, len(huellas))
        self.assertTrue(all(registro.existe()
                            for registro in registros.values()))
        self.assertEqual(3, resultado["propagacion"]["acknowledged"])
        self.assertFalse(marker.exists())

    def test_arranque_frio_sin_marker_falla_sin_materializar_ni_readiness(self):
        registros = {nombre: self.registro(nombre, nombre)
                     for nombre in ("node-a", "node-b", "node-c")}
        endpoints, pedir = self.red(registros)
        marker = self.raiz / ".bootstrap-pool-ausente"
        readiness = self.raiz / "pool-ready"
        parches = self.contexto(
            "node-a", registros["node-a"],
            [base for base, nombre in endpoints.items() if nombre != "node-a"],
            pedir)
        with parches[0], parches[1], parches[2], \
                mock.patch.multiple(
                    servidor,
                    MARCADOR_BOOTSTRAP_POOL=str(marker),
                    MARCADOR_LISTO=str(readiness)):
            with self.assertRaises(pool.ErrorRevisionPool) as error:
                servidor.reconciliar_pool(aplicar_configuracion=True)

        self.assertEqual("POOL_BOOTSTRAP_REQUIRED", error.exception.codigo)
        self.assertFalse(any(registro.existe() for registro in registros.values()))
        self.assertFalse(readiness.exists())

    def test_arranque_frio_reanuda_corte_tras_rename_causal_inicial(self):
        registros = {nombre: self.registro(nombre, nombre)
                     for nombre in ("node-a", "node-b", "node-c")}
        inicial = registros["node-a"].inicializar_desde_candidato(
            registros["node-a"].leer())
        self.assertEqual({"node-a": 1}, inicial["revision"]["clock"])
        self.assertFalse(registros["node-b"].existe())
        self.assertFalse(registros["node-c"].existe())
        endpoints, pedir = self.red(registros)
        parches = self.contexto(
            "node-a", registros["node-a"],
            [base for base, nombre in endpoints.items() if nombre != "node-a"],
            pedir)
        marker = crear_marker_bootstrap(self.raiz / ".bootstrap-pool")
        with parches[0], parches[1], parches[2], \
                mock.patch.object(
                    servidor, "MARCADOR_BOOTSTRAP_POOL", str(marker)):
            resultado = servidor.reconciliar_pool()

        self.assertEqual(3, resultado["propagacion"]["acknowledged"])
        self.assertEqual(1, len({
            pool.Pool.huella(registro.leer()) for registro in registros.values()
        }))
        self.assertFalse(marker.exists())

    def test_arranque_repara_intermedio_legacy_de_version_anterior(self):
        registros = {nombre: self.registro(nombre, nombre)
                     for nombre in ("node-a", "node-b", "node-c")}
        # Simula el antiguo primer rename (legacy materializado) y un corte
        # antes de que aquella versión avanzase el reloj.
        registros["node-a"].aplicar_replica(registros["node-a"].leer())
        self.assertEqual({}, registros["node-a"].leer()["revision"]["clock"])
        endpoints, pedir = self.red(registros)
        parches = self.contexto(
            "node-a", registros["node-a"],
            [base for base, nombre in endpoints.items() if nombre != "node-a"],
            pedir)
        marker = crear_marker_bootstrap(self.raiz / ".bootstrap-pool")
        with parches[0], parches[1], parches[2], \
                mock.patch.object(
                    servidor, "MARCADOR_BOOTSTRAP_POOL", str(marker)):
            resultado = servidor.reconciliar_pool()

        self.assertEqual({"node-a": 1}, resultado["snapshot"]["revision"]["clock"])
        self.assertEqual(3, resultado["propagacion"]["acknowledged"])
        self.assertFalse(marker.exists())

    def test_bootstrap_cinco_nodos_reanuda_dos_copias_por_debajo_de_quorum(self):
        nodos = [
            {"nombre": f"node-{letra}", "ip": f"192.0.2.{10 + indice}",
             "interfaz": "eth0", "prioridad": 150 - indice}
            for indice, letra in enumerate("abcde")
        ]
        registros = {
            nodo["nombre"]: self.registro(nodo["nombre"], nodo["nombre"])
            for nodo in nodos
        }
        inicial = registros["node-a"].inicializar_desde_candidato(
            registros["node-a"].leer())
        registros["node-b"].aplicar_replica(inicial)
        endpoints, pedir = self.red(registros)
        marker = crear_marker_bootstrap(self.raiz / ".bootstrap-pool")
        with mock.patch.multiple(
                servidor,
                POOL=registros["node-a"],
                PARES=[base for base, nombre in endpoints.items()
                       if nombre != "node-a"],
                PROTOCOLO=ProtocoloClaro(),
                _pedir_interno=pedir,
                MARCADOR_BOOTSTRAP_POOL=str(marker),
                MARCADOR_PROTOCOLO_V2=str(
                    self.raiz / ".cluster-protocol-v2"),
                _observaciones_protocolo_v2={"pool": None, "security": None}), \
                mock.patch.object(local, "NODOS", nodos), \
                mock.patch.object(local, "YO", "node-a"):
            resultado = servidor.reconciliar_pool()

        self.assertEqual(3, resultado["quorum"])
        self.assertEqual(5, resultado["propagacion"]["acknowledged"])
        self.assertEqual(1, len({
            pool.Pool.huella(registro.leer()) for registro in registros.values()
        }))
        self.assertFalse(marker.exists())

    def test_marker_no_autoriza_reanudar_una_revision_minoritaria_no_inicial(self):
        registros = {nombre: self.registro(nombre, nombre)
                     for nombre in ("node-a", "node-b", "node-c")}
        registros["node-a"].inicializar_desde_candidato(
            registros["node-a"].leer())
        mutado = registros["node-a"].leer()
        mutado["dhcp_desde"] = 120
        registros["node-a"].escribir(mutado, marcar_hora=False)
        endpoints, pedir = self.red(registros)
        parches = self.contexto(
            "node-a", registros["node-a"],
            [base for base, nombre in endpoints.items() if nombre != "node-a"],
            pedir)
        marker = crear_marker_bootstrap(self.raiz / ".bootstrap-pool")
        with parches[0], parches[1], parches[2], \
                mock.patch.object(
                    servidor, "MARCADOR_BOOTSTRAP_POOL", str(marker)):
            with self.assertRaises(pool.ErrorRevisionPool) as error:
                servidor.reconciliar_pool()

        self.assertEqual("POOL_QUORUM_UNAVAILABLE", error.exception.codigo)
        self.assertTrue(marker.exists())
        self.assertFalse(registros["node-b"].existe())

    def test_quorum_legacy_materializado_migra_sin_marker(self):
        legacy = pool._vacio()
        legacy.pop("revision")
        registros = {nombre: self.registro(nombre, nombre)
                     for nombre in ("node-a", "node-b", "node-c")}
        for registro in registros.values():
            registro.aplicar_replica(legacy)
        endpoints, pedir = self.red(registros)
        parches = self.contexto(
            "node-a", registros["node-a"],
            [base for base, nombre in endpoints.items() if nombre != "node-a"],
            pedir)
        with parches[0], parches[1], parches[2], \
                mock.patch.object(
                    servidor, "MARCADOR_BOOTSTRAP_POOL",
                    str(self.raiz / "inexistente")):
            resultado = servidor.reconciliar_pool()

        self.assertEqual(
            {"node-a": 1}, resultado["snapshot"]["revision"]["clock"])
        self.assertEqual(1, len({
            pool.Pool.huella(registro.leer()) for registro in registros.values()
        }))

    def test_dos_de_tres_forman_quorum_y_el_rejoin_converge(self):
        origen = self.registro("node-a", "node-a")
        base = origen.escribir(pool._vacio(), marcar_hora=False)
        atrasado = self.registro("node-b", "node-b")
        atrasado.aplicar_replica(base)
        aislado = self.registro("node-c", "node-c")
        aislado.aplicar_replica(base)
        nuevo = origen.leer()
        nuevo["dhcp_desde"] = 120
        origen.escribir(nuevo, marcar_hora=False)
        registros = {"node-a": origen, "node-c": aislado}
        endpoints, pedir = self.red(registros, caidos={"node-c"})
        parches = self.contexto(
            "node-b", atrasado, list(endpoints), pedir)
        aplicar = mock.Mock(return_value={"sin_cambios": False})
        with parches[0], parches[1], parches[2], \
                mock.patch.object(servidor, "aplicar", aplicar):
            resultado = servidor.reconciliar_pool(aplicar_configuracion=True)

        self.assertEqual(120, atrasado.leer()["dhcp_desde"])
        self.assertEqual(2, resultado["propagacion"]["acknowledged"])
        aplicar.assert_called_once()

    def test_nodo_reemplazado_sin_pool_recupera_dos_peers_identicos(self):
        origen = self.registro("node-a", "node-a")
        snapshot = origen.escribir(pool._vacio(), marcar_hora=False)
        snapshot["dhcp_desde"] = 120
        origen.escribir(snapshot, marcar_hora=False)
        peer = self.registro("node-c", "node-c")
        peer.aplicar_replica(origen.leer())
        reemplazo = self.registro("node-b", "node-b")
        self.assertFalse(reemplazo.existe())
        endpoints, pedir = self.red({"node-a": origen, "node-c": peer})
        parches = self.contexto(
            "node-b", reemplazo, list(endpoints), pedir)

        with parches[0], parches[1], parches[2], \
                mock.patch.object(
                    servidor, "aplicar", return_value={"sin_cambios": False}):
            resultado = servidor.reconciliar_pool(aplicar_configuracion=True)

        self.assertTrue(reemplazo.existe())
        self.assertEqual(120, reemplazo.leer()["dhcp_desde"])
        self.assertEqual(
            pool.Pool.huella(origen.leer()),
            pool.Pool.huella(reemplazo.leer()),
        )
        self.assertEqual(3, resultado["propagacion"]["acknowledged"])

    def test_rejoin_legacy_divergente_bloquea_sin_sobrescribir(self):
        escritor = self.registro("node-a", "node-a")
        origen_legacy = pool._vacio()
        origen_legacy.pop("revision")
        vector = escritor.escribir(origen_legacy, marcar_hora=False)
        peer_vector = self.registro("node-b", "node-b")
        peer_vector.aplicar_replica(vector)
        peer_legacy = self.registro("node-c", "node-c")
        divergente = pool._vacio()
        divergente.pop("revision")
        divergente["dhcp_desde"] = 120
        peer_legacy.aplicar_replica(divergente)
        huella_divergente = pool.Pool.huella(peer_legacy.leer())
        endpoints, transporte = self.red({
            "node-b": peer_vector, "node-c": peer_legacy})
        llamadas = []

        def pedir(base, ruta, datos=None, metodo=None, tiempo=None):
            llamadas.append((metodo or ("POST" if datos else "GET"), ruta))
            return transporte(base, ruta, datos, metodo, tiempo)

        parches = self.contexto(
            "node-a", escritor, list(endpoints), pedir)
        with parches[0], parches[1], parches[2]:
            with self.assertRaises(pool.ErrorRevisionPool) as error:
                servidor.reconciliar_pool()

        self.assertEqual("POOL_REPLICA_CONFLICT", error.exception.codigo)
        self.assertFalse(any(metodo == "POST" for metodo, _ in llamadas))
        self.assertEqual(
            huella_divergente, pool.Pool.huella(peer_legacy.leer()))

    def test_existe_no_materializa_y_json_duplicado_falla_cerrado(self):
        registro = self.registro("pool-ausente", "node-a")
        self.assertFalse(registro.existe())
        self.assertFalse(Path(registro.ruta).exists())
        registro.escribir(pool._vacio(), marcar_hora=False)
        self.assertTrue(registro.existe())

        for nombre, contenido in (
            ("duplicado-raiz", '{"version":1,"version":1}'),
            ("duplicado-anidado", '{"revision":{"schema":1,"schema":1}}'),
        ):
            with self.subTest(nombre=nombre):
                ruta = self.raiz / f"{nombre}.json"
                ruta.write_text(contenido, encoding="utf-8")
                corrupto = pool.Pool(str(ruta), autor="node-a")
                with self.assertRaises(pool.ErrorPool) as error:
                    corrupto.leer()
                self.assertIn("duplicada", str(error.exception))

    def test_identidad_duplicada_no_cuenta_dos_veces(self):
        registro = self.registro("local", "node-a")
        endpoints = ["http://peer-1:6060", "http://peer-2:6060"]

        def pedir(_base, _ruta, datos=None, metodo=None, tiempo=None):
            return {"payload": {
                "capability": servidor.CAPACIDAD_POOL_V2,
                "nodo": "node-b", "initialized": False,
                "snapshot": pool._vacio()}}

        parches = self.contexto("node-a", registro, endpoints, pedir)
        with parches[0], parches[1], parches[2]:
            consulta = servidor._consultar_snapshots_pool()
            with self.assertRaises(pool.ErrorRevisionPool) as error:
                servidor.reconciliar_pool()

        self.assertEqual(["node-a"], consulta["identidades"])
        self.assertEqual(["node-b"], consulta["duplicadas"])
        self.assertEqual("POOL_QUORUM_UNAVAILABLE", error.exception.codigo)

    def test_cohorte_v2_dos_de_tres_ignora_old_y_no_le_hace_post(self):
        local_a = self.registro("node-a", "node-a")
        snapshot = local_a.escribir(pool._vacio(), marcar_hora=False)
        peer_b = self.registro("node-b", "node-b")
        peer_b.aplicar_replica(snapshot)
        nuevo = "http://node-b:6060"
        antiguo = "http://node-c-old:6060"
        llamadas = []

        def pedir(base, ruta, datos=None, metodo=None, tiempo=None):
            metodo = metodo or ("POST" if datos is not None else "GET")
            llamadas.append((base, metodo, ruta))
            if base == antiguo:
                raise RuntimeError("404 old sin v2")
            if ruta == servidor.RUTA_POOL_V2:
                return {"payload": {
                    "capability": servidor.CAPACIDAD_POOL_V2,
                    "nodo": "node-b", "initialized": peer_b.existe(),
                    "snapshot": peer_b.leer(),
                }}
            if ruta == servidor.RUTA_REPLICA_POOL_V2:
                mensaje = datos["payload"]
                peer_b.aplicar_replica(mensaje["snapshot"])
                return {"payload": {
                    "capability": servidor.CAPACIDAD_POOL_V2,
                    "estado": "ok", "nodo": "node-b",
                    "huella": pool.Pool.huella(peer_b.leer()),
                }}
            raise AssertionError("un nodo nuevo no debe usar rutas legacy")

        parches = self.contexto(
            "node-a", local_a, [nuevo, antiguo], pedir)
        with parches[0], parches[1], parches[2], \
                mock.patch.object(servidor, "aplicar", return_value={"sin_cambios": True}):
            resultado = servidor.reconciliar_pool(aplicar_configuracion=True)

        self.assertEqual(2, resultado["propagacion"]["acknowledged"])
        self.assertEqual({"node-b": nuevo}, resultado["capacidades"])
        self.assertFalse(any(
            base == antiguo and metodo == "POST"
            for base, metodo, _ruta in llamadas))
        self.assertFalse(any(
            metodo == "POST" and ruta != servidor.RUTA_REPLICA_POOL_V2
            for _base, metodo, ruta in llamadas))

    def test_non_writer_falla_antes_de_reconciliar_mutar_o_aplicar(self):
        operacion = mock.Mock()
        reconciliar = mock.Mock()
        aplicar = mock.Mock()
        with mock.patch.object(local, "NODOS", NODOS), \
                mock.patch.object(local, "YO", "node-b"), \
                mock.patch.object(servidor, "_esta_listo", return_value=True), \
                mock.patch.object(servidor, "reconciliar_pool", reconciliar), \
                mock.patch.object(servidor, "aplicar", aplicar):
            with self.assertRaises(pool.ErrorRevisionPool) as error:
                servidor._ejecutar_mutacion(operacion)

        self.assertEqual("POOL_WRITER_REQUIRED", error.exception.codigo)
        reconciliar.assert_not_called()
        operacion.assert_not_called()
        aplicar.assert_not_called()

    def test_vip_runtime_invalida_no_toca_bytes_ni_revision_local(self):
        registro = self.registro("node-a", "node-a")
        base = registro.escribir(pool._vacio(), marcar_hora=False)
        antes = Path(registro.ruta).read_bytes()
        revision = dict(base["revision"])
        reconciliacion = {
            "snapshot": registro.leer(), "capacidades": {
                "node-b": "http://node-b:6060",
                "node-c": "http://node-c:6060",
            },
            "identidades": ["node-a", "node-b"], "quorum": 2,
        }
        with mock.patch.object(local, "NODOS", NODOS), \
                mock.patch.object(local, "YO", "node-a"), \
                mock.patch.object(servidor, "POOL", registro), \
                mock.patch.object(servidor, "_esta_listo", return_value=True), \
                mock.patch.object(
                    servidor, "reconciliar_pool", return_value=reconciliacion):
            with self.assertRaises(pool.ErrorPool):
                servidor._ejecutar_mutacion(lambda: registro.alta({
                    "ip": "192.0.2.10", "vrid": 42,
                }))

        self.assertEqual(antes, Path(registro.ruta).read_bytes())
        self.assertEqual(revision, registro.leer()["revision"])

    def test_vip_runtime_rechaza_no_host_gestion_y_prefijo_no_24(self):
        invalidas = (
            "0.0.0.0", "127.0.0.1", "169.254.1.2", "224.0.0.1",
            "240.0.0.1", "192.0.2.0", "192.0.2.255", "192.0.2.10",
        )
        with mock.patch.object(local, "NODOS", NODOS):
            for direccion in invalidas:
                with self.subTest(direccion=direccion), \
                        self.assertRaises(pool.ErrorPool):
                    servidor._validar_vip_runtime(direccion)
            self.assertEqual(
                "192.0.2.100", servidor._validar_vip_runtime("192.0.2.100"))

        with mock.patch.dict(os.environ, {"FIP_VIP_PREFIX": "23"}):
            with self.assertRaisesRegex(ValueError, "debe ser 24"):
                servidor.plan._vip_prefijo()

    def test_mutaciones_concurrentes_del_writer_se_serializan_extremo_a_extremo(self):
        snapshot = self.registro("node-a", "node-a").escribir(
            pool._vacio(), marcar_hora=False)
        estado = {"activas": 0, "maximas": 0}
        candado = threading.Lock()
        errores = []

        def operacion():
            with candado:
                estado["activas"] += 1
                estado["maximas"] = max(estado["maximas"], estado["activas"])
            time.sleep(0.05)
            with candado:
                estado["activas"] -= 1
            return snapshot

        def ejecutar():
            try:
                servidor._ejecutar_mutacion(operacion)
            except Exception as error:  # noqa: BLE001
                errores.append(error)

        with mock.patch.object(local, "NODOS", NODOS), \
                mock.patch.object(local, "YO", "node-a"), \
                mock.patch.object(servidor, "_esta_listo", return_value=True), \
                mock.patch.object(servidor, "reconciliar_pool", return_value={
                    "capacidades": {
                        "node-b": "http://node-b:6060",
                        "node-c": "http://node-c:6060",
                    }}), \
                mock.patch.object(servidor, "aplicar_y_propagar", return_value={}):
            hilos = [threading.Thread(target=ejecutar) for _ in range(2)]
            for hilo in hilos:
                hilo.start()
            for hilo in hilos:
                hilo.join(timeout=5)

        self.assertEqual([], errores)
        self.assertEqual(1, estado["maximas"])

    def test_mixed_version_congela_mutacion_externa_sin_tocar_pool(self):
        operacion = mock.Mock()
        with mock.patch.multiple(
                servidor,
                MARCADOR_PROTOCOLO_V2=str(
                    self.raiz / ".cluster-protocol-v2"),
                _observaciones_protocolo_v2={"pool": None, "security": None}), \
                mock.patch.object(local, "NODOS", NODOS), \
                mock.patch.object(local, "YO", "node-a"), \
                mock.patch.object(servidor, "_esta_listo", return_value=True), \
                mock.patch.object(servidor, "reconciliar_pool", return_value={
                    "capacidades": {"node-b": "http://node-b:6060"}}):
            with self.assertRaises(pool.ErrorRevisionPool) as error:
                servidor._ejecutar_mutacion(operacion)

        self.assertEqual(
            "CLUSTER_UPGRADE_IN_PROGRESS", error.exception.codigo)
        operacion.assert_not_called()

    def test_evidencia_v2_durable_permite_quorum_con_un_peer_caido(self):
        marker = self.raiz / ".cluster-protocol-v2"
        capacidades = {
            "node-b": "http://node-b:6060",
            "node-c": "http://node-c:6060",
        }
        operacion = mock.Mock(return_value=pool._vacio())
        with mock.patch.multiple(
                servidor,
                MARCADOR_PROTOCOLO_V2=str(marker),
                _observaciones_protocolo_v2={"pool": None, "security": None}), \
                mock.patch.object(local, "NODOS", NODOS), \
                mock.patch.object(local, "YO", "node-a"), \
                mock.patch.object(servidor, "_esta_listo", return_value=True), \
                mock.patch.object(servidor, "reconciliar_pool", return_value={
                    # node-c está temporalmente caído, pero ya pertenecía a la
                    # cohorte v2 sellada cuando los tres respondieron.
                    "capacidades": {"node-b": "http://node-b:6060"}}), \
                mock.patch.object(
                    servidor, "aplicar_y_propagar", return_value={"ok": True}):
            self.assertFalse(
                servidor._observar_protocolo_v2("pool", capacidades))
            self.assertTrue(
                servidor._observar_protocolo_v2("security", capacidades))
            self.assertTrue(marker.exists())
            self.assertEqual(0o600, stat.S_IMODE(marker.stat().st_mode))
            servidor._ejecutar_mutacion(operacion)

        operacion.assert_called_once()

    def test_marker_v2_inseguro_bloquea_mutacion_aunque_haya_n_sobre_n(self):
        capacidades = {
            "node-b": "http://node-b:6060",
            "node-c": "http://node-c:6060",
        }
        for clase in ("contenido", "symlink"):
            with self.subTest(clase=clase):
                raiz = self.raiz / clase
                raiz.mkdir(mode=0o700)
                marker = raiz / ".cluster-protocol-v2"
                if clase == "contenido":
                    marker.write_text("otra-cohorte\n", encoding="utf-8")
                    marker.chmod(0o600)
                else:
                    destino = raiz / "destino"
                    destino.write_bytes(servidor._contenido_marker_protocolo_v2())
                    destino.chmod(0o600)
                    marker.symlink_to(destino)
                with mock.patch.multiple(
                        servidor,
                        MARCADOR_PROTOCOLO_V2=str(marker),
                        _observaciones_protocolo_v2={
                            "pool": None, "security": None}), \
                        mock.patch.object(local, "NODOS", NODOS), \
                        mock.patch.object(local, "YO", "node-a"):
                    with self.assertRaises(pool.ErrorRevisionPool) as error:
                        servidor._exigir_cluster_v2_pool(capacidades)
                self.assertEqual(
                    "CLUSTER_PROTOCOL_MARKER_INVALID", error.exception.codigo)

    def test_sin_quorum_no_muta_ni_aplica_configuracion(self):
        operacion = mock.Mock()
        aplicar = mock.Mock()
        fallo = pool.ErrorRevisionPool("sin quorum", "POOL_QUORUM_UNAVAILABLE")
        with mock.patch.object(servidor, "_esta_listo", return_value=True), \
                mock.patch.object(servidor, "reconciliar_pool", side_effect=fallo), \
                mock.patch.object(servidor, "aplicar", aplicar), \
                mock.patch.object(local, "NODOS", NODOS), \
                mock.patch.object(local, "YO", "node-a"):
            with self.assertRaises(pool.ErrorRevisionPool) as error:
                servidor._ejecutar_mutacion(operacion)

        self.assertEqual("POOL_QUORUM_UNAVAILABLE", error.exception.codigo)
        operacion.assert_not_called()
        aplicar.assert_not_called()

    def test_quorum_perdido_tras_escribir_es_resultado_incierto_y_no_aplica(self):
        registro = self.registro("node-a", "node-a")
        snapshot = registro.escribir(pool._vacio(), marcar_hora=False)
        fallo = pool.ErrorRevisionPool("sin quorum", "POOL_QUORUM_UNAVAILABLE")
        aplicar = mock.Mock()
        with mock.patch.object(servidor, "POOL", registro), \
                mock.patch.object(servidor, "_esta_listo", return_value=True), \
                mock.patch.object(servidor, "reconciliar_pool", return_value={
                    "capacidades": {
                        "node-b": "http://node-b:6060",
                        "node-c": "http://node-c:6060",
                    }}), \
                mock.patch.object(servidor, "_propagar", side_effect=fallo), \
                mock.patch.object(servidor, "aplicar", aplicar), \
                mock.patch.object(local, "NODOS", NODOS), \
                mock.patch.object(local, "YO", "node-a"):
            with self.assertRaises(pool.ErrorRevisionPool) as error:
                servidor._ejecutar_mutacion(lambda: snapshot)

        self.assertEqual("POOL_COMMIT_UNCERTAIN", error.exception.codigo)
        aplicar.assert_not_called()

    def test_claim_activa_bloquea_edicion_y_segunda_asignacion(self):
        registro = self.registro("claims", "node-a")
        registro.escribir(pool._vacio(), marcar_hora=False)
        registro.alta({
            "ip": "192.0.2.10", "vrid": 10, "estado": "libre",
        })
        peticion = {
            "servicio": "app-a", "descripcion": "Aplicación",
            "puertos": [8080],
            "chequeo": {"puerto": 8080, "ruta": "/health"},
        }
        registro.reclamar(peticion, "claim:k1-activa")
        with self.assertRaisesRegex(pool.ErrorPool, "reclamación activa"):
            registro.modificar("192.0.2.10", {"estado": "libre"})
        with self.assertRaisesRegex(pool.ErrorPool, "ya usa"):
            registro.reclamar(peticion, "claim:k2-activa")
        actual = registro.leer()
        self.assertNotIn("claim:k2-activa", actual["reclamaciones"])
        self.assertEqual("en_uso", registro.buscar(actual, "192.0.2.10")["estado"])

    def test_tombstones_de_claim_rotan_sin_agotar_el_pool_de_por_vida(self):
        registro = self.registro("tombstones", "node-a")
        registro.escribir(pool._vacio(), marcar_hora=False)
        registro.alta({
            "ip": "192.0.2.10", "vrid": 10, "estado": "libre",
        })
        datos = registro.leer()
        datos["reclamaciones"] = {
            f"claim:old:{indice:04d}": {
                "ip": "192.0.2.99", "servicio": "retirado",
                "estado": "liberada",
                "creada": "2026-01-01T00:00:00+00:00",
                "liberada": f"2026-01-{1 + indice // 100:02d}T00:00:00+00:00",
                "reserva_anterior": {
                    "estado": "reservada", "servicio": "retirado",
                    "descripcion": "d" * pool._MAX_DESCRIPCION,
                    "notas": "n" * pool._MAX_NOTAS,
                    "preferente": None,
                },
            }
            for indice in range(pool._MAX_TOMBSTONES_RECLAMACION + 1)
        }
        registro.escribir(datos, marcar_hora=False)
        peticion = {
            "servicio": "app-nueva", "descripcion": "Aplicación",
            "puertos": [8080],
            "chequeo": {"puerto": 8080, "ruta": "/health"},
        }
        actualizado, _direccion, repetida = registro.reclamar(
            peticion, "claim:nueva-activa")

        self.assertFalse(repetida)
        tombstones = [
            valor for valor in actualizado["reclamaciones"].values()
            if valor["estado"] == "liberada"
        ]
        self.assertEqual(pool._MAX_TOMBSTONES_RECLAMACION, len(tombstones))
        self.assertEqual(
            "activa",
            actualizado["reclamaciones"]["claim:nueva-activa"]["estado"],
        )
        self.assertLessEqual(
            len(pool._json_canonico(actualizado)), pool._MAX_SNAPSHOT_BYTES)

    def test_invariantes_semanticas_claim_y_compatibilidad_legacy_explicita(self):
        registro = self.registro("claims-semantica", "node-a")
        registro.escribir(pool._vacio(), marcar_hora=False)
        registro.alta({
            "ip": "192.0.2.10", "vrid": 10, "estado": "libre",
        })
        peticion = {
            "servicio": "app-a", "descripcion": "Aplicación",
            "puertos": [8080],
            "chequeo": {"puerto": 8080, "ruta": "/health"},
        }
        activo, _direccion, _repetida = registro.reclamar(
            peticion, "claim:semantica-1")
        self.assertEqual([], pool.validar(activo))

        duplicado = deepcopy(activo)
        duplicado["reclamaciones"]["claim:semantica-2"] = deepcopy(
            duplicado["reclamaciones"]["claim:semantica-1"])
        errores = pool.validar(duplicado)
        self.assertTrue(any("IP" in error and "ya está activa" in error
                            for error in errores))
        self.assertTrue(any("servicio" in error and "ya está activo" in error
                            for error in errores))

        for nombre, mutar, fragmento in (
            ("direccion libre", lambda datos: datos["direcciones"][0].update(
                {"estado": "libre", "servicio": None, "chequeo": None,
                 "puertos": []}), "existente, en_uso"),
            ("huella", lambda datos: datos["reclamaciones"]
             ["claim:semantica-1"].update({"huella": "0" * 64}),
             "huella no corresponde"),
            ("activa liberada", lambda datos: datos["reclamaciones"]
             ["claim:semantica-1"].update({
                 "liberada": "2026-01-01T00:00:00+00:00"}),
             "activa no puede tener liberada"),
            ("reserva en uso", lambda datos: datos["reclamaciones"]
             ["claim:semantica-1"]["reserva_anterior"].update(
                 {"estado": "en_uso"}), "libre o reservada"),
        ):
            with self.subTest(nombre=nombre):
                invalido = deepcopy(activo)
                mutar(invalido)
                self.assertTrue(any(
                    fragmento in error for error in pool.validar(invalido)))

        liberado, _ip, _repetida = registro.liberar_reclamacion(
            "claim:semantica-1")
        tombstone = liberado["reclamaciones"]["claim:semantica-1"]
        self.assertNotIn("reserva_anterior", tombstone)
        self.assertEqual([], pool.validar(liberado))
        sin_timestamp = deepcopy(liberado)
        sin_timestamp["reclamaciones"]["claim:semantica-1"].pop("liberada")
        self.assertTrue(any(
            "exige timestamp" in error for error in pool.validar(sin_timestamp)))

        # Ausencia de `schema` identifica explícitamente el formato heredado:
        # se siguen aceptando tombstones antiguos con reserva_anterior para
        # poder leer y migrar instalaciones existentes.
        legacy = deepcopy(liberado)
        claim_legacy = legacy["reclamaciones"]["claim:semantica-1"]
        claim_legacy.pop("schema")
        claim_legacy["reserva_anterior"] = deepcopy(
            activo["reclamaciones"]["claim:semantica-1"]["reserva_anterior"])
        self.assertEqual([], pool.validar(legacy))

    def test_marcador_se_publica_completo_y_con_identidad(self):
        registro = self.registro("node-a", "node-a")
        snapshot = registro.escribir(pool._vacio(), marcar_hora=False)
        marcador = self.raiz / "run" / "pool-ready"
        with mock.patch.object(servidor, "MARCADOR_LISTO", str(marcador)), \
                mock.patch.object(local, "YO", "node-a"):
            servidor._publicar_marcador_listo(snapshot)
        contenido = json.loads(marcador.read_text(encoding="utf-8"))
        self.assertEqual("node-a", contenido["nodo"])
        self.assertEqual(pool.Pool.huella(snapshot), contenido["huella"])
        self.assertEqual([], list(marcador.parent.glob("*.ready.tmp")))

    def test_worker_sigue_reconciliando_despues_de_readiness(self):
        snapshot = self.registro("node-a", "node-a").escribir(
            pool._vacio(), marcar_hora=False)

        class DosVueltas:
            def __init__(self):
                self.esperas = 0

            def is_set(self):
                return self.esperas >= 2

            def wait(self, _segundos):
                self.esperas += 1
                return False

        detener = DosVueltas()
        reconciliar = mock.Mock(return_value={
            "snapshot": snapshot,
            "aplicado": {"sin_cambios": True},
            "quorum": 2,
            "identidades": ["node-a", "node-b"],
        })
        reconciliar_acceso = mock.Mock(return_value={
            "quorum": 2, "identidades": ["node-a", "node-b"]})
        publicar = mock.Mock()
        with mock.patch.object(servidor, "_esta_listo", return_value=False), \
                mock.patch.object(servidor, "reconciliar_pool", reconciliar), \
                mock.patch.object(
                    servidor, "reconciliar_seguridad", reconciliar_acceso), \
                mock.patch.object(servidor, "_publicar_marcador_listo", publicar):
            servidor._trabajador_arranque(detener)

        self.assertEqual(2, reconciliar.call_count)
        self.assertEqual(2, reconciliar_acceso.call_count)
        publicar.assert_called_once_with(snapshot)

    def test_worker_retira_readiness_degradada_y_la_restaura_al_converger(self):
        snapshot = self.registro("node-a", "node-a").escribir(
            pool._vacio(), marcar_hora=False)

        class DosVueltas:
            def __init__(self):
                self.esperas = 0

            def is_set(self):
                return self.esperas >= 2

            def wait(self, _segundos):
                self.esperas += 1
                return False

        fallo = pool.ErrorRevisionPool(
            "sin quorum", "POOL_QUORUM_UNAVAILABLE")
        exito = {
            "snapshot": snapshot, "aplicado": {"sin_cambios": True},
            "quorum": 2, "identidades": ["node-a", "node-b"],
        }
        acceso = {"quorum": 2, "identidades": ["node-a", "node-b"]}
        with mock.patch.object(servidor, "_esta_listo", return_value=True), \
                mock.patch.object(
                    servidor, "reconciliar_pool", side_effect=[fallo, exito]), \
                mock.patch.object(
                    servidor, "reconciliar_seguridad", return_value=acceso), \
                mock.patch.object(
                    servidor, "_degradar_readiness_pool") as degradar, \
                mock.patch.object(
                    servidor, "_publicar_marcador_listo") as publicar:
            servidor._trabajador_arranque(DosVueltas())

        degradar.assert_called_once_with(detener_keepalived=False)
        publicar.assert_called_once_with(snapshot)

    def test_readiness_depende_del_pool_y_seguridad_degradada_no_apaga_vip(self):
        snapshot = self.registro("node-a", "node-a").escribir(
            pool._vacio(), marcar_hora=False)

        class UnaVuelta:
            def __init__(self):
                self.terminado = False

            def is_set(self):
                return self.terminado

            def wait(self, _segundos):
                self.terminado = True
                return False

        publicar = mock.Mock()
        fallo = seguridad.ErrorAcceso(
            "sin quorum", "AUTH_QUORUM_UNAVAILABLE", 503)
        with mock.patch.object(servidor, "_esta_listo", return_value=False), \
                mock.patch.object(servidor, "reconciliar_pool", return_value={
                    "snapshot": snapshot,
                    "aplicado": {"sin_cambios": True},
                    "quorum": 2,
                    "identidades": ["node-a", "node-b"],
                }), \
                mock.patch.object(
                    servidor, "reconciliar_seguridad", side_effect=fallo), \
                mock.patch.object(servidor, "_publicar_marcador_listo", publicar):
            servidor._trabajador_arranque(UnaVuelta())

        publicar.assert_called_once_with(snapshot)

    def test_entrypoint_espera_marcador_antes_de_keepalived(self):
        candidato = Path(__file__).resolve().parents[1] / "entrypoint.sh"
        ruta = candidato if candidato.exists() else Path("/usr/local/bin/entrypoint")
        texto = ruta.read_text(encoding="utf-8")
        espera = texto.index('while [ ! -f "$LISTO" ]')
        arranque = texto.index("keepalived --dont-fork")
        self.assertLess(espera, arranque)
        self.assertIn('kill -0 "$PANEL"', texto[espera:arranque])
        self.assertIn('rm -f "$LISTO"', texto[:espera])

    def test_entrypoint_real_no_arranca_keepalived_sin_readiness(self):
        if not Path("/bin/sh").exists():
            self.skipTest("requiere un entorno POSIX")
        candidato = Path(__file__).resolve().parents[1] / "entrypoint.sh"
        ruta = candidato if candidato.exists() else Path("/usr/local/bin/entrypoint")
        binarios = self.raiz / "bin"
        binarios.mkdir()
        panel = binarios / "python3"
        panel.write_text(
            "#!/bin/sh\n"
            "case \"${1:-}\" in *bootstrap.py) exit 0;; esac\n"
            "echo panel >> \"$FIP_TEST_EVENTS\"\n"
            "if [ \"${FIP_TEST_READY:-0}\" = 1 ]; then\n"
            "  (sleep 0.2; : > \"$FIP_READY_MARKER\") &\n"
            "fi\n"
            "trap 'exit 0' TERM INT\n"
            "while :; do sleep 1; done\n",
            encoding="utf-8",
        )
        keepalived = binarios / "keepalived"
        keepalived.write_text(
            "#!/bin/sh\n"
            "echo keepalived >> \"$FIP_TEST_EVENTS\"\n"
            "trap 'exit 0' TERM INT\n"
            "while :; do sleep 1; done\n",
            encoding="utf-8",
        )
        panel.chmod(0o755)
        keepalived.chmod(0o755)
        dormir = binarios / "sleep"
        dormir.write_text("#!/bin/sh\n/bin/sleep 0.05\n", encoding="utf-8")
        dormir.chmod(0o755)
        eventos = self.raiz / "events"
        marcador = self.raiz / "run" / "ready"
        entorno = dict(os.environ)
        entorno.update({
            "PATH": f"{binarios}:/usr/bin:/bin",
            "FIP_DRENAR": str(self.raiz / "run" / "drain"),
            "FIP_READY_MARKER": str(marcador),
            "FIP_TEST_EVENTS": str(eventos),
        })

        def lanzar(listo):
            actual = dict(entorno)
            actual["FIP_TEST_READY"] = "1" if listo else "0"
            return subprocess.Popen(
                ["/bin/sh", str(ruta)], env=actual,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                text=True)

        aislado = lanzar(False)
        try:
            time.sleep(0.25)
            self.assertIsNone(aislado.poll())
            self.assertEqual(["panel"], eventos.read_text().splitlines())
        finally:
            aislado.terminate()
            aislado.wait(timeout=5)

        eventos.unlink()
        preparado = lanzar(True)
        try:
            limite = time.monotonic() + 4
            lineas = []
            while time.monotonic() < limite:
                lineas = eventos.read_text().splitlines() if eventos.exists() else []
                if "keepalived" in lineas:
                    break
                time.sleep(0.1)
            self.assertEqual(["panel", "keepalived"], lineas)
            self.assertTrue(marcador.is_file())
        finally:
            preparado.terminate()
            preparado.wait(timeout=5)

    def test_status_autenticado_expone_readiness_sin_cambiar_health(self):
        with mock.patch.object(servidor.AUTH_HTTP, "manejar", return_value=False), \
                mock.patch.object(servidor.AUTH_HTTP, "exigir"), \
                mock.patch.object(servidor, "_esta_listo", return_value=True), \
                mock.patch.object(local, "NODOS", NODOS), \
                mock.patch.object(local, "YO", "node-a"):
            httpd = servidor.Servidor(("127.0.0.1", 0), servidor.Manejador)
            worker = threading.Thread(target=httpd.serve_forever, daemon=True)
            worker.start()
            try:
                base_url = f"http://127.0.0.1:{httpd.server_port}"
                with urllib.request.urlopen(
                        base_url + "/api/status", timeout=5) as respuesta:
                    estado = json.loads(respuesta.read())
                with urllib.request.urlopen(
                        base_url + "/api/health", timeout=5) as respuesta:
                    salud = json.loads(respuesta.read())
            finally:
                httpd.shutdown()
                httpd.server_close()
                worker.join(timeout=5)

        self.assertTrue(estado["pool_ready"])
        self.assertEqual("node-a", estado["pool_writer"])
        self.assertTrue(estado["pool_writable"])
        self.assertIn("pool_apply_pending", estado)
        self.assertIn("pool_apply_error", estado)
        self.assertNotIn("pool_ready", salud)

    def test_marker_bootstrap_no_puede_salir_de_datos_ni_cambiar_nombre(self):
        datos = self.raiz / "datos"
        with mock.patch.object(servidor, "DIR_DATOS", str(datos)):
            servidor._validar_ruta_marker(
                str(datos / ".bootstrap-pool"), ".bootstrap-pool", "POOL")
            for ruta in (
                    self.raiz / ".bootstrap-pool",
                    datos / "otro-marker",
                    datos / "sub" / ".bootstrap-pool"):
                with self.subTest(ruta=ruta), self.assertRaises(RuntimeError):
                    servidor._validar_ruta_marker(
                        str(ruta), ".bootstrap-pool", "POOL")

    def test_deploy_freeze_bloquea_mutaciones_externas_y_no_replicas(self):
        marker = crear_marker_freeze(self.raiz / ".deploy-freeze")
        mutantes = (
            ("POST", "/api/auth/session"),
            ("POST", "/api/users"),
            ("POST", "/api/claims"),
            ("POST", "/api/pool"),
            ("POST", "/api/mantenimiento"),
            ("PUT", "/api/pool/192.0.2.10/servidor"),
            ("PATCH", "/api/pool/192.0.2.10"),
            ("DELETE", "/api/claims/claim:12345678"),
            ("DELETE", "/api/pool/192.0.2.10"),
        )
        permitidas = (
            ("GET", "/api/pool"),
            ("GET", "/api/auth/session"),
            ("DELETE", "/api/auth/session"),
            ("POST", servidor.RUTA_REPLICA_POOL_V2),
            ("POST", servidor.RUTA_REPLICA_SEGURIDAD_V2),
        )
        with mock.patch.object(
                servidor, "MARCADOR_DEPLOY_FREEZE", str(marker)), \
                mock.patch.object(local, "NODOS", NODOS), \
                mock.patch.object(local, "YO", "node-a"):
            for metodo, ruta in mutantes:
                with self.subTest(metodo=metodo, ruta=ruta), \
                        self.assertRaises(pool.ErrorRevisionPool) as error:
                    servidor._exigir_mutacion_no_congelada(metodo, ruta)
                self.assertEqual("DEPLOY_FROZEN", error.exception.codigo)
            for metodo, ruta in permitidas:
                with self.subTest(metodo=metodo, ruta=ruta):
                    servidor._exigir_mutacion_no_congelada(metodo, ruta)
            operacion = mock.Mock()
            with self.assertRaises(pool.ErrorRevisionPool) as error_pool:
                servidor._ejecutar_mutacion(operacion)
            self.assertEqual("DEPLOY_FROZEN", error_pool.exception.codigo)
            operacion.assert_not_called()
            reconciliar = mock.Mock()
            with mock.patch.object(
                    servidor, "reconciliar_seguridad", reconciliar):
                with self.assertRaises(seguridad.ErrorAcceso) as error_auth:
                    servidor.preflight_mutacion_seguridad()
            self.assertEqual("DEPLOY_FROZEN", error_auth.exception.codigo)
            self.assertEqual(503, error_auth.exception.http)
            reconciliar.assert_not_called()

            manejador = object.__new__(servidor.Manejador)
            manejador._error = mock.Mock()
            manejador._error_pool(error_pool.exception)
            self.assertEqual(503, manejador._error.call_args.args[1])

    @unittest.skipUnless(os.name == "posix", "protecciones marker POSIX")
    def test_deploy_freeze_inseguro_falla_cerrado(self):
        for clase in ("contenido", "modo", "symlink"):
            with self.subTest(clase=clase):
                raiz = self.raiz / f"freeze-{clase}"
                raiz.mkdir()
                marker = raiz / ".deploy-freeze"
                if clase == "contenido":
                    marker.write_bytes(b"freeze ambiguo\n")
                    marker.chmod(0o600)
                elif clase == "modo":
                    marker.write_bytes(servidor.CONTENIDO_DEPLOY_FREEZE)
                    marker.chmod(0o644)
                else:
                    destino = raiz / "destino"
                    destino.write_bytes(servidor.CONTENIDO_DEPLOY_FREEZE)
                    destino.chmod(0o600)
                    marker.symlink_to(destino)
                with mock.patch.object(
                        servidor, "MARCADOR_DEPLOY_FREEZE", str(marker)):
                    with self.assertRaises(pool.ErrorRevisionPool) as error:
                        servidor._exigir_mutacion_no_congelada(
                            "POST", "/api/pool")
                self.assertEqual(
                    "DEPLOY_FREEZE_INVALID", error.exception.codigo)

    def test_json_http_rechaza_duplicados_nan_y_raiz_no_objeto(self):
        casos = (
            b'{"nodo":"node-a","nodo":"node-b"}',
            b'{"anidado":{"x":1,"x":2}}',
            b'{"valor":NaN}',
            b'{"valor":Infinity}',
            b'[1,2,3]',
        )
        for cuerpo in casos:
            with self.subTest(cuerpo=cuerpo):
                manejador = object.__new__(servidor.Manejador)
                manejador._cuerpo_cache = cuerpo
                with self.assertRaises(pool.ErrorPool):
                    manejador._cuerpo()

        manejador = object.__new__(servidor.Manejador)
        manejador._cuerpo_cache = b'{"objeto":{"x":1}}'
        self.assertEqual(
            {"objeto": {"x": 1}}, manejador._cuerpo())

    def test_keep_alive_no_reutiliza_el_cuerpo_de_la_peticion_anterior(self):
        recibidos = []

        class Eco(servidor.Manejador):
            def do_POST(self):
                recibidos.append(self._cuerpo())
                self._json({"numero": recibidos[-1]["numero"]})

        httpd = servidor.Servidor(("127.0.0.1", 0), Eco)
        worker = threading.Thread(target=httpd.serve_forever, daemon=True)
        worker.start()
        conexion = http.client.HTTPConnection(
            "127.0.0.1", httpd.server_port, timeout=5)
        try:
            for numero in (1, 2):
                cuerpo = json.dumps({"numero": numero}).encode("utf-8")
                conexion.request(
                    "POST", "/eco", body=cuerpo,
                    headers={"Content-Type": "application/json"})
                respuesta = conexion.getresponse()
                self.assertEqual(200, respuesta.status)
                self.assertEqual(numero, json.loads(respuesta.read())["numero"])
            self.assertEqual([{"numero": 1}, {"numero": 2}], recibidos)
        finally:
            conexion.close()
            httpd.shutdown()
            httpd.server_close()
            worker.join(timeout=5)

    def test_respuesta_interna_acota_longitud_stream_y_json(self):
        demasiado = RespuestaInternaFalsa(
            b"{}", content_length=servidor.MAX_CUERPO + 1)
        with mock.patch.object(servidor, "PROTOCOLO", ProtocoloClaro()), \
                mock.patch.object(
                    servidor.urllib.request, "urlopen", return_value=demasiado):
            with self.assertRaisesRegex(ValueError, "supera"):
                servidor._pedir_interno("http://node-b:6060", "/v2")
        self.assertEqual(0, demasiado.lecturas)

        class CabecerasDuplicadas:
            @staticmethod
            def get_all(_nombre):
                return ["2", "2"]

        duplicada = RespuestaInternaFalsa(b"{}")
        duplicada.headers = CabecerasDuplicadas()
        with self.assertRaisesRegex(ValueError, "varios Content-Length"):
            servidor._leer_respuesta_interna(duplicada, 1)
        self.assertEqual(0, duplicada.lecturas)

        streaming = RespuestaInternaFalsa(
            b"x" * (servidor.MAX_CUERPO + 1), trozo=8192)
        with mock.patch.object(servidor, "PROTOCOLO", ProtocoloClaro()), \
                mock.patch.object(
                    servidor.urllib.request, "urlopen", return_value=streaming):
            with self.assertRaisesRegex(ValueError, "supera"):
                servidor._pedir_interno("http://node-b:6060", "/v2")

        for cuerpo in (
                b'{"x":1,"x":2}', b'{"x":{"y":1,"y":2}}',
                b'{"x":NaN}', b"[]"):
            with self.subTest(cuerpo=cuerpo):
                respuesta = RespuestaInternaFalsa(
                    cuerpo, content_length=len(cuerpo))
                with mock.patch.object(
                        servidor, "PROTOCOLO", ProtocoloClaro()), \
                        mock.patch.object(
                            servidor.urllib.request, "urlopen",
                            return_value=respuesta):
                    with self.assertRaises(ValueError):
                        servidor._pedir_interno(
                            "http://node-b:6060", "/v2")

    def test_respuesta_interna_aplica_plazo_total_al_cuerpo_lento(self):
        respuesta = RespuestaInternaFalsa(b"{}", trozo=1)
        with mock.patch.object(servidor, "PROTOCOLO", ProtocoloClaro()), \
                mock.patch.object(
                    servidor.urllib.request, "urlopen", return_value=respuesta), \
                mock.patch.object(
                    servidor.time, "monotonic", side_effect=(0.0, 0.1, 1.1)):
            with self.assertRaises(TimeoutError):
                servidor._pedir_interno(
                    "http://node-b:6060", "/v2", tiempo=1)

    def test_vista_local_acota_checks_colgados_y_presupuesto_total(self):
        liberar = threading.Event()
        candado = threading.Lock()
        estado = {"activos": 0, "maximo": 0, "llamadas": 0}

        def colgado(_chequeo):
            with candado:
                estado["activos"] += 1
                estado["llamadas"] += 1
                estado["maximo"] = max(estado["maximo"], estado["activos"])
            liberar.wait(2)
            with candado:
                estado["activos"] -= 1
            return {"sano": False, "detalle": "Timeout", "respuesta_ms": 2000}

        datos = pool._vacio()
        datos["direcciones"] = [
            {
                "ip": f"192.0.2.{indice + 20}", "estado": "en_uso",
                "servicio": f"service-{indice}",
                "chequeo": {"puerto": 20000 + indice, "ruta": "/health"},
            }
            for indice in range(pool._MAX_DIRECCIONES)
        ]
        with local._candado_salud:
            local._cache_salud.clear()
            local._futuros_salud.clear()
        inicio = time.monotonic()
        try:
            with mock.patch.object(local, "PRESUPUESTO_VISTA", 0.1), \
                    mock.patch.object(local, "comprobar", side_effect=colgado), \
                    mock.patch.object(
                        local, "direcciones_del_sistema", return_value={}), \
                    mock.patch.object(local, "drenando", return_value=False), \
                    mock.patch.object(local, "drenajes", return_value=[]), \
                    mock.patch.object(local, "NODOS", [NODOS[0]]), \
                    mock.patch.object(local, "YO", "node-a"):
                vista = local.vista_local(datos)
            duracion = time.monotonic() - inicio
            self.assertLess(duracion, 0.6)
            self.assertLessEqual(estado["maximo"], local.TRABAJADORES_SALUD)
            self.assertLessEqual(estado["llamadas"], local.TRABAJADORES_SALUD)
            self.assertEqual(pool._MAX_DIRECCIONES, len(vista["servicios"]))
            self.assertTrue(all(
                valor["detalle"] == "presupuesto de salud agotado"
                for valor in vista["servicios"].values()))
        finally:
            liberar.set()
            limite = time.monotonic() + 3
            while time.monotonic() < limite:
                with local._candado_salud:
                    if not local._futuros_salud:
                        local._cache_salud.clear()
                        break
                time.sleep(0.02)

    def test_http_rechaza_content_length_duplicado_en_frontera(self):
        httpd = servidor.Servidor(("127.0.0.1", 0), servidor.Manejador)
        worker = threading.Thread(target=httpd.serve_forever, daemon=True)
        worker.start()
        try:
            for segundo in ("2", "3"):
                with self.subTest(segundo=segundo), \
                        socket.create_connection(
                            ("127.0.0.1", httpd.server_port), timeout=2) as cliente:
                    cliente.sendall(
                        ("POST /api/claims HTTP/1.1\r\n"
                         "Host: localhost\r\n"
                         "Content-Length: 2\r\n"
                         f"Content-Length: {segundo}\r\n"
                         "Connection: close\r\n\r\n{}").encode("ascii"))
                    respuesta = cliente.recv(4096)
                self.assertIn(b" 400 ", respuesta.split(b"\r\n", 1)[0])
        finally:
            httpd.shutdown()
            httpd.server_close()
            worker.join(timeout=5)

    def test_limite_http_reserva_capacidad_local_y_corta_slow_headers(self):
        modo = {"local": False}
        lentos = []
        with mock.patch.object(servidor, "MAX_HTTP_EXTERNOS", 2), \
                mock.patch.object(servidor, "MAX_HTTP_TOTAL", 3), \
                mock.patch.object(servidor, "TIEMPO_CABECERAS", 0.3), \
                mock.patch.object(
                    servidor.Servidor, "_es_cliente_local",
                    side_effect=lambda _direccion: modo["local"]):
            httpd = servidor.Servidor(("127.0.0.1", 0), servidor.Manejador)
            worker = threading.Thread(target=httpd.serve_forever, daemon=True)
            worker.start()
            try:
                for _indice in range(2):
                    cliente = socket.create_connection(
                        ("127.0.0.1", httpd.server_port), timeout=2)
                    cliente.sendall(
                        b"GET /api/health HTTP/1.1\r\nHost: lento")
                    lentos.append(cliente)
                limite = time.monotonic() + 2
                while time.monotonic() < limite:
                    with httpd._candado_reservas_http:
                        if len(httpd._reservas_http) == 2:
                            break
                    time.sleep(0.01)

                modo["local"] = True
                with urllib.request.urlopen(
                        f"http://127.0.0.1:{httpd.server_port}/api/health",
                        timeout=2) as respuesta:
                    salud = json.loads(respuesta.read())
                self.assertEqual("ok", salud["estado"])

                limite = time.monotonic() + 2
                while time.monotonic() < limite:
                    with httpd._candado_reservas_http:
                        if not httpd._reservas_http:
                            break
                    time.sleep(0.02)
                with httpd._candado_reservas_http:
                    self.assertFalse(httpd._reservas_http)
            finally:
                for cliente in lentos:
                    cliente.close()
                httpd.shutdown()
                httpd.server_close()
                worker.join(timeout=5)

    def test_primer_nodo_declarado_es_escritor_sin_alterar_ranking_vrrp(self):
        declaracion = (
            "writer:192.0.2.10:eth0:50,"
            "fast:192.0.2.11:eth0:150,"
            "middle:192.0.2.12:eth0:100"
        )
        with mock.patch.dict(os.environ, {"FIP_NODOS": declaracion}):
            nodos = local._nodos_de_entorno()
        self.assertEqual(
            ["writer", "fast", "middle"],
            [nodo["nombre"] for nodo in nodos],
        )
        with mock.patch.object(local, "NODOS", nodos):
            self.assertEqual("writer", servidor._escritor_cluster())

        prioridades = servidor.plan.prioridades(
            "service-a", "writer", nodos, set())
        self.assertEqual(
            {"writer": 150, "fast": 100, "middle": 50}, prioridades)
        datos = pool._vacio()
        datos["direcciones"] = [{
            "ip": "192.0.2.100", "vrid": 42, "estado": "en_uso",
            "servicio": "service-a", "preferente": "writer",
            "chequeo": {"puerto": 8080, "ruta": "/health"},
        }]
        with mock.patch.object(
                servidor.plan, "_auth_pass", return_value="Vrrp1234"):
            configuraciones = {
                nodo["nombre"]: servidor.plan.generar_conf(
                    datos, nodo["nombre"], nodos, 45)
                for nodo in nodos
            }
        for nodo, prioridad in prioridades.items():
            self.assertRegex(
                configuraciones[nodo], rf"priority\s+{prioridad}\b")

        duplicadas = (
            "a:192.0.2.10:eth0:100,b:192.0.2.11:eth0:100")
        with mock.patch.dict(os.environ, {"FIP_NODOS": duplicadas}):
            with self.assertRaisesRegex(ValueError, "prioridad repetida"):
                local._nodos_de_entorno()

    def test_limita_nodos_y_pares_antes_de_crear_ejecutores(self):
        declaracion = ",".join(
            f"node-{indice}:192.0.2.{indice}:eth0:{indice}"
            for indice in range(1, local.MAX_NODOS + 2)
        )
        with mock.patch.dict(os.environ, {"FIP_NODOS": declaracion}):
            with self.assertRaisesRegex(ValueError, "más de 16 nodos"):
                local._nodos_de_entorno()

        pares = ",".join(
            f"http://node-{indice}:6060"
            for indice in range(1, servidor.configuracion.MAX_PARES + 2)
        )
        with self.assertRaisesRegex(RuntimeError, "más de 15 paneles"):
            servidor.configuracion.urls_pares(pares)

    def test_retardo_vuelta_exige_decimal_canonico_en_rango(self):
        for invalido in ("", "-1", "+1", "01", " 1", "1 ", "1001", "1.0"):
            with self.subTest(valor=invalido), \
                    mock.patch.dict(
                        os.environ, {"FIP_RETARDO": invalido}, clear=False):
                with self.assertRaises(RuntimeError):
                    servidor._retardo_vuelta_entorno()
        for valido, esperado in (("0", 0), ("45", 45), ("1000", 1000)):
            with self.subTest(valor=valido), \
                    mock.patch.dict(
                        os.environ, {"FIP_RETARDO": valido}, clear=False):
                self.assertEqual(esperado, servidor._retardo_vuelta_entorno())

    @unittest.skipUnless(os.name == "posix", "protecciones de fichero POSIX")
    def test_config_keepalived_usa_temporal_aleatorio_y_modo_secreto(self):
        directorio = self.raiz / "config-segura"
        directorio.mkdir(mode=0o777)
        ruta = directorio / "keepalived.conf"
        texto = "global_defs {\n  router_id TEST\n}\n# auth_pass Secreto\n"
        ejecucion = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(servidor, "RUTA_CONF", str(ruta)), \
                mock.patch.object(
                    servidor, "_config_recarga_pendiente", False), \
                mock.patch.object(local, "NODOS", NODOS), \
                mock.patch.object(local, "YO", "node-a"), \
                mock.patch.object(
                    servidor.plan, "generar_conf", return_value=texto), \
                mock.patch.object(local, "drenajes", return_value=[]), \
                mock.patch.object(
                    servidor.subprocess, "run", return_value=ejecucion) as run, \
                mock.patch.object(servidor, "_pid_keepalived", return_value=None):
            resultado = servidor.aplicar(pool._vacio())

        self.assertTrue(resultado["pendiente_arranque"])
        self.assertEqual(0o600, stat.S_IMODE(ruta.stat().st_mode))
        self.assertEqual(0o700, stat.S_IMODE(directorio.stat().st_mode))
        temporal_validado = Path(run.call_args.args[0][-1])
        self.assertNotEqual(ruta, temporal_validado)
        self.assertTrue(temporal_validado.name.startswith(".keepalived."))
        self.assertEqual([], list(directorio.glob(".keepalived.*.tmp")))

    @unittest.skipUnless(os.name == "posix", "tipos especiales POSIX")
    def test_config_rechaza_symlink_fifo_y_hardlink_sin_tocarlos(self):
        for tipo in ("symlink", "fifo", "hardlink"):
            with self.subTest(tipo=tipo):
                directorio = self.raiz / f"config-{tipo}"
                directorio.mkdir()
                ruta = directorio / "keepalived.conf"
                victima = directorio / "victima"
                victima.write_text("NO TOCAR", encoding="utf-8")
                if tipo == "symlink":
                    ruta.symlink_to(victima)
                elif tipo == "fifo":
                    os.mkfifo(ruta)
                else:
                    os.link(victima, ruta)
                with mock.patch.object(servidor, "RUTA_CONF", str(ruta)), \
                        mock.patch.object(
                            servidor, "_config_recarga_pendiente", False), \
                        mock.patch.object(local, "NODOS", NODOS), \
                        mock.patch.object(local, "YO", "node-a"), \
                        mock.patch.object(
                            servidor.plan, "generar_conf", return_value="ok\n"), \
                        mock.patch.object(
                            servidor, "_validar_archivo_config",
                            return_value=(True, "")), \
                        mock.patch.object(local, "drenajes", return_value=[]):
                    with self.assertRaises(pool.ErrorPool):
                        servidor.aplicar(pool._vacio())
                self.assertEqual("NO TOCAR", victima.read_text(encoding="utf-8"))
                self.assertEqual(
                    [], list(directorio.glob(".keepalived.*.tmp")))

    @unittest.skipUnless(os.name == "posix", "fsync de directorio POSIX")
    def test_config_no_hace_hup_hasta_confirmar_fsync_directorio(self):
        directorio = self.raiz / "config-incierta"
        directorio.mkdir()
        ruta = directorio / "keepalived.conf"
        textos = ["config vieja\n", "config nueva con auth_pass secreto\n"]
        fsync_real = servidor.os.fsync

        def ejecutar(texto, pid=None):
            with mock.patch.object(
                    servidor.plan, "generar_conf", return_value=texto), \
                    mock.patch.object(
                        servidor, "_validar_archivo_config",
                        return_value=(True, "")), \
                    mock.patch.object(local, "drenajes", return_value=[]), \
                    mock.patch.object(
                        servidor, "_pid_keepalived", return_value=pid):
                return servidor.aplicar(pool._vacio())

        with mock.patch.object(servidor, "RUTA_CONF", str(ruta)), \
                mock.patch.object(
                    servidor, "_config_recarga_pendiente", False), \
                mock.patch.object(local, "NODOS", NODOS), \
                mock.patch.object(local, "YO", "node-a"):
            ejecutar(textos[0])

            def fsync_con_eio(fd):
                if stat.S_ISDIR(os.fstat(fd).st_mode):
                    raise OSError(errno.EIO, "fallo de almacenamiento")
                return fsync_real(fd)

            with mock.patch.object(
                    servidor.os, "fsync", side_effect=fsync_con_eio), \
                    mock.patch.object(servidor.os, "kill") as matar:
                with self.assertRaises(pool.ErrorRevisionPool) as error:
                    ejecutar(textos[1], pid=4321)
            self.assertEqual(
                "POOL_CONFIG_COMMIT_UNCERTAIN", error.exception.codigo)
            matar.assert_not_called()
            self.assertEqual(textos[1], ruta.read_text(encoding="utf-8"))
            self.assertTrue(servidor._config_recarga_pendiente)

            with mock.patch.object(servidor.os, "kill") as matar:
                resultado = ejecutar(textos[1], pid=4321)
            matar.assert_called_once_with(4321, signal.SIGHUP)
            self.assertTrue(resultado["recargado"])
            self.assertFalse(servidor._config_recarga_pendiente)
            self.assertEqual(
                [], list(directorio.glob(".keepalived.*.tmp")))

    def test_config_invalida_es_503_apply_pending_y_no_falso_exito(self):
        ruta = self.raiz / "config-invalida" / "keepalived.conf"
        with mock.patch.object(servidor, "RUTA_CONF", str(ruta)), \
                mock.patch.object(local, "NODOS", NODOS), \
                mock.patch.object(local, "YO", "node-a"), \
                mock.patch.object(local, "drenajes", return_value=[]), \
                mock.patch.object(
                    servidor.plan, "generar_conf", return_value="rota\n"), \
                mock.patch.object(
                    servidor, "_validar_archivo_config",
                    return_value=(False, "identificador duplicado")), \
                mock.patch.object(
                    servidor, "_ultimo_error_aplicacion", None):
            with self.assertRaises(pool.ErrorRevisionPool) as error:
                servidor.aplicar(pool._vacio())
            self.assertEqual("POOL_APPLY_PENDING", error.exception.codigo)
            self.assertEqual(
                "POOL_APPLY_PENDING", servidor._ultimo_error_aplicacion)

            manejador = object.__new__(servidor.Manejador)
            manejador._error = mock.Mock()
            manejador._error_pool(error.exception)
            self.assertEqual(503, manejador._error.call_args.args[1])
            self.assertEqual(
                "POOL_APPLY_PENDING", manejador._error.call_args.args[2])

    def test_fallo_config_no_desactiva_drain_de_configuracion_anterior(self):
        ruta = self.raiz / "config-drain" / "keepalived.conf"
        datos = pool._vacio()
        datos["direcciones"] = [{
            "ip": "192.0.2.100", "vrid": 42, "estado": "en_uso",
            "servicio": "servicio-a",
            "chequeo": {"puerto": 8080, "ruta": "/health"},
        }]
        marcar = mock.Mock()
        with mock.patch.object(servidor, "RUTA_CONF", str(ruta)), \
                mock.patch.object(local, "NODOS", NODOS), \
                mock.patch.object(local, "YO", "node-a"), \
                mock.patch.object(local, "drenajes", return_value=["servicio-a"]), \
                mock.patch.object(local, "marcar_drenaje", marcar), \
                mock.patch.object(
                    servidor.plan, "generar_conf", return_value="rota\n"), \
                mock.patch.object(
                    servidor, "_validar_archivo_config",
                    return_value=(False, "config inválida")):
            with self.assertRaises(pool.ErrorRevisionPool) as error:
                servidor.aplicar(datos)

        self.assertEqual("POOL_APPLY_PENDING", error.exception.codigo)
        marcar.assert_not_called()

    def test_entrada_drain_es_temprana_pero_salida_espera_reload(self):
        ruta = self.raiz / "config-drain-entrada" / "keepalived.conf"
        datos = pool._vacio()
        datos["mantenimiento"] = ["node-a"]
        datos["direcciones"] = [{
            "ip": "192.0.2.100", "vrid": 42, "estado": "en_uso",
            "servicio": "nuevo",
            "chequeo": {"puerto": 8080, "ruta": "/health"},
        }]
        marcar = mock.Mock()
        with mock.patch.object(servidor, "RUTA_CONF", str(ruta)), \
                mock.patch.object(local, "NODOS", NODOS), \
                mock.patch.object(local, "YO", "node-a"), \
                mock.patch.object(local, "drenajes", return_value=["antiguo"]), \
                mock.patch.object(local, "marcar_drenaje", marcar), \
                mock.patch.object(
                    servidor.plan, "generar_conf", return_value="rota\n"), \
                mock.patch.object(
                    servidor, "_validar_archivo_config",
                    return_value=(False, "config inválida")):
            with self.assertRaises(pool.ErrorRevisionPool):
                servidor.aplicar(datos)

        marcar.assert_called_once_with("nuevo", True)

    @unittest.skipUnless(os.name == "posix", "recarga POSIX")
    def test_sighup_fallido_deja_recarga_pendiente_y_codigo_estable(self):
        directorio = self.raiz / "config-reload"
        directorio.mkdir()
        ruta = directorio / "keepalived.conf"
        texto = "config durable con auth_pass secreto\n"
        with mock.patch.object(servidor, "RUTA_CONF", str(ruta)), \
                mock.patch.object(
                    servidor, "_config_recarga_pendiente", False), \
                mock.patch.object(
                    servidor, "_ultimo_error_aplicacion", None), \
                mock.patch.object(local, "NODOS", NODOS), \
                mock.patch.object(local, "YO", "node-a"), \
                mock.patch.object(local, "drenajes", return_value=[]), \
                mock.patch.object(
                    servidor.plan, "generar_conf", return_value=texto), \
                mock.patch.object(
                    servidor, "_validar_archivo_config", return_value=(True, "")), \
                mock.patch.object(
                    servidor, "_pid_keepalived", return_value=4321), \
                mock.patch.object(
                    servidor.os, "kill", side_effect=OSError(errno.EIO, "HUP")):
            with self.assertRaises(pool.ErrorRevisionPool) as error:
                servidor.aplicar(pool._vacio())
            self.assertEqual(
                "POOL_CONFIG_RELOAD_UNCERTAIN", error.exception.codigo)
            self.assertEqual(texto, ruta.read_text(encoding="utf-8"))
            self.assertTrue(servidor._config_recarga_pendiente)

            with mock.patch.object(servidor.os, "kill") as matar:
                resultado = servidor.aplicar(pool._vacio())
            matar.assert_called_once_with(4321, signal.SIGHUP)
            self.assertTrue(resultado["recargado"])
            self.assertFalse(servidor._config_recarga_pendiente)
            self.assertIsNone(servidor._ultimo_error_aplicacion)

    def test_http_interno_cifra_snapshot_ack_y_rechaza_stale_conflicto(self):
        token = "cluster-token-de-prueba-" + "x" * 32
        origen = self.registro("origen", "node-a")
        base = origen.escribir(pool._vacio(), marcar_hora=False)
        posterior = origen.leer()
        posterior["dhcp_desde"] = 110
        origen.escribir(posterior, marcar_hora=False)
        receptor = self.registro("receptor", "node-b")
        receptor.aplicar_replica(base)
        rama = self.registro("rama", "node-c")
        rama.aplicar_replica(base)
        concurrente = rama.leer()
        concurrente["dhcp_desde"] = 120
        rama.escribir(concurrente, marcar_hora=False)
        protocolo_servidor = seguridad.ProtocoloCluster(
            token, "node-b", [n["nombre"] for n in NODOS])
        cliente = seguridad.ProtocoloCluster(
            token, "node-a", [n["nombre"] for n in NODOS])
        cliente_no_escritor = seguridad.ProtocoloCluster(
            token, "node-c", [n["nombre"] for n in NODOS])
        marcador = str(self.raiz / "no-listo")

        with mock.patch.object(local, "NODOS", NODOS), \
                mock.patch.object(local, "YO", "node-b"), \
                mock.patch.multiple(
                    servidor, POOL=receptor, PROTOCOLO=protocolo_servidor,
                    MARCADOR_LISTO=marcador), \
                mock.patch.object(servidor, "aplicar") as aplicar, \
                mock.patch.object(
                    servidor, "_degradar_readiness_pool") as degradar:
            httpd = servidor.Servidor(("127.0.0.1", 0), servidor.Manejador)
            worker = threading.Thread(target=httpd.serve_forever, daemon=True)
            worker.start()
            base_url = f"http://127.0.0.1:{httpd.server_port}"
            try:
                ruta = servidor.RUTA_POOL_V2
                peticion = urllib.request.Request(base_url + ruta)
                for nombre, valor in cliente.firmar("GET", ruta).items():
                    peticion.add_header(nombre, valor)
                with urllib.request.urlopen(peticion, timeout=5) as respuesta:
                    sobre = json.loads(respuesta.read())["payload"]
                mensaje = cliente.descifrar(sobre)
                self.assertEqual("node-b", mensaje["nodo"])
                self.assertTrue(mensaje["initialized"])
                self.assertEqual(
                    pool.Pool.huella(base),
                    pool.Pool.huella(mensaje["snapshot"]),
                )

                def replicar(snapshot, cuerpo_plano=False, protocolo=cliente,
                             nodo="node-a"):
                    ruta_replica = servidor.RUTA_REPLICA_POOL_V2
                    contenido = ({
                                     "capability": servidor.CAPACIDAD_POOL_V2,
                                     "nodo": nodo, "snapshot": snapshot}
                                 if cuerpo_plano else {
                                     "payload": protocolo.cifrar({
                                         "capability": servidor.CAPACIDAD_POOL_V2,
                                         "nodo": nodo, "snapshot": snapshot})})
                    crudo = json.dumps(
                        contenido, separators=(",", ":")).encode()
                    req = urllib.request.Request(
                        base_url + ruta_replica, data=crudo, method="POST")
                    req.add_header("Content-Type", "application/json")
                    for nombre, valor in protocolo.firmar(
                            "POST", ruta_replica, crudo).items():
                        req.add_header(nombre, valor)
                    try:
                        with urllib.request.urlopen(req, timeout=5) as respuesta:
                            return respuesta.status, json.loads(respuesta.read())
                    except urllib.error.HTTPError as error:
                        return error.code, json.loads(error.read())

                codigo, respuesta = replicar(posterior)
                self.assertEqual(200, codigo)
                ack = cliente.descifrar(respuesta["payload"])
                self.assertEqual("node-b", ack["nodo"])
                self.assertEqual(pool.Pool.huella(posterior), ack["huella"])
                self.assertTrue(ack["replica_aplicada"])

                codigo, respuesta = replicar(posterior)
                self.assertEqual(200, codigo)
                self.assertFalse(
                    cliente.descifrar(respuesta["payload"])["replica_aplicada"])
                codigo, respuesta = replicar(base)
                self.assertEqual((409, "POOL_REPLICA_STALE"),
                                 (codigo, respuesta["code"]))
                misma_revision = json.loads(json.dumps(posterior))
                misma_revision["dhcp_desde"] = 130
                codigo, respuesta = replicar(misma_revision)
                self.assertEqual((409, "POOL_REPLICA_EQUAL_REVISION_CONFLICT"),
                                 (codigo, respuesta["code"]))
                codigo, respuesta = replicar(
                    posterior, protocolo=cliente, nodo="node-c")
                self.assertEqual((401, "CLUSTER_IDENTITY_MISMATCH"),
                                 (codigo, respuesta["code"]))
                huella_antes = pool.Pool.huella(receptor.leer())
                codigo, respuesta = replicar(
                    concurrente, protocolo=cliente_no_escritor, nodo="node-c")
                self.assertEqual((409, "POOL_REPLICA_IDENTITY_INVALID"),
                                 (codigo, respuesta["code"]))
                self.assertEqual(
                    huella_antes, pool.Pool.huella(receptor.leer()))
                with mock.patch.object(
                        receptor, "aplicar_replica",
                        side_effect=pool.ErrorCommitPool()):
                    codigo, respuesta = replicar(posterior)
                self.assertEqual(
                    (503, "POOL_LOCAL_COMMIT_UNCERTAIN"),
                    (codigo, respuesta["code"]),
                )
                fallo_aplicar = pool.ErrorRevisionPool(
                    "configuración pendiente", "POOL_APPLY_PENDING")
                with mock.patch.object(
                        servidor, "aplicar", side_effect=fallo_aplicar):
                    codigo, respuesta = replicar(posterior)
                self.assertEqual(
                    (503, "POOL_APPLY_PENDING"),
                    (codigo, respuesta["code"]),
                )
                codigo, respuesta = replicar(posterior, cuerpo_plano=True)
                self.assertEqual(400, codigo)
                self.assertEqual("INVALID_SECURITY_REPLICA", respuesta["code"])
                self.assertEqual(2, aplicar.call_count)
                degradar.assert_has_calls([
                    mock.call(detener_keepalived=True),
                    mock.call(detener_keepalived=True),
                ])
            finally:
                httpd.shutdown()
                httpd.server_close()
                worker.join(timeout=5)


class ClusterSeguridadTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.raiz = Path(self.tmp.name)

    def almacen(self, nombre, nodo):
        return seguridad.AlmacenSeguridad(
            str(self.raiz / f"{nombre}.json"), nodo)

    @staticmethod
    def red(registros, caidos=()):
        endpoints = {f"http://{nombre}:6060": nombre for nombre in registros}
        caidos = set(caidos)
        llamadas = []

        def pedir(base, ruta, datos=None, metodo=None, tiempo=None):
            nombre = endpoints[base]
            metodo = metodo or ("POST" if datos is not None else "GET")
            llamadas.append((base, metodo, ruta))
            if nombre in caidos:
                raise TimeoutError(nombre)
            almacen = registros[nombre]
            if ruta == servidor.RUTA_SEGURIDAD_V2:
                return {"payload": {
                    "capability": servidor.CAPACIDAD_SEGURIDAD_V2,
                    "nodo": nombre,
                    "initialized": almacen.existe(),
                    "snapshot": almacen.leer(),
                }}
            if ruta == servidor.RUTA_REPLICA_SEGURIDAD_V2:
                mensaje = datos["payload"]
                aplicado = almacen.aplicar_replica(mensaje["snapshot"])
                actual = almacen.leer()
                return {"payload": {
                    "capability": servidor.CAPACIDAD_SEGURIDAD_V2,
                    "estado": "ok",
                    "nodo": nombre,
                    "replica_aplicada": aplicado,
                    "huella": seguridad.AlmacenSeguridad.huella(actual),
                }}
            raise AssertionError(f"ruta interna inesperada: {ruta}")

        return endpoints, pedir, llamadas

    def contexto(self, yo, almacen_local, pares, pedir):
        return mock.patch.multiple(
            servidor,
            CUENTAS=almacen_local,
            PARES=pares,
            PROTOCOLO=ProtocoloClaro(),
            _pedir_interno=pedir,
            MARCADOR_PROTOCOLO_V2=str(
                self.raiz / ".cluster-protocol-v2"),
            _observaciones_protocolo_v2={"pool": None, "security": None},
        ), mock.patch.object(local, "NODOS", NODOS), mock.patch.object(local, "YO", yo)

    @staticmethod
    def inicializar_con_propietario(almacen):
        almacen.inicializar_revision("system")
        _usuario, snapshot = almacen.crear_propietario(
            "admin", "Administrador", HASH_CLAVE_PRUEBA)
        return snapshot

    def test_arranque_frio_seguridad_crea_una_rama_y_converge(self):
        almacenes = {nombre: self.almacen(nombre, nombre)
                     for nombre in ("node-a", "node-b", "node-c")}
        endpoints, pedir, _llamadas = self.red(almacenes)
        pares = [base for base, nombre in endpoints.items()
                 if nombre != "node-a"]
        parches = self.contexto("node-a", almacenes["node-a"], pares, pedir)
        marker = crear_marker_bootstrap(self.raiz / ".bootstrap-security")

        with parches[0], parches[1], parches[2], \
                mock.patch.object(
                    servidor, "MARCADOR_BOOTSTRAP_SEGURIDAD", str(marker)):
            resultado = servidor.reconciliar_seguridad()

        self.assertEqual(
            {"node-a": 1}, resultado["snapshot"]["revision"]["clock"])
        self.assertTrue(all(valor.existe() for valor in almacenes.values()))
        self.assertEqual(1, len({
            seguridad.AlmacenSeguridad.huella(valor.leer())
            for valor in almacenes.values()
        }))
        # El vacío causal replicado mantiene abierto el alta inicial; el
        # permiso one-shot ya se consumió antes de declarar bootstrap completo.
        self.assertFalse(marker.exists())

    def test_arranque_frio_seguridad_reanuda_corte_post_rename(self):
        almacenes = {nombre: self.almacen(nombre, nombre)
                     for nombre in ("node-a", "node-b", "node-c")}
        inicial = almacenes["node-a"].inicializar_desde_candidato(
            almacenes["node-a"].leer(), actor="system")
        self.assertEqual({"node-a": 1}, inicial["revision"]["clock"])
        endpoints, pedir, _llamadas = self.red(almacenes)
        pares = [base for base, nombre in endpoints.items()
                 if nombre != "node-a"]
        parches = self.contexto("node-a", almacenes["node-a"], pares, pedir)
        marker = crear_marker_bootstrap(self.raiz / ".bootstrap-security")
        with parches[0], parches[1], parches[2], \
                mock.patch.object(
                    servidor, "MARCADOR_BOOTSTRAP_SEGURIDAD", str(marker)):
            resultado = servidor.reconciliar_seguridad()

        self.assertEqual(3, resultado["propagacion"]["acknowledged"])
        self.assertEqual(1, len({
            seguridad.AlmacenSeguridad.huella(almacen.leer())
            for almacen in almacenes.values()
        }))
        self.assertFalse(marker.exists())

    def test_seguridad_repara_intermedio_legacy_de_version_anterior(self):
        almacenes = {nombre: self.almacen(nombre, nombre)
                     for nombre in ("node-a", "node-b", "node-c")}
        almacenes["node-a"].aplicar_replica(almacenes["node-a"].leer())
        self.assertEqual(
            {}, almacenes["node-a"].leer()["revision"]["clock"])
        endpoints, pedir, _llamadas = self.red(almacenes)
        pares = [base for base, nombre in endpoints.items()
                 if nombre != "node-a"]
        parches = self.contexto("node-a", almacenes["node-a"], pares, pedir)
        marker = crear_marker_bootstrap(self.raiz / ".bootstrap-security")
        with parches[0], parches[1], parches[2], \
                mock.patch.object(
                    servidor, "MARCADOR_BOOTSTRAP_SEGURIDAD", str(marker)):
            resultado = servidor.reconciliar_seguridad()

        self.assertEqual({"node-a": 1}, resultado["snapshot"]["revision"]["clock"])
        self.assertEqual(3, resultado["propagacion"]["acknowledged"])
        self.assertFalse(marker.exists())

    def test_bootstrap_seguridad_cinco_nodos_reanuda_dos_copias(self):
        nodos = [
            {"nombre": f"node-{letra}", "ip": f"192.0.2.{10 + indice}",
             "interfaz": "eth0", "prioridad": 150 - indice}
            for indice, letra in enumerate("abcde")
        ]
        almacenes = {
            nodo["nombre"]: self.almacen(nodo["nombre"], nodo["nombre"])
            for nodo in nodos
        }
        inicial = almacenes["node-a"].inicializar_desde_candidato(
            almacenes["node-a"].leer(), actor="system")
        almacenes["node-b"].aplicar_replica(inicial)
        endpoints, pedir, _llamadas = self.red(almacenes)
        marker = crear_marker_bootstrap(self.raiz / ".bootstrap-security")
        with mock.patch.multiple(
                servidor,
                CUENTAS=almacenes["node-a"],
                PARES=[base for base, nombre in endpoints.items()
                       if nombre != "node-a"],
                PROTOCOLO=ProtocoloClaro(),
                _pedir_interno=pedir,
                MARCADOR_BOOTSTRAP_SEGURIDAD=str(marker),
                MARCADOR_PROTOCOLO_V2=str(
                    self.raiz / ".cluster-protocol-v2"),
                _observaciones_protocolo_v2={"pool": None, "security": None}), \
                mock.patch.object(local, "NODOS", nodos), \
                mock.patch.object(local, "YO", "node-a"):
            resultado = servidor.reconciliar_seguridad()

        self.assertEqual(3, resultado["quorum"])
        self.assertEqual(5, resultado["propagacion"]["acknowledged"])
        self.assertEqual(1, len({
            seguridad.AlmacenSeguridad.huella(almacen.leer())
            for almacen in almacenes.values()
        }))
        self.assertFalse(marker.exists())

    def test_seguridad_sin_marker_no_materializa_y_con_marker_cierra_alta(self):
        almacenes = {nombre: self.almacen(nombre, nombre)
                     for nombre in ("node-a", "node-b", "node-c")}
        endpoints, pedir, _llamadas = self.red(almacenes)
        pares = [base for base, nombre in endpoints.items()
                 if nombre != "node-a"]
        parches = self.contexto("node-a", almacenes["node-a"], pares, pedir)
        marker = self.raiz / ".bootstrap-security"

        with parches[0], parches[1], parches[2], \
                mock.patch.object(
                    servidor, "MARCADOR_BOOTSTRAP_SEGURIDAD", str(marker)):
            with self.assertRaises(seguridad.ErrorAcceso) as error:
                servidor.reconciliar_seguridad()
            self.assertEqual("AUTH_BOOTSTRAP_REQUIRED", error.exception.codigo)
            self.assertFalse(any(valor.existe() for valor in almacenes.values()))

            crear_marker_bootstrap(marker)
            vacio = servidor.reconciliar_seguridad()
            self.assertFalse(vacio["snapshot"]["users"])
            self.assertFalse(marker.exists())
            segunda = servidor.reconciliar_seguridad()
            self.assertFalse(segunda["snapshot"]["users"])

            _usuario, con_propietario = almacenes["node-a"].crear_propietario(
                "admin", "Administrador", HASH_CLAVE_PRUEBA)
            confirmado = servidor.replicar_seguridad(con_propietario)
            self.assertTrue(confirmado["ok"])
            self.assertFalse(marker.exists())

            # Perder después todos los bind mounts no vuelve a abrir registro.
            for almacen in almacenes.values():
                os.unlink(almacen.ruta)
            with self.assertRaises(seguridad.ErrorAcceso) as reapertura:
                servidor.reconciliar_seguridad()
            self.assertEqual(
                "AUTH_BOOTSTRAP_REQUIRED", reapertura.exception.codigo)
            self.assertFalse(any(valor.existe() for valor in almacenes.values()))

    def test_reemplazo_sin_security_recupera_dos_peers_identicos(self):
        origen = self.almacen("node-a", "node-a")
        snapshot = self.inicializar_con_propietario(origen)
        peer = self.almacen("node-c", "node-c")
        peer.aplicar_replica(snapshot)
        reemplazo = self.almacen("node-b", "node-b")
        self.assertFalse(reemplazo.existe())
        endpoints, pedir, llamadas = self.red({
            "node-a": origen, "node-c": peer})
        parches = self.contexto(
            "node-b", reemplazo, list(endpoints), pedir)

        with parches[0], parches[1], parches[2]:
            resultado = servidor.reconciliar_seguridad()

        self.assertTrue(reemplazo.existe())
        self.assertEqual("admin", reemplazo.leer()["users"][0]["username"])
        self.assertEqual(
            seguridad.AlmacenSeguridad.huella(snapshot),
            seguridad.AlmacenSeguridad.huella(reemplazo.leer()),
        )
        self.assertEqual(1, resultado["propagacion"]["acknowledged"])
        self.assertEqual("non-writer", resultado["propagacion"]["skipped"])
        self.assertFalse(any(
            metodo == "POST" for _base, metodo, _ruta in llamadas))

    def test_seguridad_v2_ignora_old_y_nunca_hace_post_legacy(self):
        escritor = self.almacen("node-a", "node-a")
        snapshot = self.inicializar_con_propietario(escritor)
        peer = self.almacen("node-b", "node-b")
        peer.aplicar_replica(snapshot)
        nuevo = "http://node-b:6060"
        antiguo = "http://node-c-old:6060"
        llamadas = []

        def pedir(base, ruta, datos=None, metodo=None, tiempo=None):
            metodo = metodo or ("POST" if datos is not None else "GET")
            llamadas.append((base, metodo, ruta))
            if base == antiguo:
                raise RuntimeError("404 old sin security v2")
            if ruta == servidor.RUTA_SEGURIDAD_V2:
                return {"payload": {
                    "capability": servidor.CAPACIDAD_SEGURIDAD_V2,
                    "nodo": "node-b", "initialized": True,
                    "snapshot": peer.leer(),
                }}
            if ruta == servidor.RUTA_REPLICA_SEGURIDAD_V2:
                mensaje = datos["payload"]
                peer.aplicar_replica(mensaje["snapshot"])
                return {"payload": {
                    "capability": servidor.CAPACIDAD_SEGURIDAD_V2,
                    "estado": "ok", "nodo": "node-b",
                    "huella": seguridad.AlmacenSeguridad.huella(peer.leer()),
                }}
            raise AssertionError("un nodo nuevo no usa rutas legacy de acceso")

        parches = self.contexto(
            "node-a", escritor, [nuevo, antiguo], pedir)
        with parches[0], parches[1], parches[2]:
            resultado = servidor.reconciliar_seguridad()

        self.assertEqual({"node-b": nuevo}, resultado["capacidades"])
        self.assertFalse(any(
            base == antiguo and metodo == "POST"
            for base, metodo, _ruta in llamadas))
        self.assertFalse(any(
            metodo == "POST" and ruta != servidor.RUTA_REPLICA_SEGURIDAD_V2
            for _base, metodo, ruta in llamadas))

    def test_identidad_seguridad_duplicada_no_aporta_quorum(self):
        escritor = self.almacen("node-a", "node-a")
        snapshot = self.inicializar_con_propietario(escritor)
        endpoints = ["http://peer-1:6060", "http://peer-2:6060"]

        def pedir(_base, _ruta, datos=None, metodo=None, tiempo=None):
            return {"payload": {
                "capability": servidor.CAPACIDAD_SEGURIDAD_V2,
                "nodo": "node-b", "initialized": True,
                "snapshot": snapshot,
            }}

        parches = self.contexto("node-a", escritor, endpoints, pedir)
        with parches[0], parches[1], parches[2]:
            consulta = servidor._consultar_snapshots_seguridad()
            with self.assertRaises(seguridad.ErrorAcceso) as error:
                servidor.reconciliar_seguridad()

        self.assertEqual(["node-a"], consulta["identidades"])
        self.assertEqual(["node-b"], consulta["duplicadas"])
        self.assertEqual("AUTH_QUORUM_UNAVAILABLE", error.exception.codigo)

    def test_non_writer_seguridad_falla_antes_de_reconciliar(self):
        reconciliar = mock.Mock()
        with mock.patch.object(local, "NODOS", NODOS), \
                mock.patch.object(local, "YO", "node-b"), \
                mock.patch.object(
                    servidor, "reconciliar_seguridad", reconciliar):
            with self.assertRaises(seguridad.ErrorAcceso) as error:
                servidor.preflight_mutacion_seguridad()

        self.assertEqual("AUTH_WRITER_REQUIRED", error.exception.codigo)
        reconciliar.assert_not_called()

    def test_mixed_version_congela_mutacion_de_seguridad(self):
        with mock.patch.multiple(
                servidor,
                MARCADOR_PROTOCOLO_V2=str(
                    self.raiz / ".cluster-protocol-v2"),
                _observaciones_protocolo_v2={"pool": None, "security": None}), \
                mock.patch.object(local, "NODOS", NODOS), \
                mock.patch.object(local, "YO", "node-a"), \
                mock.patch.object(
                    servidor, "reconciliar_seguridad", return_value={
                        "capacidades": {"node-b": "http://node-b:6060"}}):
            with self.assertRaises(seguridad.ErrorAcceso) as error:
                servidor.preflight_mutacion_seguridad()

        self.assertEqual(
            "CLUSTER_UPGRADE_IN_PROGRESS", error.exception.codigo)
        self.assertEqual(503, error.exception.http)

    def test_marker_v2_durable_permite_revocar_con_un_peer_caido(self):
        marker = self.raiz / ".cluster-protocol-v2"
        capacidades = {
            "node-b": "http://node-b:6060",
            "node-c": "http://node-c:6060",
        }
        esperado = {"capacidades": {"node-b": "http://node-b:6060"}}
        with mock.patch.multiple(
                servidor,
                MARCADOR_PROTOCOLO_V2=str(marker),
                _observaciones_protocolo_v2={"pool": None, "security": None}), \
                mock.patch.object(local, "NODOS", NODOS), \
                mock.patch.object(local, "YO", "node-a"):
            servidor._observar_protocolo_v2("pool", capacidades)
            servidor._observar_protocolo_v2("security", capacidades)
            with mock.patch.object(
                    servidor, "reconciliar_seguridad", return_value=esperado):
                self.assertIs(esperado, servidor.preflight_mutacion_seguridad())

    def test_legacy_seguridad_divergente_falla_sin_propagar(self):
        fuente = self.almacen("fuente", "node-a")
        con_usuario = self.inicializar_con_propietario(fuente)
        con_usuario["revision"] = {
            "counter": 1, "timestamp": 1, "node": "node-a", "actor": "admin"}
        escritor = self.almacen("node-a", "node-a")
        escritor.aplicar_replica(con_usuario)
        vacio = self.almacen("node-b", "node-b")
        vacio.aplicar_replica(vacio._vacio())
        ausente = self.almacen("node-c", "node-c")
        endpoints, pedir, llamadas = self.red({
            "node-b": vacio, "node-c": ausente})
        parches = self.contexto(
            "node-a", escritor, list(endpoints), pedir)

        with parches[0], parches[1], parches[2]:
            with self.assertRaises(seguridad.ErrorAcceso) as error:
                servidor.reconciliar_seguridad()

        self.assertEqual("AUTH_REPLICA_CONFLICT", error.exception.codigo)
        self.assertFalse(any(
            metodo == "POST" for _base, metodo, _ruta in llamadas))

    def test_commit_seguridad_sin_quorum_es_resultado_incierto(self):
        escritor = self.almacen("node-a", "node-a")
        snapshot = self.inicializar_con_propietario(escritor)

        def caido(*_args, **_kwargs):
            raise TimeoutError("aislado")

        parches = self.contexto(
            "node-a", escritor,
            ["http://node-b:6060", "http://node-c:6060"], caido)
        with parches[0], parches[1], parches[2]:
            with self.assertRaises(seguridad.ErrorAcceso) as error:
                servidor.replicar_seguridad(snapshot)

        self.assertEqual("AUTH_COMMIT_UNCERTAIN", error.exception.codigo)

    def test_http_seguridad_v2_cifra_ack_y_rechaza_conflictos(self):
        token = "cluster-token-seguridad-" + "x" * 32
        origen = self.almacen("origen", "node-a")
        base = origen.inicializar_revision("system")
        posterior = self.inicializar_con_propietario(origen)
        receptor = self.almacen("receptor", "node-b")
        receptor.aplicar_replica(base)
        rama = self.almacen("rama", "node-c")
        rama.aplicar_replica(base)
        _usuario, no_escritor = rama.crear_propietario(
            "intruso", "Rama", HASH_CLAVE_PRUEBA)
        protocolo_servidor = seguridad.ProtocoloCluster(
            token, "node-b", [n["nombre"] for n in NODOS])
        cliente = seguridad.ProtocoloCluster(
            token, "node-a", [n["nombre"] for n in NODOS])
        cliente_no_escritor = seguridad.ProtocoloCluster(
            token, "node-c", [n["nombre"] for n in NODOS])
        marker_receptor = crear_marker_bootstrap(
            self.raiz / ".bootstrap-security-receptor")

        with mock.patch.object(local, "NODOS", NODOS), \
                mock.patch.object(local, "YO", "node-b"), \
                mock.patch.multiple(
                    servidor, CUENTAS=receptor, PROTOCOLO=protocolo_servidor,
                    MARCADOR_BOOTSTRAP_SEGURIDAD=str(marker_receptor)):
            httpd = servidor.Servidor(("127.0.0.1", 0), servidor.Manejador)
            worker = threading.Thread(target=httpd.serve_forever, daemon=True)
            worker.start()
            base_url = f"http://127.0.0.1:{httpd.server_port}"
            try:
                ruta = servidor.RUTA_SEGURIDAD_V2
                peticion = urllib.request.Request(base_url + ruta)
                for nombre, valor in cliente.firmar("GET", ruta).items():
                    peticion.add_header(nombre, valor)
                with urllib.request.urlopen(peticion, timeout=5) as respuesta:
                    mensaje = cliente.descifrar(
                        json.loads(respuesta.read())["payload"])
                self.assertEqual("node-b", mensaje["nodo"])
                self.assertTrue(mensaje["initialized"])
                self.assertEqual(
                    seguridad.AlmacenSeguridad.huella(base),
                    seguridad.AlmacenSeguridad.huella(mensaje["snapshot"]),
                )

                def replicar(snapshot, protocolo=cliente, nodo="node-a",
                             cuerpo_plano=False):
                    ruta_replica = servidor.RUTA_REPLICA_SEGURIDAD_V2
                    mensaje_replica = {
                        "capability": servidor.CAPACIDAD_SEGURIDAD_V2,
                        "nodo": nodo, "snapshot": snapshot,
                    }
                    contenido = (mensaje_replica if cuerpo_plano else {
                        "payload": protocolo.cifrar(mensaje_replica)})
                    crudo = json.dumps(
                        contenido, separators=(",", ":")).encode()
                    req = urllib.request.Request(
                        base_url + ruta_replica, data=crudo, method="POST")
                    req.add_header("Content-Type", "application/json")
                    for nombre, valor in protocolo.firmar(
                            "POST", ruta_replica, crudo).items():
                        req.add_header(nombre, valor)
                    try:
                        with urllib.request.urlopen(req, timeout=5) as respuesta:
                            return respuesta.status, json.loads(respuesta.read())
                    except urllib.error.HTTPError as error:
                        return error.code, json.loads(error.read())

                # Fresh install: un receptor consume su propio marker incluso
                # si el snapshot causal vacío ya le llegó antes del reintento.
                codigo, respuesta = replicar(base)
                self.assertEqual(200, codigo)
                ack_vacio = cliente.descifrar(respuesta["payload"])
                self.assertFalse(ack_vacio["replica_aplicada"])
                self.assertEqual(
                    seguridad.AlmacenSeguridad.huella(base),
                    ack_vacio["huella"],
                )
                self.assertFalse(marker_receptor.exists())

                codigo, respuesta = replicar(posterior)
                self.assertEqual(200, codigo)
                ack = cliente.descifrar(respuesta["payload"])
                self.assertEqual("node-b", ack["nodo"])
                self.assertTrue(ack["replica_aplicada"])
                self.assertEqual(
                    seguridad.AlmacenSeguridad.huella(posterior), ack["huella"])

                codigo, respuesta = replicar(posterior)
                self.assertEqual(200, codigo)
                self.assertFalse(
                    cliente.descifrar(respuesta["payload"])["replica_aplicada"])
                codigo, respuesta = replicar(base)
                self.assertEqual((409, "AUTH_REPLICA_STALE"),
                                 (codigo, respuesta["code"]))
                misma_revision = json.loads(json.dumps(posterior))
                misma_revision["users"][0]["display_name"] = "Otro nombre"
                codigo, respuesta = replicar(misma_revision)
                self.assertEqual(
                    (409, "AUTH_REPLICA_EQUAL_REVISION_CONFLICT"),
                    (codigo, respuesta["code"]),
                )
                codigo, respuesta = replicar(
                    posterior, protocolo=cliente, nodo="node-c")
                self.assertEqual((401, "CLUSTER_IDENTITY_MISMATCH"),
                                 (codigo, respuesta["code"]))
                huella_antes = seguridad.AlmacenSeguridad.huella(receptor.leer())
                codigo, respuesta = replicar(
                    no_escritor, cliente_no_escritor, "node-c")
                self.assertEqual((409, "AUTH_REPLICA_IDENTITY_INVALID"),
                                 (codigo, respuesta["code"]))
                self.assertEqual(
                    huella_antes,
                    seguridad.AlmacenSeguridad.huella(receptor.leer()),
                )
                codigo, respuesta = replicar(posterior, cuerpo_plano=True)
                self.assertEqual(400, codigo)
                self.assertEqual("INVALID_SECURITY_REPLICA", respuesta["code"])
            finally:
                httpd.shutdown()
                httpd.server_close()
                worker.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
