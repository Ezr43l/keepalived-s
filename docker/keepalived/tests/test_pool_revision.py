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

import pool  # noqa: E402


class RevisionPoolTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.raiz = Path(self.tmp.name)

    def registro(self, nombre, autor):
        return pool.Pool(str(self.raiz / nombre), autor=autor)

    @staticmethod
    def vacio(marca="2026-01-01T00:00:00+00:00"):
        datos = pool._vacio()
        datos["actualizado"] = marca
        return datos

    @staticmethod
    def entrada(ip="192.0.2.10", vrid=1):
        return {"ip": ip, "vrid": vrid}

    @staticmethod
    def peticion():
        return {
            "servicio": "service-a",
            "descripcion": "Servicio de prueba",
            "puertos": [8080],
            "chequeo": {"puerto": 8080, "ruta": "/alive"},
        }

    @staticmethod
    def codigo(error):
        return getattr(error.exception, "codigo", None)

    def test_vacios_legacy_con_horas_distintas_son_equivalentes(self):
        primero = self.vacio("2026-01-01T00:00:00+00:00")
        segundo = self.vacio("2026-01-02T00:00:00+00:00")
        primero.pop("revision")
        segundo.pop("revision")

        self.assertEqual(pool.Pool.huella(primero), pool.Pool.huella(segundo))
        self.assertEqual(
            "identica", pool.Pool.clasificar_replica(primero, segundo))
        elegido = pool.Pool.seleccionar_dominante([segundo, primero])
        self.assertEqual("2026-01-02T00:00:00+00:00", elegido["actualizado"])
        self.assertEqual(1, elegido["revision"]["schema"])
        self.assertEqual({}, elegido["revision"]["clock"])
        self.assertEqual("legacy", elegido["revision"]["author"])
        self.assertRegex(elegido["revision"]["legacy_base"], r"^[0-9a-f]{64}$")

    def test_legacy_se_normaliza_y_migra_en_la_primera_escritura(self):
        ruta = self.raiz / "pool.json"
        legacy = self.vacio()
        legacy.pop("revision")
        legacy["vrids_quemados"] = [42]
        ruta.write_text(json.dumps(legacy), encoding="utf-8")
        registro = pool.Pool(str(ruta), autor="node-a")

        leido = registro.leer()
        self.assertNotIn("vrids_quemados", leido)
        self.assertEqual({}, leido["revision"]["clock"])
        self.assertNotIn("revision", json.loads(ruta.read_text(encoding="utf-8")))

        base_legacy = leido["revision"]["legacy_base"]
        registro.escribir(leido, marcar_hora=False)
        persistido = json.loads(ruta.read_text(encoding="utf-8"))
        self.assertEqual(
            {"schema": 1, "clock": {"node-a": 1}, "author": "node-a",
             "legacy_base": base_legacy},
            persistido["revision"],
        )

    def test_replica_legacy_equivalente_migra_sin_conflicto_por_la_hora(self):
        ruta = self.raiz / "pool.json"
        local = self.vacio("2026-01-01T00:00:00+00:00")
        entrante = self.vacio("2026-01-02T00:00:00+00:00")
        local.pop("revision")
        entrante.pop("revision")
        ruta.write_text(json.dumps(local), encoding="utf-8")
        registro = pool.Pool(str(ruta), autor="node-a")

        self.assertFalse(registro.aplicar_replica(entrante))
        persistido = json.loads(ruta.read_text(encoding="utf-8"))
        self.assertEqual("legacy", persistido["revision"]["author"])
        self.assertEqual({}, persistido["revision"]["clock"])
        self.assertEqual("2026-01-01T00:00:00+00:00", persistido["actualizado"])

    def test_vector_solo_domina_el_mismo_contenido_legacy(self):
        legacy_a = self.vacio("2026-01-01T00:00:00+00:00")
        legacy_a.pop("revision")
        misma_a = deepcopy(legacy_a)
        misma_a["actualizado"] = "2026-01-02T00:00:00+00:00"
        legacy_b = deepcopy(legacy_a)
        legacy_b["dhcp_desde"] = 120
        registro = self.registro("pool.json", "node-a")
        vector_a = registro.escribir(deepcopy(legacy_a), marcar_hora=False)

        self.assertEqual(
            "nueva", pool.Pool.clasificar_replica(misma_a, vector_a))
        self.assertEqual(
            "conflicto_concurrente",
            pool.Pool.clasificar_replica(legacy_b, vector_a),
        )
        with self.assertRaises(pool.ErrorRevisionPool) as error:
            pool.Pool.seleccionar_dominante([legacy_b, vector_a])
        self.assertEqual("POOL_REPLICA_CONFLICT", self.codigo(error))

    def test_todas_las_mutaciones_reales_avanzan_y_los_reintentos_no(self):
        registro = self.registro("pool.json", "node-a")
        inicial = self.vacio()
        registro.escribir(inicial, marcar_hora=False)
        self.assertEqual(1, inicial["revision"]["clock"]["node-a"])

        registro.alta(self.entrada())
        self.assertEqual(2, registro.leer()["revision"]["clock"]["node-a"])
        registro.modificar("192.0.2.10", {"descripcion": "Actualizada"})
        self.assertEqual(3, registro.leer()["revision"]["clock"]["node-a"])
        registro.elegir_servidor("192.0.2.10", "node-b", {"node-a", "node-b"})
        self.assertEqual(4, registro.leer()["revision"]["clock"]["node-a"])

        datos, _, repetida = registro.reclamar(
            self.peticion(), "provision:revision-1")
        self.assertFalse(repetida)
        self.assertEqual(5, datos["revision"]["clock"]["node-a"])
        datos, _, repetida = registro.reclamar(
            self.peticion(), "provision:revision-1")
        self.assertTrue(repetida)
        self.assertEqual(5, datos["revision"]["clock"]["node-a"])

        datos, _, repetida = registro.liberar_reclamacion(
            "provision:revision-1")
        self.assertFalse(repetida)
        self.assertEqual(6, datos["revision"]["clock"]["node-a"])
        datos, _, repetida = registro.liberar_reclamacion(
            "provision:revision-1")
        self.assertTrue(repetida)
        self.assertEqual(6, datos["revision"]["clock"]["node-a"])

        registro.baja("192.0.2.10")
        self.assertEqual(7, registro.leer()["revision"]["clock"]["node-a"])
        datos = registro.leer()
        pool.marcar_mantenimiento(datos, "node-b", True)
        registro.escribir(datos)
        self.assertEqual(8, registro.leer()["revision"]["clock"]["node-a"])

    def test_replica_posterior_se_aplica_sin_crear_otra_revision(self):
        origen = self.registro("origen.json", "node-a")
        replica = self.registro("replica.json", "node-b")
        base = origen.escribir(self.vacio(), marcar_hora=False)

        self.assertTrue(replica.aplicar_replica(base))
        self.assertFalse(replica.aplicar_replica(deepcopy(base)))
        origen.alta(self.entrada())
        revision_origen = deepcopy(origen.leer()["revision"])
        self.assertTrue(replica.aplicar_replica(origen.leer()))
        self.assertEqual(revision_origen, replica.leer()["revision"])

        datos_replica = replica.leer()
        datos_replica["dhcp_desde"] = 110
        replica.escribir(datos_replica)
        self.assertEqual(
            {"node-a": 2, "node-b": 1},
            datos_replica["revision"]["clock"],
        )
        self.assertTrue(origen.aplicar_replica(datos_replica))
        self.assertEqual(datos_replica["revision"], origen.leer()["revision"])

    def test_replica_obsoleta_se_rechaza(self):
        registro = self.registro("pool.json", "node-a")
        antigua = deepcopy(registro.escribir(self.vacio(), marcar_hora=False))
        registro.alta(self.entrada())

        with self.assertRaises(pool.ErrorRevisionPool) as error:
            registro.aplicar_replica(antigua)
        self.assertEqual("POOL_REPLICA_STALE", self.codigo(error))

    def test_escrituras_concurrentes_se_rechazan_en_ambos_sentidos(self):
        primero = self.registro("primero.json", "node-a")
        segundo = self.registro("segundo.json", "node-b")
        base = primero.escribir(self.vacio(), marcar_hora=False)
        segundo.aplicar_replica(base)

        datos_a = primero.leer()
        datos_a["dhcp_desde"] = 110
        primero.escribir(datos_a)
        datos_b = segundo.leer()
        datos_b["dhcp_desde"] = 120
        segundo.escribir(datos_b)

        for destino, entrante in ((primero, datos_b), (segundo, datos_a)):
            with self.assertRaises(pool.ErrorRevisionPool) as error:
                destino.aplicar_replica(entrante)
            self.assertEqual("POOL_REPLICA_CONCURRENT", self.codigo(error))

    def test_misma_revision_con_otro_contenido_falla_cerrado(self):
        registro = self.registro("pool.json", "node-a")
        original = registro.escribir(self.vacio(), marcar_hora=False)
        alterado = deepcopy(original)
        alterado["dhcp_desde"] = 110

        with self.assertRaises(pool.ErrorRevisionPool) as error:
            registro.aplicar_replica(alterado)
        self.assertEqual(
            "POOL_REPLICA_EQUAL_REVISION_CONFLICT", self.codigo(error))

    def test_mutacion_basada_en_snapshot_obsoleto_no_pisa_estado(self):
        registro = self.registro("pool.json", "node-a")
        registro.escribir(self.vacio(), marcar_hora=False)
        primera = registro.leer()
        obsoleta = registro.leer()
        primera["dhcp_desde"] = 110
        registro.escribir(primera)
        obsoleta["dhcp_desde"] = 120

        with self.assertRaises(pool.ErrorRevisionPool) as error:
            registro.escribir(obsoleta)
        self.assertEqual("POOL_LOCAL_STALE", self.codigo(error))
        self.assertEqual(110, registro.leer()["dhcp_desde"])

    def test_seleccion_solo_acepta_un_dominante_causal(self):
        base = self.vacio()
        base_legacy = base["revision"]["legacy_base"]
        base["revision"] = {
            "schema": 1, "clock": {"node-a": 1}, "author": "node-a",
            "legacy_base": base_legacy}
        rama_a = deepcopy(base)
        rama_a["dhcp_desde"] = 110
        rama_a["revision"] = {
            "schema": 1, "clock": {"node-a": 2}, "author": "node-a",
            "legacy_base": base_legacy}
        rama_b = deepcopy(base)
        rama_b["dhcp_desde"] = 120
        rama_b["revision"] = {
            "schema": 1,
            "clock": {"node-a": 1, "node-b": 1},
            "author": "node-b",
            "legacy_base": base_legacy,
        }
        fusion = deepcopy(rama_a)
        fusion["revision"] = {
            "schema": 1,
            "clock": {"node-a": 2, "node-b": 1},
            "author": "node-a",
            "legacy_base": base_legacy,
        }

        elegido = pool.Pool.seleccionar_dominante([rama_a, rama_b, fusion])
        self.assertEqual(fusion["revision"], elegido["revision"])
        with self.assertRaises(pool.ErrorRevisionPool) as error:
            pool.Pool.seleccionar_dominante([rama_a, rama_b])
        self.assertEqual("POOL_REPLICA_CONFLICT", self.codigo(error))

    def test_revision_malformada_se_rechaza(self):
        casos = [
            {"schema": True, "clock": {}, "author": "legacy"},
            {"schema": 1, "clock": {"node-a": True}, "author": "node-a"},
            {"schema": 1, "clock": {"node-a": 1}, "author": "node-b"},
            {"schema": 1, "clock": {}, "author": "node-a"},
            {"schema": 2, "clock": {}, "author": "legacy"},
        ]
        for revision in casos:
            with self.subTest(revision=revision):
                datos = self.vacio()
                datos["revision"] = revision
                with self.assertRaises(pool.ErrorPool):
                    pool.Pool.huella(datos)

    def test_fallo_atomico_conserva_fichero_revision_y_temporales(self):
        registro = self.registro("pool.json", "node-a")
        registro.escribir(self.vacio(), marcar_hora=False)
        antes = Path(registro.ruta).read_bytes()
        candidato = registro.leer()
        revision_antes = deepcopy(candidato["revision"])
        candidato["dhcp_desde"] = 110

        with mock.patch.object(pool.os, "replace", side_effect=OSError("fallo")):
            with self.assertRaises(OSError):
                registro.escribir(candidato)

        self.assertEqual(antes, Path(registro.ruta).read_bytes())
        self.assertEqual(revision_antes, candidato["revision"])
        self.assertEqual([], list(self.raiz.glob("*.tmp")))

    def test_bootstrap_causal_es_una_sola_escritura_y_reintenta_pre_replace(self):
        registro = self.registro("bootstrap.json", "node-a")
        legacy = self.vacio()
        original = registro._escribir_atomico
        observados = []

        def observar(datos):
            observados.append(deepcopy(datos))
            return original(datos)

        with mock.patch.object(
                registro, "_escribir_atomico", side_effect=observar):
            inicial = registro.inicializar_desde_candidato(legacy)
        self.assertEqual(1, len(observados))
        self.assertEqual({"node-a": 1}, inicial["revision"]["clock"])
        self.assertNotEqual("legacy", observados[0]["revision"]["author"])

        fallido = self.registro("bootstrap-pre-replace.json", "node-a")
        with mock.patch.object(
                pool.os, "replace", side_effect=OSError("corte pre-rename")):
            with self.assertRaises(OSError):
                fallido.inicializar_desde_candidato(self.vacio())
        self.assertFalse(Path(fallido.ruta).exists())
        recuperado = fallido.inicializar_desde_candidato(self.vacio())
        self.assertEqual({"node-a": 1}, recuperado["revision"]["clock"])

    @unittest.skipUnless(os.name == "posix", "fsync de directorio POSIX")
    def test_bootstrap_post_replace_incierto_se_reanuda_sin_segunda_escritura(self):
        registro = self.registro("bootstrap-post-replace.json", "node-a")
        fsync_real = pool.os.fsync

        def fsync_con_eio(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(errno.EIO, "corte post-rename")
            return fsync_real(fd)

        with mock.patch.object(pool.os, "fsync", side_effect=fsync_con_eio):
            with self.assertRaises(pool.ErrorCommitPool):
                registro.inicializar_desde_candidato(self.vacio())
        self.assertEqual(
            {"node-a": 1}, registro.leer()["revision"]["clock"])
        with mock.patch.object(
                registro, "_escribir_atomico",
                side_effect=AssertionError("no debe reescribir")):
            reanudado = registro.inicializar_desde_candidato(self.vacio())
        self.assertEqual({"node-a": 1}, reanudado["revision"]["clock"])

    def test_limite_de_512_kib_se_aplica_al_entrante_y_al_fichero(self):
        registro = self.registro("pool.json", "node-a")
        enorme = self.vacio()
        enorme["actualizado"] = "x" * (pool._MAX_SNAPSHOT_BYTES + 1)
        with self.assertRaisesRegex(pool.ErrorPool, "512 KiB"):
            registro.escribir(enorme)
        self.assertFalse(Path(registro.ruta).exists())

        Path(registro.ruta).write_bytes(b" " * (pool._MAX_SNAPSHOT_BYTES + 1))
        with self.assertRaisesRegex(pool.ErrorPool, "512 KiB"):
            registro.leer()

    def test_servicios_que_renderizan_misma_instancia_vrrp_se_rechazan(self):
        datos = self.vacio()
        datos["direcciones"] = [
            {
                "ip": "192.0.2.10", "vrid": 10, "estado": "en_uso",
                "servicio": "foo-bar", "descripcion": "",
                "puertos": [8080],
                "chequeo": {"puerto": 8080, "ruta": "/health"},
                "preferente": None, "notas": "",
            },
            {
                "ip": "192.0.2.11", "vrid": 11, "estado": "en_uso",
                "servicio": "foo_bar", "descripcion": "",
                "puertos": [8081],
                "chequeo": {"puerto": 8081, "ruta": "/health"},
                "preferente": None, "notas": "",
            },
        ]
        self.assertEqual("FOO_BAR", pool.identificador_vrrp("foo-bar"))
        self.assertEqual("FOO_BAR", pool.identificador_vrrp("foo_bar"))

        registro = self.registro("colision.json", "node-a")
        with self.assertRaisesRegex(pool.ErrorPool, "colisiona en keepalived"):
            registro.escribir(datos, marcar_hora=False)

    def test_esquema_rechaza_campos_desconocidos_y_acota_colecciones(self):
        desconocido = self.vacio()
        desconocido["dato_inyectado"] = "x"
        with self.assertRaisesRegex(pool.ErrorPool, "campos desconocidos"):
            pool.Pool.huella(desconocido)

        casos = []
        mantenimiento = self.vacio()
        mantenimiento["mantenimiento"] = [
            f"node-{indice}" for indice in range(pool._MAX_MANTENIMIENTO + 1)]
        casos.append((mantenimiento, "mantenimiento"))

        direcciones = self.vacio()
        direcciones["direcciones"] = [{}] * (pool._MAX_DIRECCIONES + 1)
        casos.append((direcciones, "direcciones"))

        reclamaciones = self.vacio()
        reclamaciones["reclamaciones"] = {
            f"claim:{indice:08d}": {} for indice in range(pool._MAX_RECLAMACIONES + 1)}
        casos.append((reclamaciones, "reclamaciones"))

        for datos, fragmento in casos:
            with self.subTest(fragmento=fragmento):
                self.assertTrue(any(
                    fragmento in problema and "más de" in problema
                    for problema in pool.validar(datos)))

        registro = self.registro("acotado.json", "node-a")
        with self.assertRaisesRegex(pool.ErrorPool, "notas"):
            registro.alta({
                **self.entrada(),
                "notas": "x" * (pool._MAX_NOTAS + 1),
            })
        with self.assertRaisesRegex(pool.ErrorPool, "puertos"):
            registro.alta({
                **self.entrada(),
                "puertos": list(range(1, pool._MAX_PUERTOS + 2)),
            })

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink no disponible")
    def test_rechaza_pool_symlink_sin_leer_su_objetivo(self):
        victima = self.raiz / "victima.json"
        victima.write_text(json.dumps({"secreto": "no-leer"}), encoding="utf-8")
        enlace = self.raiz / "pool.json"
        enlace.symlink_to(victima)

        with self.assertRaisesRegex(pool.ErrorPool, "enlace simbólico"):
            pool.Pool(str(enlace), autor="node-a").leer()

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO no disponible")
    def test_rechaza_fifo_antes_de_abrirlo(self):
        ruta = self.raiz / "pool.json"
        os.mkfifo(ruta)

        with self.assertRaisesRegex(pool.ErrorPool, "fichero regular"):
            pool.Pool(str(ruta), autor="node-a").leer()

    @unittest.skipUnless(os.name == "posix", "permisos POSIX")
    def test_normaliza_propietario_modo_y_lockfile_a_0600(self):
        ruta = self.raiz / "pool.json"
        os.chmod(self.raiz, 0o777)
        ruta.write_text(json.dumps(self.vacio()), encoding="utf-8")
        os.chmod(ruta, 0o644)
        if os.geteuid() == 0:
            os.chown(ruta, 12345, 12345)

        registro = pool.Pool(str(ruta), autor="node-a")
        registro.leer()

        self.assertEqual(0o700, stat.S_IMODE(self.raiz.stat().st_mode))
        for protegida in (ruta, Path(registro.ruta_candado)):
            estado = protegida.stat()
            self.assertEqual(os.geteuid(), estado.st_uid)
            self.assertEqual(0o600, stat.S_IMODE(estado.st_mode))

    @unittest.skipUnless(pool.fcntl is not None, "flock no disponible")
    def test_dos_instancias_no_pueden_confirmar_escrituras_concurrentes(self):
        ruta = str(self.raiz / "pool.json")
        semilla = pool.Pool(ruta, autor="seed")
        semilla.escribir(self.vacio(), marcar_hora=False)
        primero = pool.Pool(ruta, autor="node-a")
        segundo = pool.Pool(ruta, autor="node-b")
        datos_a = primero.leer()
        datos_b = segundo.leer()
        datos_a["dhcp_desde"] = 110
        datos_b["dhcp_desde"] = 120
        barrera = threading.Barrier(2)
        resultados = []
        candado_resultados = threading.Lock()

        def escribir(registro, datos):
            barrera.wait(timeout=5)
            try:
                registro.escribir(datos, marcar_hora=False)
                resultado = "ok"
            except pool.ErrorRevisionPool as error:
                resultado = error.codigo
            with candado_resultados:
                resultados.append(resultado)

        hilos = [
            threading.Thread(target=escribir, args=(primero, datos_a)),
            threading.Thread(target=escribir, args=(segundo, datos_b)),
        ]
        for hilo in hilos:
            hilo.start()
        for hilo in hilos:
            hilo.join(timeout=10)
            self.assertFalse(hilo.is_alive())

        self.assertEqual(1, resultados.count("ok"))
        self.assertEqual(1, resultados.count("POOL_LOCAL_STALE"))
        self.assertIn(semilla.leer()["dhcp_desde"], (110, 120))

    @unittest.skipUnless(os.name == "posix", "fsync de directorio POSIX")
    def test_fsync_eio_del_directorio_no_se_oculta(self):
        registro = self.registro("pool.json", "node-a")
        registro.escribir(self.vacio(), marcar_hora=False)
        candidato = registro.leer()
        candidato["dhcp_desde"] = 110
        fsync_real = pool.os.fsync

        def fsync_con_eio(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(errno.EIO, "fallo de almacenamiento")
            return fsync_real(fd)

        with mock.patch.object(pool.os, "fsync", side_effect=fsync_con_eio):
            with self.assertRaises(pool.ErrorCommitPool) as error:
                registro.escribir(candidato)
        self.assertEqual(
            "POOL_LOCAL_COMMIT_UNCERTAIN", error.exception.codigo)
        # No se intenta un rollback tras rename: el nuevo snapshot puede ser el
        # visible y la anti-entropía decidirá causalmente cómo convergerlo.
        visible = registro.leer()
        self.assertEqual(110, visible["dhcp_desde"])
        self.assertEqual({"node-a": 2}, visible["revision"]["clock"])

    @unittest.skipUnless(os.name == "posix", "fsync de directorio POSIX")
    def test_fsync_no_soportado_del_directorio_se_tolera(self):
        registro = self.registro("pool.json", "node-a")
        registro.escribir(self.vacio(), marcar_hora=False)
        candidato = registro.leer()
        candidato["dhcp_desde"] = 110
        fsync_real = pool.os.fsync

        def fsync_no_soportado(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError(errno.EINVAL, "operación no soportada")
            return fsync_real(fd)

        with mock.patch.object(pool.os, "fsync", side_effect=fsync_no_soportado):
            registro.escribir(candidato)
        self.assertEqual(110, registro.leer()["dhcp_desde"])


if __name__ == "__main__":
    unittest.main()
