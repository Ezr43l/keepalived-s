import contextlib
import copy
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

import pool
import preflight_remoto
import seguridad


class PreflightRemotoTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        os.chmod(self.base, 0o700)

    @staticmethod
    def _pool_legacy():
        return {
            "version": 1,
            "actualizado": "2026-01-01T00:00:00+00:00",
            "dhcp_desde": 100,
            "mantenimiento": [],
            "direcciones": [],
            "reclamaciones": {},
        }

    @staticmethod
    def _security_legacy():
        return {
            "schema": 1,
            "revision": {
                "counter": 0, "timestamp": 0, "node": "",
            },
            "users": [],
            "api_keys": [],
        }

    @classmethod
    def _pool_causal(cls):
        normalizado = pool.Pool.seleccionar_dominante([cls._pool_legacy()])
        normalizado["revision"] = {
            "schema": 1,
            "clock": {"node-a": 1},
            "author": "node-a",
            "legacy_base": normalizado["revision"]["legacy_base"],
        }
        # Obliga a pasar por la misma validación que usará el preflight.
        return pool.Pool.seleccionar_dominante([normalizado])

    @classmethod
    def _security_causal(cls):
        normalizado = seguridad.AlmacenSeguridad.seleccionar_dominante(
            [cls._security_legacy()])
        normalizado["revision"] = {
            "schema": 1,
            "clock": {"node-a": 1},
            "author": "node-a",
            "actor": "system",
            "legacy_base": normalizado["revision"]["legacy_base"],
        }
        return seguridad.AlmacenSeguridad.seleccionar_dominante(
            [normalizado])

    def _guardar(self, nombre, contenido):
        ruta = self.base / nombre
        if isinstance(contenido, bytes):
            ruta.write_bytes(contenido)
        else:
            ruta.write_text(
                json.dumps(contenido, ensure_ascii=False, allow_nan=False),
                encoding="utf-8",
            )
        os.chmod(ruta, 0o600)
        return ruta.name

    def _manifest(self, topologia, observaciones, nombre="manifest.json"):
        return self._guardar(nombre, {
            "schema": 1,
            "topology": topologia,
            "writer": topologia[0] if topologia else "",
            "management_ips": [
                f"192.0.2.{10 + indice}" for indice, _ in enumerate(topologia)
            ],
            "observations": observaciones,
        })

    def _par_identico(self, prefijo, pool_snapshot=None,
                      security_snapshot=None):
        pool_snapshot = pool_snapshot or self._pool_legacy()
        security_snapshot = security_snapshot or self._security_legacy()
        return {
            "pool": self._guardar(
                f"{prefijo}.pool.json", copy.deepcopy(pool_snapshot)),
            "security": self._guardar(
                f"{prefijo}.security.json", copy.deepcopy(security_snapshot)),
        }

    def test_dos_legacy_divergentes_fallan_sin_desempate(self):
        pool_a = self._pool_legacy()
        pool_b = copy.deepcopy(pool_a)
        pool_b["dhcp_desde"] = 101
        estado_a = self._par_identico("node-a", pool_a)
        estado_b = self._par_identico("node-b", pool_b)
        manifiesto = self._manifest(["node-a", "node-b"], [
            {"node": "node-a", **estado_a},
            {"node": "node-b", **estado_b},
        ])

        with self.assertRaises(preflight_remoto.ErrorPreflight) as error:
            preflight_remoto.validar_preflight(self.base / manifiesto)

        self.assertEqual("PREFLIGHT_STATE_DIVERGENT", error.exception.codigo)
        self.assertEqual("pool", error.exception.recurso)
        self.assertEqual(preflight_remoto.EXIT_COHERENCIA, error.exception.salida)

    def test_json_truncado_falla_antes_de_declarar_quorum(self):
        estado_a = self._par_identico("node-a")
        estado_b = self._par_identico("node-b")
        estado_b["security"] = self._guardar(
            "node-b.security.truncated.json", b'{"schema":1,"users":[')
        manifiesto = self._manifest(["node-a", "node-b"], [
            {"node": "node-a", **estado_a},
            {"node": "node-b", **estado_b},
        ])

        with self.assertRaises(preflight_remoto.ErrorPreflight) as error:
            preflight_remoto.validar_preflight(self.base / manifiesto)

        self.assertEqual("PREFLIGHT_STATE_JSON_INVALID", error.exception.codigo)
        self.assertEqual("security", error.exception.recurso)
        self.assertEqual(preflight_remoto.EXIT_ESTADO, error.exception.salida)

    def test_vector_dominante_sobre_legacy_con_quorum_materializado(self):
        estado_a = self._par_identico("node-a")
        estado_b = self._par_identico(
            "node-b", self._pool_causal(), self._security_causal())
        manifiesto = self._manifest(
            ["node-a", "node-b", "node-c"], [
                {"node": "node-a", **estado_a},
                {"node": "node-b", **estado_b},
                {"node": "node-c", "pool": None, "security": None},
            ])

        salida = preflight_remoto.validar_preflight(
            self.base / manifiesto)

        self.assertTrue(salida["ok"])
        self.assertEqual(2, salida["quorum"])
        for recurso in ("pool", "security"):
            with self.subTest(recurso=recurso):
                estado = salida[recurso]
                self.assertEqual("recovery-ready", estado["status"])
                self.assertEqual("causal", estado["format"])
                self.assertEqual({"legacy": 1, "causal": 1}, estado["formats"])
                self.assertEqual(["node-b"], estado["dominant_nodes"])
                self.assertRegex(estado["fingerprint"], r"^[0-9a-f]{64}$")

    def test_rechaza_revision_causal_ajena_al_escritor_de_topologia(self):
        pool_ajeno = self._pool_causal()
        pool_ajeno["revision"]["clock"] = {"node-z": 1}
        pool_ajeno["revision"]["author"] = "node-z"
        seguridad_ajena = self._security_causal()
        seguridad_ajena["revision"]["clock"] = {"node-z": 1}
        seguridad_ajena["revision"]["author"] = "node-z"
        casos = (
            (pool_ajeno, self._security_causal(), "pool"),
            (self._pool_causal(), seguridad_ajena, "security"),
        )
        for indice, (pool_snapshot, seguridad_snapshot, recurso) in enumerate(casos):
            with self.subTest(recurso=recurso):
                estado_a = self._par_identico(
                    f"identity-{indice}-a", pool_snapshot, seguridad_snapshot)
                estado_b = self._par_identico(
                    f"identity-{indice}-b", pool_snapshot, seguridad_snapshot)
                manifiesto = self._manifest(["node-a", "node-b"], [
                    {"node": "node-a", **estado_a},
                    {"node": "node-b", **estado_b},
                ], f"manifest-identity-{indice}.json")
                with self.assertRaises(preflight_remoto.ErrorPreflight) as error:
                    preflight_remoto.validar_preflight(self.base / manifiesto)
                self.assertEqual(
                    "PREFLIGHT_STATE_IDENTITY_INVALID", error.exception.codigo)
                self.assertEqual(recurso, error.exception.recurso)

    def test_rechaza_vip_que_colisiona_con_ip_de_gestion(self):
        pool_colision = self._pool_legacy()
        pool_colision["direcciones"] = [{
            "ip": "192.0.2.10",
            "vrid": 51,
            "estado": "libre",
            "servicio": None,
            "descripcion": "",
            "puertos": [],
            "chequeo": None,
            "preferente": None,
            "notas": "",
            "creada": "2026-01-01T00:00:00+00:00",
        }]
        estado_a = self._par_identico("collision-a", pool_colision)
        estado_b = self._par_identico("collision-b", pool_colision)
        manifiesto = self._manifest(["node-a", "node-b"], [
            {"node": "node-a", **estado_a},
            {"node": "node-b", **estado_b},
        ], "manifest-network-collision.json")

        with self.assertRaises(preflight_remoto.ErrorPreflight) as error:
            preflight_remoto.validar_preflight(self.base / manifiesto)
        self.assertEqual(
            "PREFLIGHT_STATE_NETWORK_INVALID", error.exception.codigo)
        self.assertEqual("pool", error.exception.recurso)

    def test_ausencia_solo_permite_recovery_con_quorum_materializado(self):
        estado_a = self._par_identico("node-a")
        manifiesto_insuficiente = self._manifest(
            ["node-a", "node-b", "node-c"], [
                {"node": "node-a", **estado_a},
                {"node": "node-b", "pool": None, "security": None},
                {"node": "node-c", "pool": None, "security": None},
            ], "manifest-insuficiente.json")

        with self.assertRaises(preflight_remoto.ErrorPreflight) as error:
            preflight_remoto.validar_preflight(
                self.base / manifiesto_insuficiente)
        self.assertEqual(
            "PREFLIGHT_MATERIALIZED_QUORUM_UNAVAILABLE",
            error.exception.codigo,
        )

        estado_b = self._par_identico("node-b")
        manifiesto_recuperable = self._manifest(
            ["node-a", "node-b", "node-c"], [
                {"node": "node-a", **estado_a},
                {"node": "node-b", **estado_b},
                {"node": "node-c", "pool": None, "security": None},
            ], "manifest-recuperable.json")
        salida = preflight_remoto.validar_preflight(
            self.base / manifiesto_recuperable)
        self.assertEqual("recovery-ready", salida["pool"]["status"])
        self.assertEqual("recovery-ready", salida["security"]["status"])
        self.assertEqual("legacy", salida["pool"]["format"])
        self.assertEqual("legacy", salida["security"]["format"])
        self.assertEqual(
            ["node-a", "node-b"], salida["pool"]["dominant_nodes"])

    def test_fresh_all_absent_requiere_autorizacion_explicita(self):
        manifiesto = self._manifest(
            ["node-a", "node-b", "node-c"], [
                {"node": "node-a", "pool": None, "security": None},
                {"node": "node-b", "pool": None, "security": None},
            ])
        with self.assertRaises(preflight_remoto.ErrorPreflight) as error:
            preflight_remoto.validar_preflight(self.base / manifiesto)
        self.assertEqual(
            "PREFLIGHT_FRESH_EMPTY_NOT_ALLOWED", error.exception.codigo)

        salida = preflight_remoto.validar_preflight(
            self.base / manifiesto, permitir_fresh=True)
        self.assertEqual("fresh-empty", salida["pool"]["status"])
        self.assertEqual("fresh-empty", salida["security"]["status"])
        self.assertIsNone(salida["security"]["fingerprint"])

    def test_campos_omitidos_no_votan_y_identidades_no_se_duplican(self):
        manifiesto_sin_quorum = self._manifest(
            ["node-a", "node-b", "node-c"], [
                {"node": "node-a", "pool": None, "security": None},
                {"node": "node-b", "security": None},
            ], "manifest-omitido.json")
        with self.assertRaises(preflight_remoto.ErrorPreflight) as error:
            preflight_remoto.validar_preflight(
                self.base / manifiesto_sin_quorum, permitir_fresh=True)
        self.assertEqual(
            "PREFLIGHT_OBSERVATION_QUORUM_UNAVAILABLE",
            error.exception.codigo,
        )

        for indice, (topologia, observaciones) in enumerate((
            (["node-a", "node-a"], []),
            (["node-a", "node-b"], [
                {"node": "node-a", "pool": None, "security": None},
                {"node": "node-a", "pool": None, "security": None},
            ]),
        )):
            with self.subTest(indice=indice):
                manifiesto = self._manifest(
                    topologia, observaciones, f"manifest-duplicado-{indice}.json")
                with self.assertRaises(preflight_remoto.ErrorPreflight) as error:
                    preflight_remoto.validar_preflight(
                        self.base / manifiesto, permitir_fresh=True)
                self.assertEqual(
                    "PREFLIGHT_MANIFEST_INVALID", error.exception.codigo)

        compartido = self._par_identico("compartido")
        manifiesto = self._manifest(
            ["node-a", "node-b"], [
                {"node": "node-a", **compartido},
                {"node": "node-b", "pool": compartido["pool"],
                 "security": None},
            ], "manifest-ruta-duplicada.json")
        with self.assertRaises(preflight_remoto.ErrorPreflight) as error:
            preflight_remoto.validar_preflight(
                self.base / manifiesto, permitir_fresh=True)
        self.assertEqual("PREFLIGHT_PATH_DUPLICATE", error.exception.codigo)

    @unittest.skipUnless(hasattr(os, "symlink"), "requiere symlink")
    def test_rechaza_symlink_y_payload_sobredimensionado(self):
        estado = self._par_identico("node-a")
        objetivo = self._guardar("pool-real.json", self._pool_legacy())
        enlace = self.base / "pool-link.json"
        os.symlink(self.base / objetivo, enlace)
        estado["pool"] = enlace.name
        manifiesto = self._manifest(["node-a"], [
            {"node": "node-a", **estado},
        ], "manifest-link.json")
        with self.assertRaises(preflight_remoto.ErrorPreflight) as error:
            preflight_remoto.validar_preflight(self.base / manifiesto)
        self.assertEqual("PREFLIGHT_STATE_FILE_UNSAFE", error.exception.codigo)

        modo_abierto = self._guardar("pool-0644.json", self._pool_legacy())
        os.chmod(self.base / modo_abierto, 0o644)
        estado["pool"] = modo_abierto
        manifiesto = self._manifest(["node-a"], [
            {"node": "node-a", **estado},
        ], "manifest-mode.json")
        with self.assertRaises(preflight_remoto.ErrorPreflight) as error:
            preflight_remoto.validar_preflight(self.base / manifiesto)
        self.assertEqual("PREFLIGHT_STATE_FILE_UNSAFE", error.exception.codigo)

        original = self._guardar("pool-hardlink-original.json", self._pool_legacy())
        hardlink = self.base / "pool-hardlink.json"
        os.link(self.base / original, hardlink)
        estado["pool"] = hardlink.name
        manifiesto = self._manifest(["node-a"], [
            {"node": "node-a", **estado},
        ], "manifest-hardlink.json")
        with self.assertRaises(preflight_remoto.ErrorPreflight) as error:
            preflight_remoto.validar_preflight(self.base / manifiesto)
        self.assertEqual("PREFLIGHT_STATE_FILE_UNSAFE", error.exception.codigo)

        enorme = self._guardar(
            "pool-enorme.json",
            b"{" + b" " * (512 * 1024) + b"}",
        )
        estado["pool"] = enorme
        manifiesto = self._manifest(["node-a"], [
            {"node": "node-a", **estado},
        ], "manifest-enorme.json")
        with self.assertRaises(preflight_remoto.ErrorPreflight) as error:
            preflight_remoto.validar_preflight(self.base / manifiesto)
        self.assertEqual("PREFLIGHT_STATE_TOO_LARGE", error.exception.codigo)

    def test_cli_emite_solo_metadata_y_codigo_estable(self):
        secreto_trampa = "NO DEBE APARECER / EN LA SALIDA"
        pool_snapshot = self._pool_legacy()
        pool_snapshot["mantenimiento"] = [secreto_trampa]
        # El nombre no es válido en el esquema y la salida tampoco debe repetirlo.
        estado = self._par_identico("node-a", pool_snapshot)
        manifiesto = self._manifest(["node-a"], [
            {"node": "node-a", **estado},
        ])
        salida = io.StringIO()
        with contextlib.redirect_stdout(salida):
            codigo = preflight_remoto.main([
                "--manifest", str(self.base / manifiesto),
            ])
        documento = json.loads(salida.getvalue())

        self.assertEqual(preflight_remoto.EXIT_ESTADO, codigo)
        self.assertFalse(documento["ok"])
        self.assertEqual("PREFLIGHT_STATE_INVALID", documento["error"]["code"])
        self.assertNotIn(secreto_trampa, salida.getvalue())


if __name__ == "__main__":
    unittest.main()
