import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


PANEL = Path(__file__).resolve().parents[1] / "panel"
sys.path.insert(0, str(PANEL))

import configuracion  # noqa: E402
import local  # noqa: E402


class ConfiguracionTest(unittest.TestCase):
    def test_secreto_admite_fichero_y_rechaza_conflicto(self):
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp) / "secret"
            ruta.write_text("a" * 32 + "\n", encoding="utf-8")
            with patch.dict(os.environ, {
                "TEST_SECRET": "",
                "TEST_SECRET_FILE": str(ruta),
            }, clear=False):
                self.assertEqual("a" * 32, configuracion.secreto("TEST_SECRET"))
            with patch.dict(os.environ, {
                "TEST_SECRET": "directo",
                "TEST_SECRET_FILE": str(ruta),
            }, clear=False):
                with self.assertRaises(RuntimeError):
                    configuracion.secreto("TEST_SECRET")

    def test_secreto_rechaza_enlaces_y_ficheros_desproporcionados(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target"
            target.write_text("a" * 32, encoding="utf-8")
            link = root / "link"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("el sistema no permite crear symlinks")
            with patch.dict(os.environ, {"TEST_SECRET_FILE": str(link)}, clear=False):
                with self.assertRaisesRegex(RuntimeError, "fichero regular"):
                    configuracion.secreto("TEST_SECRET")
            oversized = root / "oversized"
            oversized.write_bytes(b"x" * (16 * 1024 + 1))
            with patch.dict(os.environ, {"TEST_SECRET_FILE": str(oversized)}, clear=False):
                with self.assertRaisesRegex(RuntimeError, "16 KiB"):
                    configuracion.secreto("TEST_SECRET")

    def test_pares_solo_admite_endpoints_sin_credenciales_ni_ruta(self):
        self.assertEqual(
            ["http://192.0.2.11:6060", "https://node-c.example:7443"],
            configuracion.urls_pares(
                "http://192.0.2.11:6060/,https://node-c.example:7443"),
        )
        for invalida in (
            "node-b:6060",
            "http://user:pass@node-b:6060",
            "http://node-b:6060/api",
            "http://node-b:6060?x=1",
            "http://node-b",
        ):
            with self.subTest(invalida=invalida), self.assertRaises(RuntimeError):
                configuracion.urls_pares(invalida)

    def test_topologia_malformada_falla_cerrada(self):
        with patch.dict(os.environ, {
            "FIP_NODOS": "node-a:192.0.2.10:eth0:no-numero",
        }, clear=False):
            with self.assertRaises(ValueError):
                local._nodos_de_entorno()
        with patch.dict(os.environ, {
            "FIP_NODOS": "node-a:192.0.2.10:eth0:150,node-a:192.0.2.11:eth0:100",
        }, clear=False):
            with self.assertRaises(ValueError):
                local._nodos_de_entorno()


if __name__ == "__main__":
    unittest.main()
