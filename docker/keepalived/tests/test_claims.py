import sys
import tempfile
import unittest
from pathlib import Path


PANEL = Path(__file__).resolve().parents[1] / "panel"
sys.path.insert(0, str(PANEL))

import pool  # noqa: E402


class ReclamacionesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.registro = pool.Pool(str(Path(self.tmp.name) / "pool.json"))
        datos = pool._vacio()
        datos["direcciones"] = [
            {
                "ip": "192.0.2.42",
                "vrid": 2,
                "estado": "libre",
                "servicio": None,
                "descripcion": "",
                "puertos": [],
                "chequeo": None,
                "preferente": None,
                "notas": "",
                "creada": pool.ahora(),
            },
            {
                "ip": "192.0.2.41",
                "vrid": 1,
                "estado": "libre",
                "servicio": None,
                "descripcion": "",
                "puertos": [],
                "chequeo": None,
                "preferente": None,
                "notas": "",
                "creada": pool.ahora(),
            },
        ]
        datos["dhcp_desde"] = 100
        self.registro.escribir(datos)

    @staticmethod
    def peticion(servicio="service-a", puerto=8080):
        return {
            "servicio": servicio,
            "descripcion": "Servicio de ejemplo",
            "puertos": [puerto],
            "chequeo": {"puerto": puerto, "ruta": "/alive"},
        }

    def test_coge_la_primera_ip_libre_y_no_decide_servidor(self):
        _, direccion, repetida = self.registro.reclamar(
            self.peticion(), "provision:00000001")

        self.assertFalse(repetida)
        self.assertEqual("192.0.2.41", direccion["ip"])
        self.assertEqual("en_uso", direccion["estado"])
        self.assertEqual("service-a", direccion["servicio"])
        self.assertIsNone(direccion["preferente"])

    def test_repetir_la_misma_operacion_devuelve_la_misma_ip(self):
        _, primera, _ = self.registro.reclamar(
            self.peticion(), "provision:00000002")
        _, segunda, repetida = self.registro.reclamar(
            self.peticion(), "provision:00000002")

        self.assertTrue(repetida)
        self.assertEqual(primera["ip"], segunda["ip"])
        self.assertEqual(
            1,
            len([d for d in self.registro.leer()["direcciones"]
                 if d["estado"] == "en_uso"]),
        )

    def test_reclama_primero_la_ip_apartada_para_el_mismo_servicio(self):
        datos = self.registro.leer()
        apartada = self.registro.buscar(datos, "192.0.2.42")
        apartada.update({
            "estado": "reservada",
            "servicio": "service-a",
            "descripcion": "Reserva de service-a",
        })
        self.registro.escribir(datos)

        _, direccion, _ = self.registro.reclamar(
            self.peticion(), "provision:00000012")

        self.assertEqual("192.0.2.42", direccion["ip"])
        self.assertEqual("en_uso", direccion["estado"])

    def test_no_entrega_a_otro_servicio_una_ip_apartada(self):
        datos = self.registro.leer()
        apartada = self.registro.buscar(datos, "192.0.2.42")
        apartada.update({
            "estado": "reservada",
            "servicio": "service-a",
        })
        self.registro.escribir(datos)

        _, direccion, _ = self.registro.reclamar(
            self.peticion("service-b", 8081), "provision:00000013")

        self.assertEqual("192.0.2.41", direccion["ip"])

    def test_al_liberar_restaurara_la_reserva(self):
        datos = self.registro.leer()
        apartada = self.registro.buscar(datos, "192.0.2.42")
        apartada.update({
            "estado": "reservada",
            "servicio": "service-a",
            "descripcion": "Reserva persistente",
        })
        self.registro.escribir(datos)
        self.registro.reclamar(self.peticion(), "provision:00000014")

        self.registro.liberar_reclamacion("provision:00000014")
        restaurada = self.registro.buscar(self.registro.leer(), "192.0.2.42")
        self.assertEqual("reservada", restaurada["estado"])
        self.assertEqual("service-a", restaurada["servicio"])
        self.assertEqual("Reserva persistente", restaurada["descripcion"])

    def test_solo_elimina_direcciones_libres(self):
        datos = self.registro.leer()
        apartada = self.registro.buscar(datos, "192.0.2.42")
        apartada.update({
            "estado": "reservada",
            "servicio": "service-a",
        })
        self.registro.escribir(datos)

        with self.assertRaisesRegex(pool.ErrorPool, "no está libre"):
            self.registro.baja("192.0.2.42")

        datos = self.registro.leer()
        libre = self.registro.buscar(datos, "192.0.2.41")
        self.assertEqual("libre", libre["estado"])
        self.registro.baja("192.0.2.41")
        self.assertIsNone(
            self.registro.buscar(self.registro.leer(), "192.0.2.41"))

    def test_no_admite_reutilizar_la_clave_con_otros_datos(self):
        self.registro.reclamar(self.peticion(), "provision:00000003")

        with self.assertRaisesRegex(pool.ErrorPool, "petición distinta"):
            self.registro.reclamar(
                self.peticion(servicio="service-b"),
                "provision:00000003",
            )

    def test_dos_operaciones_cogen_dos_direcciones(self):
        _, primera, _ = self.registro.reclamar(
            self.peticion("service-a", 8080), "provision:00000004")
        _, segunda, _ = self.registro.reclamar(
            self.peticion("service-b", 8081), "provision:00000005")

        self.assertNotEqual(primera["ip"], segunda["ip"])

    def test_no_duplica_un_servicio_aunque_cambie_la_clave(self):
        self.registro.reclamar(self.peticion(), "provision:00000006")

        with self.assertRaisesRegex(pool.ErrorPool, "ya usa"):
            self.registro.reclamar(self.peticion(), "provision:00000007")

    def test_liberar_es_idempotente_y_no_reutiliza_la_clave(self):
        peticion = self.peticion()
        self.registro.reclamar(peticion, "provision:00000008")

        _, ip, repetida = self.registro.liberar_reclamacion(
            "provision:00000008")
        self.assertFalse(repetida)
        self.assertEqual("192.0.2.41", ip)
        direccion = self.registro.buscar(self.registro.leer(), ip)
        self.assertEqual("libre", direccion["estado"])
        self.assertIsNone(direccion["servicio"])

        _, _, repetida = self.registro.liberar_reclamacion(
            "provision:00000008")
        self.assertTrue(repetida)
        with self.assertRaisesRegex(pool.ErrorPool, "ya fue liberada"):
            self.registro.reclamar(peticion, "provision:00000008")

    def test_falla_sin_direcciones_libres(self):
        self.registro.reclamar(
            self.peticion("service-a", 8080), "provision:00000009")
        self.registro.reclamar(
            self.peticion("service-b", 8081), "provision:00000010")

        with self.assertRaisesRegex(pool.ErrorPool, "No quedan"):
            self.registro.reclamar(
                self.peticion("service-c", 8082), "provision:00000011")


if __name__ == "__main__":
    unittest.main()
