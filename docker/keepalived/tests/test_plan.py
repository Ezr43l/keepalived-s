import sys
import unittest
from collections import Counter
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "panel"
sys.path.insert(0, str(PANEL))

import plan  # noqa: E402


NODOS = [
    {"nombre": "node-a", "ip": "192.0.2.10", "interfaz": "eth0", "prioridad": 150},
    {"nombre": "node-b", "ip": "192.0.2.11", "interfaz": "eth0", "prioridad": 100},
    {"nombre": "node-c", "ip": "192.0.2.12", "interfaz": "eth0", "prioridad": 50},
]


def direccion(servicio, ip, preferente=None):
    return {
        "servicio": servicio,
        "ip": ip,
        "preferente": preferente,
    }


class RepartoTest(unittest.TestCase):
    def test_sin_servidor_por_defecto_reparte_con_diferencia_maxima_de_uno(self):
        direcciones = [
            direccion("service-a", "192.0.2.101"),
            direccion("service-b", "192.0.2.102"),
            direccion("service-c", "192.0.2.103"),
            direccion("service-d", "192.0.2.104"),
            direccion("service-e", "192.0.2.105"),
        ]

        asignado = plan.repartir(direcciones, NODOS, set())
        cargas = Counter(asignado.values())

        self.assertLessEqual(max(cargas.values()) - min(cargas.values()), 1)

    def test_fallback_reparte_las_direcciones_del_nodo_caido(self):
        direcciones = [
            direccion("service-a", "192.0.2.101", "node-a"),
            direccion("service-b", "192.0.2.102", "node-a"),
            direccion("service-c", "192.0.2.103", "node-b"),
            direccion("service-d", "192.0.2.104", "node-c"),
        ]

        fallback = plan.reparto_fallback(direcciones, NODOS, set())

        self.assertEqual("node-b", fallback["service-a"]["node-a"])
        self.assertEqual("node-c", fallback["service-b"]["node-a"])

    def test_con_dos_nodos_el_superviviente_recoge_todo(self):
        direcciones = [
            direccion("service-a", "192.0.2.101", "node-a"),
            direccion("service-b", "192.0.2.102", "node-a"),
            direccion("service-c", "192.0.2.103", "node-b"),
        ]

        fallback = plan.reparto_fallback(direcciones, NODOS[:2], set())

        self.assertEqual("node-b", fallback["service-a"]["node-a"])
        self.assertEqual("node-b", fallback["service-b"]["node-a"])

    def test_respaldo_no_usa_un_nodo_en_mantenimiento(self):
        orden = plan.orden_para(
            "service-a", "node-a", NODOS, {"node-b"}, "node-b")

        self.assertEqual(["node-a", "node-c", "node-b"], orden)


if __name__ == "__main__":
    unittest.main()
