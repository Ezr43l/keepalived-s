import json
import sys
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock


PANEL = Path(__file__).resolve().parents[1] / "panel"
sys.path.insert(0, str(PANEL))

import local  # noqa: E402
import servidor  # noqa: E402


class Respuesta:
    status = 204

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


class SaludLocalTest(unittest.TestCase):
    def test_salud_publica_no_revela_topologia(self):
        httpd = servidor.Servidor(("127.0.0.1", 0), servidor.Manejador)
        worker = threading.Thread(target=httpd.serve_forever, daemon=True)
        worker.start()
        try:
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{httpd.server_port}/api/health", timeout=5) as respuesta:
                payload = json.loads(respuesta.read())
            self.assertEqual({"estado", "version"}, set(payload))
            self.assertEqual("1.0.7", payload["version"]["version"])
        finally:
            httpd.shutdown()
            httpd.server_close()
            worker.join(timeout=5)

    def test_mide_el_tiempo_de_respuesta(self):
        with mock.patch.object(local.time, "perf_counter", side_effect=[10, 10.0123]), \
                mock.patch.object(local.urllib.request, "urlopen", return_value=Respuesta()):
            resultado = local.comprobar({"puerto": 8080, "ruta": "/health"})

        self.assertTrue(resultado["sano"])
        self.assertEqual("HTTP 204", resultado["detalle"])
        self.assertEqual(12.3, resultado["respuesta_ms"])

    def test_mide_tambien_un_fallo(self):
        with mock.patch.object(local.time, "perf_counter", side_effect=[20, 20.25]), \
                mock.patch.object(
                    local.urllib.request,
                    "urlopen",
                    side_effect=urllib.error.URLError("sin conexión"),
                ):
            resultado = local.comprobar({"puerto": 8080, "ruta": "/health"})

        self.assertFalse(resultado["sano"])
        self.assertEqual("URLError", resultado["detalle"])
        self.assertEqual(250.0, resultado["respuesta_ms"])

    def test_exige_aceptar_cada_direccion_sin_respaldo(self):
        seguridad = {"si_lo_paras": [
            {"ip": "192.0.2.101", "sin_red": True},
            {"ip": "192.0.2.102", "sin_red": False},
            {"ip": "192.0.2.103", "sin_red": True},
        ]}

        pendientes = servidor.riesgos_mantenimiento_pendientes(
            seguridad, ["192.0.2.101"])

        self.assertEqual(["192.0.2.103"], [x["ip"] for x in pendientes])

    def test_arranque_rechaza_secretos_reutilizados(self):
        nodos = [
            {"nombre": "node-a", "ip": "192.0.2.10", "interfaz": "eth0", "prioridad": 150},
            {"nombre": "node-b", "ip": "192.0.2.11", "interfaz": "eth0", "prioridad": 100},
        ]
        with mock.patch.object(local, "NODOS", nodos), \
                mock.patch.object(local, "YO", "node-a"), \
                mock.patch.object(servidor, "PARES", ["http://node-b:6060"]), \
                mock.patch.object(servidor, "SESSION_SECRET", "a" * 32), \
                mock.patch.object(servidor, "CLUSTER_TOKEN", "a" * 32), \
                mock.patch.object(servidor.plan, "_auth_pass", return_value="Vrrp123"):
            with self.assertRaises(RuntimeError):
                servidor.validar_arranque()

    def test_par_caido_conserva_su_identidad_logica(self):
        nodos = [
            {"nombre": "node-a", "ip": "192.0.2.10", "interfaz": "eth0", "prioridad": 150},
            {"nombre": "node-b", "ip": "192.0.2.11", "interfaz": "eth0", "prioridad": 100},
        ]
        vista_local = {
            "nodo": "node-a", "servicios": {}, "direcciones_puestas": []
        }
        endpoint = "https://peer-b.example:7443"
        with mock.patch.object(local, "NODOS", nodos), \
                mock.patch.object(local, "YO", "node-a"), \
                mock.patch.object(local, "vista_local", return_value=vista_local), \
                mock.patch.object(servidor, "PARES", [endpoint]), \
                mock.patch.object(
                    servidor, "_pedir_interno", side_effect=TimeoutError("caído")
                ):
            vistas = servidor.vistas_de_todos({"direcciones": []})

        self.assertEqual({"node-a", "node-b"}, set(vistas))
        self.assertFalse(vistas["node-b"]["alcanzable"])
        self.assertIsNone(vistas["node-b"]["base"])
        self.assertEqual("PeerUnavailable", vistas["node-b"]["error"])

    def test_identidad_duplicada_falla_cerrada_sin_ocultar_nodos(self):
        nodos = [
            {"nombre": "node-a", "ip": "192.0.2.10", "interfaz": "eth0", "prioridad": 150},
            {"nombre": "node-b", "ip": "192.0.2.11", "interfaz": "eth0", "prioridad": 100},
            {"nombre": "node-c", "ip": "192.0.2.12", "interfaz": "eth0", "prioridad": 90},
        ]
        endpoints = ["https://peer-1.example:7443", "https://peer-2.example:7443"]
        with mock.patch.object(local, "NODOS", nodos), \
                mock.patch.object(local, "YO", "node-a"), \
                mock.patch.object(local, "vista_local", return_value={
                    "nodo": "node-a", "servicios": {}, "direcciones_puestas": [],
                }), \
                mock.patch.object(servidor, "PARES", endpoints), \
                mock.patch.object(
                    servidor, "_pedir_interno",
                    side_effect=lambda base, _ruta: {"payload": base},
                ), \
                mock.patch.object(
                    servidor.PROTOCOLO, "descifrar", side_effect=lambda _sobre: {
                        "nodo": "node-c", "servicios": {}, "direcciones_puestas": [],
                    }
                ):
            vistas = servidor.vistas_de_todos({"direcciones": []})

        self.assertEqual({"node-a", "node-b", "node-c"}, set(vistas))
        self.assertFalse(vistas["node-b"]["alcanzable"])
        self.assertEqual("PeerUnavailable", vistas["node-b"]["error"])
        self.assertFalse(vistas["node-c"]["alcanzable"])
        self.assertEqual("PeerIdentityDuplicate", vistas["node-c"]["error"])

    def test_identidades_local_y_desconocida_no_crean_vistas(self):
        nodos = [
            {"nombre": "node-a", "ip": "192.0.2.10", "interfaz": "eth0", "prioridad": 150},
            {"nombre": "node-b", "ip": "192.0.2.11", "interfaz": "eth0", "prioridad": 100},
            {"nombre": "node-c", "ip": "192.0.2.12", "interfaz": "eth0", "prioridad": 90},
        ]
        endpoints = [f"https://peer-{n}.example:7443" for n in range(1, 5)]
        respuestas = {
            endpoints[0]: {
                "nodo": "node-a", "servicios": {}, "direcciones_puestas": [],
            },
            endpoints[1]: {
                "nodo": "node-externo", "servicios": {}, "direcciones_puestas": [],
            },
            endpoints[2]: {
                "nodo": [], "servicios": {}, "direcciones_puestas": [],
            },
            endpoints[3]: {
                "nodo": "node-b", "servicios": [], "direcciones_puestas": [],
            },
        }
        with mock.patch.object(local, "NODOS", nodos), \
                mock.patch.object(local, "YO", "node-a"), \
                mock.patch.object(local, "vista_local", return_value={
                    "nodo": "node-a", "servicios": {}, "direcciones_puestas": [],
                }), \
                mock.patch.object(servidor, "PARES", endpoints), \
                mock.patch.object(
                    servidor, "_pedir_interno",
                    side_effect=lambda base, _ruta: {"payload": base},
                ), \
                mock.patch.object(
                    servidor.PROTOCOLO, "descifrar",
                    side_effect=lambda sobre: respuestas[sobre],
                ):
            vistas = servidor.vistas_de_todos({"direcciones": []})

        self.assertEqual({"node-a", "node-b", "node-c"}, set(vistas))
        self.assertTrue(vistas["node-a"]["alcanzable"])
        self.assertFalse(vistas["node-b"]["alcanzable"])
        self.assertFalse(vistas["node-c"]["alcanzable"])

    def test_cuadro_detecta_una_vip_sostenida_por_dos_nodos(self):
        nodos = [
            {"nombre": "node-a", "ip": "192.0.2.10", "interfaz": "eth0", "prioridad": 150},
            {"nombre": "node-b", "ip": "192.0.2.11", "interfaz": "eth0", "prioridad": 100},
        ]
        vip = "192.0.2.100"
        vistas = {
            nombre: {
                "nodo": nombre,
                "alcanzable": True,
                "servicios": {},
                "direcciones_puestas": [vip],
            }
            for nombre in ("node-a", "node-b")
        }
        datos = {
            "direcciones": [{
                "ip": vip,
                "estado": "libre",
                "servicio": None,
                "preferente": None,
            }],
            "mantenimiento": [],
        }

        with mock.patch.object(local, "NODOS", nodos), \
                mock.patch.object(local, "YO", "node-a"), \
                mock.patch.object(servidor, "vistas_de_todos", return_value=vistas):
            fila = servidor.cuadro(datos)["direcciones"][0]
            resumen = servidor.resumen_nodos(datos)

        self.assertTrue(fila["duplicada"])
        self.assertEqual(["node-a", "node-b"], fila["portadores"])
        self.assertIsNone(fila["portador"])
        self.assertTrue(fila["nodos"]["node-a"]["sostenida"])
        self.assertTrue(fila["nodos"]["node-b"]["sostenida"])
        self.assertEqual([[vip], [vip]], [nodo["sostiene"] for nodo in resumen])


if __name__ == "__main__":
    unittest.main()
