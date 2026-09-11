import unittest
from html.parser import HTMLParser
from pathlib import Path


WEB = Path(__file__).resolve().parents[1] / "panel" / "web"


class _Ids(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []

    def handle_starttag(self, _tag, attrs):
        values = dict(attrs)
        if values.get("id"):
            self.ids.append(values["id"])


class NavegacionCuentaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (WEB / "index.html").read_text(encoding="utf-8")
        cls.css = (WEB / "estilo.css").read_text(encoding="utf-8")
        cls.js = (WEB / "auth.js").read_text(encoding="utf-8")

    def test_ids_unicos_y_vistas_principales_presentes(self):
        parser = _Ids()
        parser.feed(self.html)
        self.assertEqual(len(parser.ids), len(set(parser.ids)))
        for identifier in (
            "vista-operacion", "vista-cuenta", "contenido-cuenta", "panel-secretos",
            "pestana-usuarios", "pestana-api", "pestana-configuracion", "cerrar-sesion",
        ):
            self.assertIn(identifier, parser.ids)
        for view in ("estado", "perfil", "seguridad", "usuarios", "api", "configuracion"):
            self.assertIn(f'data-vista="{view}"', self.html)

    def test_cuenta_y_secretos_no_son_dialogos_flotantes(self):
        self.assertNotIn('id="dialogo-cuenta"', self.html)
        self.assertNotIn('id="dialogo-codigos"', self.html)
        self.assertNotIn("dialogo-cuenta", self.js)
        self.assertNotIn("dialogo-codigos", self.js)
        self.assertIn(".vista-panel.oculto { display: none; }", self.css)
        self.assertIn(".bloque-cuenta.oculto { display: none; }", self.css)

    def test_identidad_visible_es_keepalived(self):
        self.assertIn("<title>Keepalived</title>", self.html)
        self.assertIn('id="marca-acceso-titulo">Keepalived.</h1>', self.html)
        self.assertNotIn("<title>Direcciones flotantes</title>", self.html)
        self.assertNotIn(">Direcciones flotantes</h1>", self.html)

    def test_nombre_de_clave_api_no_usa_un_campo_generico(self):
        self.assertIn("'api_key_name'", self.js)
        self.assertIn("String(controlNombre.value || '').trim()", self.js)
        self.assertNotIn("name: valor(alta, 'name')", self.js)

    def test_configuracion_expone_todos_los_valores_editables(self):
        self.assertIn("async function pintarConfiguracion", self.js)
        self.assertIn("request('/api/settings')", self.js)
        for field in (
            "local_node", "nodes", "preempt_delay", "vip_prefix",
            "session_hours", "cookie_secure", "totp_issuer",
        ):
            self.assertIn(field, self.js)
        self.assertNotIn("readonly", self.js.lower())


if __name__ == "__main__":
    unittest.main()
