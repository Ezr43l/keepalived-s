import subprocess
import sys
import tempfile
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET


if Path("/src/VERSION").is_file():
    ROOT = Path("/src")
else:
    ROOT = Path(__file__).resolve().parents[3]


class ContratoDistribucionTest(unittest.TestCase):
    def test_runtime_and_http_framing_hardening_are_part_of_the_contract(self):
        dockerfile = (ROOT / "docker/keepalived/Dockerfile").read_text(encoding="utf-8")
        server_path = (ROOT / "docker/keepalived/panel/servidor.py"
                       if (ROOT / "docker/keepalived/panel/servidor.py").is_file()
                       else Path("/opt/panel/servidor.py"))
        server = server_path.read_text(encoding="utf-8")
        local_path = (ROOT / "docker/keepalived/panel/local.py"
                      if (ROOT / "docker/keepalived/panel/local.py").is_file()
                      else Path("/opt/panel/local.py"))
        local = local_path.read_text(encoding="utf-8")
        self.assertIn("python:3.12-alpine@sha256:", dockerfile)
        self.assertIn("--only-binary=:all:", dockerfile)
        self.assertIn("--require-hashes", dockerfile)
        self.assertNotRegex(dockerfile, re.compile(r"(?m)^\s*RUN\s+apk\s+upgrade\b"))
        self.assertIn("apk-packages.lock", dockerfile)
        apk_lock = (
            ROOT / "docker/keepalived/apk-packages.lock"
        ).read_text(encoding="utf-8")
        paquetes = [
            linea.strip() for linea in apk_lock.splitlines()
            if linea.strip() and not linea.lstrip().startswith("#")
        ]
        self.assertEqual(len(paquetes), len(set(paquetes)))
        self.assertTrue(paquetes)
        for paquete in paquetes:
            self.assertRegex(
                paquete,
                re.compile(r"^[a-z0-9][a-z0-9+_.-]*=[0-9][A-Za-z0-9._+-]*-r[0-9]+$"),
            )
        self.assertIn("keepalived=2.3.4-r2", paquetes)
        self.assertIn("iproute2=7.0.0-r0", paquetes)
        self.assertIn("libcrypto3=3.5.8-r0", paquetes)
        self.assertIn("libssl3=3.5.8-r0", paquetes)
        notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
        self.assertIn("e0fe0621ab32bf73a803d0e7d0c8c084c784dfd2", notices)
        self.assertIn("3ee752ad0c8445c8105177cd5cebdd730789bcd8", notices)
        self.assertIn('self.headers.get("Transfer-Encoding")', server)
        self.assertIn("request_queue_size = 64", server)
        self.assertIn('["/usr/sbin/keepalived", "-t"', server)
        self.assertIn('["/sbin/ip", "-4"', local)
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("- SETGID", compose)
        tests_dir = (ROOT / "docker/keepalived/tests"
                     if (ROOT / "docker/keepalived/tests").is_dir()
                     else Path("/opt/tests"))
        self.assertTrue((tests_dir / "secure_vrrp_lab.py").is_file())
        self.assertTrue((tests_dir / "secure_vrrp_lab.ps1").is_file())

    def test_version_es_consistente(self):
        version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        self.assertEqual("1.0.6", version)
        for ruta in (
            ROOT / "docker" / "keepalived" / "Dockerfile"
            if (ROOT / "docker" / "keepalived" / "Dockerfile").is_file()
            else Path("/opt/panel") / "../Dockerfile",
            ROOT / "docker-compose.yml",
            ROOT / ".env.example",
        ):
            if ruta.is_file():
                self.assertIn("1.0.6", ruta.read_text(encoding="utf-8"))

    def test_panel_enlaza_el_estado_de_la_api(self):
        panel_path = ROOT / "docker/keepalived/panel/web/index.html"
        if not panel_path.is_file():
            panel_path = Path("/opt/panel/web/index.html")
        panel = panel_path.read_text(encoding="utf-8")
        self.assertIn('href="api/status"', panel)
        self.assertIn('>Ver API JSON</a>', panel)

    def test_plantilla_publica_no_tiene_marcadores_datos_privados_ni_secretos(self):
        ruta = ROOT / "unraid" / "my-Keepalived.xml"
        texto = ruta.read_text(encoding="utf-8")
        ET.parse(ruta)
        prefijos_privados = ("10" + ".100.", "192" + ".168.")
        for prohibido in ("__IMAGE__", "__NODO__", *prefijos_privados):
            self.assertNotIn(prohibido, texto)
        self.assertIn("ghcr.io/ezr43l/keepalived-s:1.0.6", texto)
        raiz = ET.parse(ruta).getroot()
        configs = {c.get("Target"): c.text or "" for c in raiz.findall("Config")}
        for secreto_directo in (
            "FIP_VRRP_AUTH_PASS", "FIP_SESSION_SECRET", "FIP_CLUSTER_TOKEN",
        ):
            self.assertNotIn(secreto_directo, configs)
        self.assertEqual({"FIP_PUERTO", "/datos"}, set(configs))
        self.assertEqual("/mnt/user/appdata/keepalived", configs["/datos"])

        despliegue = (ROOT / "deploy-floating-ip.sh").read_text(encoding="utf-8")
        for asignacion_directa in (
            "-e FIP_VRRP_AUTH_PASS=",
            "-e FIP_SESSION_SECRET=",
            "-e FIP_CLUSTER_TOKEN=",
            '--set "FIP_VRRP_AUTH_PASS=',
            '--set "FIP_SESSION_SECRET=',
            '--set "FIP_CLUSTER_TOKEN=',
        ):
            self.assertNotIn(asignacion_directa, despliegue)
        self.assertIn("FIP_REMOTE_SECRETS_DIR", despliegue)
        self.assertIn('${DIR_BOOT}-secrets', despliegue)
        self.assertIn("deben ser árboles separados", despliegue)
        self.assertIn("stat -c %u:%g:%a", despliegue)
        self.assertIn("FIP_DATA_DIR no puede estar bajo /boot", despliegue)
        self.assertIn("no pueden guardarse en /boot", despliegue)
        self.assertIn("FIP_VRRP_AUTH_PASS_FILE=/run/secrets/fip_vrrp_auth", despliegue)
        self.assertIn("FIP_SESSION_SECRET_FILE=/run/secrets/fip_session_secret", despliegue)
        self.assertIn("FIP_CLUSTER_TOKEN_FILE=/run/secrets/fip_cluster_token", despliegue)
        self.assertIn('--set "FIP_RETARDO=$PREEMPT_DELAY"', despliegue)
        self.assertTrue((ROOT / "prepare-compose-storage.sh").is_file())

    def test_renderer_solo_personaliza_la_copia(self):
        plantilla = ROOT / "unraid" / "my-Keepalived.xml"
        original = plantilla.read_bytes()
        with tempfile.TemporaryDirectory() as tmp:
            salida = Path(tmp) / "rendered.xml"
            with salida.open("wb") as destino:
                subprocess.run([
                    sys.executable,
                    str(ROOT / "render-unraid-template.py"),
                    str(plantilla),
                    "--repository", "registry.example/keepalived:1.0.6",
                    "--webui", "http://[IP]:7000/",
                    "--set", "FIP_PUERTO=7000",
                ], check=True, stdout=destino)
            raiz = ET.parse(salida).getroot()
            self.assertEqual(
                "registry.example/keepalived:1.0.6", raiz.findtext("Repository"))
            self.assertEqual("http://[IP]:7000/", raiz.findtext("WebUI"))
        self.assertEqual(original, plantilla.read_bytes())


if __name__ == "__main__":
    unittest.main()
