import os
import sys
import tempfile
import unittest
from pathlib import Path

PANEL = Path(__file__).resolve().parents[1] / "panel"
sys.path.insert(0, str(PANEL))
import setup_config


class SetupConfigTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.data = Path(self.temporary.name)
        setup_config.DATA = self.data
        setup_config.CONFIG = self.data / "app-config.json"
        setup_config.SECRETS = self.data / "secrets"
        setup_config.MANAGED = {
            "FIP_VRRP_AUTH_PASS": setup_config.SECRETS / "vrrp-auth",
            "FIP_SESSION_SECRET": setup_config.SECRETS / "session-secret",
            "FIP_CLUSTER_TOKEN": setup_config.SECRETS / "cluster-token",
        }
        self.saved_environment = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.saved_environment)
        self.temporary.cleanup()

    @staticmethod
    def payload(local="node-a", enrollment=""):
        return {
            "local_node": local,
            "nodes": [
                {"name": "node-a", "ip": "192.0.2.10", "interface": "eth0",
                 "priority": 150, "url": "http://192.0.2.10:6060"},
                {"name": "node-b", "ip": "192.0.2.11", "interface": "eth0",
                 "priority": 100, "url": "http://192.0.2.11:6060"},
            ],
            "preempt_delay": 45,
            "vip_prefix": 24,
            "session_hours": 12,
            "cookie_secure": False,
            "totp_issuer": "Keepalived",
            "enrollment_code": enrollment,
        }

    def test_first_node_persists_everything_and_emits_join_code(self):
        config, code = setup_config.create(self.payload())
        self.assertEqual("node-a", config["local_node"])
        self.assertTrue(code)
        self.assertTrue(setup_config.CONFIG.is_file())
        for path in setup_config.MANAGED.values():
            self.assertTrue(path.is_file())
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
        self.assertEqual("fresh-install-v1\n", (self.data / ".bootstrap-pool").read_text())

    def test_join_code_reuses_cluster_secrets_and_selects_local_node(self):
        _, code = setup_config.create(self.payload())
        first = {name: path.read_text() for name, path in setup_config.MANAGED.items()}
        second = self.data / "second"
        setup_config.DATA = second
        setup_config.CONFIG = second / "app-config.json"
        setup_config.SECRETS = second / "secrets"
        setup_config.MANAGED = {name: setup_config.SECRETS / path.name
                                for name, path in setup_config.MANAGED.items()}
        config, returned = setup_config.create(self.payload("node-b", code))
        self.assertEqual("node-b", config["local_node"])
        self.assertEqual("", returned)
        self.assertEqual(first, {name: path.read_text()
                                 for name, path in setup_config.MANAGED.items()})

    def test_legacy_environment_is_migrated_without_bootstrap_markers(self):
        secret_values = {
            "FIP_VRRP_AUTH_PASS": "Ab12Cd34",
            "FIP_SESSION_SECRET": "a" * 64,
            "FIP_CLUSTER_TOKEN": "b" * 64,
        }
        os.environ.update(secret_values)
        os.environ.update({
            "FIP_NODO": "node-a",
            "FIP_NODOS": "node-a:192.0.2.10:eth0:150,node-b:192.0.2.11:eth0:100",
            "FIP_PARES": "http://192.0.2.11:6060",
            "FIP_PUERTO": "6060",
        })
        config = setup_config.prepare()
        self.assertEqual("node-a", config["local_node"])
        self.assertTrue(setup_config.CONFIG.is_file())
        self.assertFalse((self.data / ".bootstrap-pool").exists())
        exports = setup_config.shell_exports(config)
        self.assertIn("export FIP_NODO=node-a", exports)
        self.assertNotIn("a" * 64, exports)

    def test_every_runtime_setting_is_editable_and_persisted(self):
        setup_config.create(self.payload())
        edited = self.payload("node-renamed")
        edited.pop("enrollment_code")
        edited["nodes"][0]["name"] = "node-renamed"
        edited["nodes"][0]["interface"] = "br0"
        edited["nodes"][0]["priority"] = 175
        edited["nodes"][0]["url"] = "https://192.0.2.10:7443"
        edited["preempt_delay"] = 90
        edited["session_hours"] = 24
        edited["cookie_secure"] = True
        edited["totp_issuer"] = "Mi clúster"

        candidate = setup_config.candidate(edited)
        setup_config.persist_settings(candidate)

        self.assertEqual(setup_config.settings(candidate), setup_config.settings())
        self.assertEqual("node-renamed", setup_config.prepare()["local_node"])
        self.assertEqual("br0", setup_config.prepare()["nodes"][0]["interface"])

    def test_settings_never_exposes_managed_secrets(self):
        setup_config.create(self.payload())
        public = setup_config.settings()
        self.assertEqual(setup_config.SETTINGS_KEYS, set(public))
        self.assertFalse(set(public) & set(setup_config.MANAGED))

    def test_candidate_rejects_missing_or_unknown_fields(self):
        setup_config.create(self.payload())
        edited = self.payload()
        edited.pop("enrollment_code")
        edited.pop("totp_issuer")
        with self.assertRaisesRegex(setup_config.SetupError, "incompleta"):
            setup_config.candidate(edited)


if __name__ == "__main__":
    unittest.main()
