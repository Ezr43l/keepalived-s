"""Configuracion persistente y asistente inicial de Keepalived.

La plantilla Docker solo aporta el puerto y /datos. Este modulo conserva la
compatibilidad con las variables FIP_* antiguas y las migra al primer arranque
de 1.0.3, de modo que el siguiente recreado ya no dependa de ellas.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import secrets
import shlex
import stat
import tempfile
from pathlib import Path
from urllib.parse import urlsplit


class SetupError(ValueError):
    pass


SCHEMA = "keepalived-runtime-v1"
ENROLLMENT_SCHEMA = "keepalived-enrollment-v1"
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
INTERFACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
VRRP_RE = re.compile(r"^[A-Za-z0-9]{8}$")
DATA = Path(os.environ.get("FIP_DATOS", "/datos"))
CONFIG = DATA / "app-config.json"
SECRETS = DATA / "secrets"
MANAGED = {
    "FIP_VRRP_AUTH_PASS": SECRETS / "vrrp-auth",
    "FIP_SESSION_SECRET": SECRETS / "session-secret",
    "FIP_CLUSTER_TOKEN": SECRETS / "cluster-token",
}
SETTINGS_KEYS = {
    "local_node", "nodes", "preempt_delay", "vip_prefix",
    "session_hours", "cookie_secure", "totp_issuer",
}


def _atomic(path: Path, value: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            target.write(value)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
        os.chmod(path, mode)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _text(value: object, label: str, maximum: int = 2048, required: bool = False) -> str:
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise SetupError(f"{label} debe ser texto")
    result = value.strip()
    if required and not result:
        raise SetupError(f"{label} es obligatorio")
    if len(result) > maximum or any(ord(char) < 32 or ord(char) == 127 for char in result):
        raise SetupError(f"{label} contiene caracteres no permitidos")
    return result


def _integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        raise SetupError(f"{label} no es valido")
    try:
        result = int(value)
    except (TypeError, ValueError) as error:
        raise SetupError(f"{label} no es valido") from error
    if not minimum <= result <= maximum:
        raise SetupError(f"{label} debe estar entre {minimum} y {maximum}")
    return result


def _boolean(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise SetupError(f"{label} debe ser verdadero o falso")
    return value


def _url(value: object, label: str) -> str:
    result = _text(value, label, 2048, True).rstrip("/")
    try:
        parsed = urlsplit(result)
        port = parsed.port
    except ValueError as error:
        raise SetupError(f"{label} no es una URL valida") from error
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname or port is None
            or parsed.username or parsed.password or parsed.path not in {"", "/"}
            or parsed.query or parsed.fragment):
        raise SetupError(f"{label} debe ser http(s)://host:puerto, sin credenciales ni ruta")
    return result


def _node(raw: object) -> dict:
    if not isinstance(raw, dict) or set(raw) != {"name", "ip", "interface", "priority", "url"}:
        raise SetupError("cada nodo debe incluir nombre, IPv4, interfaz, prioridad y URL")
    name = _text(raw["name"], "nombre de nodo", 64, True)
    address = _text(raw["ip"], f"IPv4 de {name}", 64, True)
    interface = _text(raw["interface"], f"interfaz de {name}", 64, True)
    if not NAME_RE.fullmatch(name):
        raise SetupError(f"nombre de nodo no valido: {name!r}")
    try:
        address = str(ipaddress.IPv4Address(address))
    except ipaddress.AddressValueError as error:
        raise SetupError(f"IPv4 no valida para {name}") from error
    if not INTERFACE_RE.fullmatch(interface):
        raise SetupError(f"interfaz no valida para {name}")
    return {"name": name, "ip": address, "interface": interface,
            "priority": _integer(raw["priority"], f"prioridad de {name}", 1, 254),
            "url": _url(raw["url"], f"URL de {name}")}


def parse_nodes_text(value: object) -> list[dict]:
    result = []
    for number, line in enumerate(str(value or "").splitlines(), 1):
        if not line.strip():
            continue
        fields = [item.strip() for item in line.split("|")]
        if len(fields) != 5:
            raise SetupError(f"linea {number}: usa nombre | IPv4 | interfaz | prioridad | URL")
        result.append(_node(dict(zip(("name", "ip", "interface", "priority", "url"), fields))))
    return result


def validate(raw: object) -> dict:
    if not isinstance(raw, dict) or raw.get("schema") != SCHEMA:
        raise SetupError("formato de configuracion desconocido")
    raw_nodes = raw.get("nodes")
    nodes = parse_nodes_text(raw_nodes) if isinstance(raw_nodes, str) else [
        _node(node) for node in raw_nodes] if isinstance(raw_nodes, list) else []
    if not 2 <= len(nodes) <= 16:
        raise SetupError("declara entre 2 y 16 nodos")
    for field, label in (("name", "nombre"), ("ip", "IPv4"),
                         ("priority", "prioridad"), ("url", "URL")):
        values = [str(node[field]).casefold() for node in nodes]
        if len(values) != len(set(values)):
            raise SetupError(f"hay mas de un nodo con el mismo {label}")
    local_node = _text(raw.get("local_node"), "nodo local", 64, True)
    if local_node not in {node["name"] for node in nodes}:
        raise SetupError("el nodo local no aparece en la topologia")
    issuer = _text(raw.get("totp_issuer", "Keepalived"), "emisor TOTP", 120, True)
    vip_prefix = _integer(raw.get("vip_prefix", 24), "prefijo CIDR", 1, 32)
    if vip_prefix != 24:
        raise SetupError(
            "el formato de pool actual sólo admite el prefijo CIDR /24")
    return {
        "schema": SCHEMA,
        "local_node": local_node,
        "nodes": nodes,
        "preempt_delay": _integer(raw.get("preempt_delay", 45), "retardo", 0, 1000),
        "vip_prefix": vip_prefix,
        "session_hours": _integer(raw.get("session_hours", 12), "duracion de sesion", 1, 168),
        "cookie_secure": _boolean(raw.get("cookie_secure", False), "cookie HTTPS"),
        "totp_issuer": issuer,
    }


def settings(config: dict | None = None) -> dict:
    """Configuración pública: nunca incluye los secretos administrados."""
    current = config if config is not None else prepare()
    if current is None:
        raise SetupError("Keepalived todavía no tiene configuración inicial")
    validated = validate(current)
    return json.loads(json.dumps(
        {key: validated[key] for key in SETTINGS_KEYS}))


def candidate(payload: object, current: dict | None = None) -> dict:
    """Valida todos los valores editables sin imponer el valor anterior."""
    if not isinstance(payload, dict) or set(payload) != SETTINGS_KEYS:
        raise SetupError(
            "la configuración está incompleta o contiene campos desconocidos")
    previous = current if current is not None else prepare()
    if previous is None:
        raise SetupError("Keepalived todavía no tiene configuración inicial")
    validate(previous)
    return validate({"schema": SCHEMA, **payload})


def persist_settings(config: dict) -> dict:
    """Sustituye sólo app-config.json; no toca pool, cuentas ni secretos."""
    validated = validate(config)
    _atomic(CONFIG, json.dumps(
        validated, ensure_ascii=False, indent=2, sort_keys=True,
    ) + "\n")
    return validated


def _environment(config: dict) -> dict[str, str]:
    nodes = config["nodes"]
    local_name = config["local_node"]
    return {
        "FIP_NODO": local_name,
        "FIP_NODOS": ",".join(
            f"{n['name']}:{n['ip']}:{n['interface']}:{n['priority']}" for n in nodes),
        "FIP_PARES": ",".join(n["url"] for n in nodes if n["name"] != local_name),
        "FIP_RETARDO": str(config["preempt_delay"]),
        "FIP_VIP_PREFIX": str(config["vip_prefix"]),
        "FIP_SESSION_HOURS": str(config["session_hours"]),
        "FIP_COOKIE_SECURE": "1" if config["cookie_secure"] else "0",
        "FIP_TOTP_ISSUER": config["totp_issuer"],
        "FIP_VRRP_AUTH_PASS_FILE": str(MANAGED["FIP_VRRP_AUTH_PASS"]),
        "FIP_SESSION_SECRET_FILE": str(MANAGED["FIP_SESSION_SECRET"]),
        "FIP_CLUSTER_TOKEN_FILE": str(MANAGED["FIP_CLUSTER_TOKEN"]),
    }


def _read_secret(name: str) -> str:
    direct = os.environ.get(name, "").strip()
    file_name = os.environ.get(f"{name}_FILE", "").strip()
    if direct and file_name:
        raise SetupError(f"{name} y {name}_FILE son excluyentes")
    if direct:
        return direct
    if not file_name:
        return ""
    path = Path(file_name)
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 16384:
        raise SetupError(f"{name}_FILE no es un fichero regular acotado")
    return path.read_text(encoding="utf-8").strip()


def _persist(config: dict, values: dict[str, str], fresh: bool) -> None:
    for name, pattern in (("FIP_VRRP_AUTH_PASS", VRRP_RE),
                          ("FIP_SESSION_SECRET", TOKEN_RE),
                          ("FIP_CLUSTER_TOKEN", TOKEN_RE)):
        if not pattern.fullmatch(values.get(name, "")):
            raise SetupError(f"{name} no tiene el formato esperado")
    if values["FIP_SESSION_SECRET"] == values["FIP_CLUSTER_TOKEN"]:
        raise SetupError("los secretos de sesion y cluster deben ser distintos")
    for name, path in MANAGED.items():
        _atomic(path, values[name] + "\n")
    _atomic(CONFIG, json.dumps(validate(config), ensure_ascii=False,
                               indent=2, sort_keys=True) + "\n")
    if fresh:
        for name in (".bootstrap-pool", ".bootstrap-security"):
            path = DATA / name
            if not path.exists():
                _atomic(path, "fresh-install-v1\n")


def _legacy_config() -> dict | None:
    local_name = os.environ.get("FIP_NODO", "").strip()
    table = os.environ.get("FIP_NODOS", "").strip()
    if not local_name or not table:
        return None
    port = _integer(os.environ.get("FIP_PUERTO", "6060"), "puerto", 1, 65535)
    peers = [item.strip().rstrip("/") for item in os.environ.get("FIP_PARES", "").split(",") if item.strip()]
    nodes = []
    peer_index = 0
    for item in table.split(","):
        fields = item.split(":")
        if len(fields) != 4:
            raise SetupError("FIP_NODOS antiguo no tiene el formato esperado")
        name, address, interface, priority = fields
        if name == local_name:
            url = f"http://{address}:{port}"
        else:
            if peer_index >= len(peers):
                raise SetupError("FIP_PARES antiguo esta incompleto")
            url = peers[peer_index]
            peer_index += 1
        nodes.append({"name": name, "ip": address, "interface": interface,
                      "priority": priority, "url": url})
    if peer_index != len(peers):
        raise SetupError("FIP_PARES antiguo contiene URLs sobrantes")
    return validate({
        "schema": SCHEMA, "local_node": local_name, "nodes": nodes,
        "preempt_delay": os.environ.get("FIP_RETARDO", "45"),
        "vip_prefix": os.environ.get("FIP_VIP_PREFIX", "24"),
        "session_hours": os.environ.get("FIP_SESSION_HOURS", "12"),
        "cookie_secure": os.environ.get("FIP_COOKIE_SECURE", "0").lower()
            in {"1", "true", "yes", "on"},
        "totp_issuer": os.environ.get("FIP_TOTP_ISSUER", "Keepalived"),
    })


def prepare() -> dict | None:
    if CONFIG.exists():
        metadata = CONFIG.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 256 * 1024:
            raise SetupError("app-config.json no es un fichero regular acotado")
        return validate(json.loads(CONFIG.read_text(encoding="utf-8")))
    legacy = _legacy_config()
    if legacy is None:
        return None
    values = {name: _read_secret(name) for name in MANAGED}
    _persist(legacy, values, fresh=False)
    return legacy


def create(payload: object) -> tuple[dict, str]:
    if CONFIG.exists():
        raise SetupError("este nodo ya esta configurado")
    if not isinstance(payload, dict) or set(payload) != {
            "local_node", "nodes", "preempt_delay", "vip_prefix",
            "session_hours", "cookie_secure", "totp_issuer", "enrollment_code"}:
        raise SetupError("el formulario esta incompleto o contiene campos desconocidos")
    enrollment_code = _text(payload["enrollment_code"], "codigo de incorporacion", 16384)
    if enrollment_code:
        try:
            decoded = json.loads(base64.urlsafe_b64decode(
                enrollment_code + "=" * (-len(enrollment_code) % 4)).decode("utf-8"))
        except (ValueError, UnicodeError, json.JSONDecodeError) as error:
            raise SetupError("el codigo de incorporacion no es valido") from error
        if (not isinstance(decoded, dict)
                or set(decoded) != {"schema", "config", "secrets"}
                or decoded.get("schema") != ENROLLMENT_SCHEMA
                or not isinstance(decoded.get("config"), dict)
                or not isinstance(decoded.get("secrets"), dict)
                or set(decoded["secrets"]) != set(MANAGED)):
            raise SetupError("el codigo pertenece a otra aplicacion o version")
        config = validate({**decoded["config"], "local_node": payload["local_node"]})
        values = decoded["secrets"]
        result_code = ""
    else:
        config = validate({"schema": SCHEMA, **{key: payload[key] for key in payload if key != "enrollment_code"}})
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        values = {
            "FIP_VRRP_AUTH_PASS": "".join(secrets.choice(alphabet) for _ in range(8)),
            "FIP_SESSION_SECRET": secrets.token_urlsafe(48),
            "FIP_CLUSTER_TOKEN": secrets.token_urlsafe(48),
        }
        shared = {**config, "local_node": config["nodes"][0]["name"]}
        encoded = json.dumps({"schema": ENROLLMENT_SCHEMA, "config": shared,
                              "secrets": values}, separators=(",", ":")).encode()
        result_code = base64.urlsafe_b64encode(encoded).decode().rstrip("=")
    _persist(config, values, fresh=True)
    return config, result_code


def shell_exports(config: dict) -> str:
    return "\n".join(f"export {key}={shlex.quote(value)}"
                     for key, value in _environment(config).items()) + "\n"
