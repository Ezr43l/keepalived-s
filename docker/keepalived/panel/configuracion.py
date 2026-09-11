"""Carga y valida configuración que pertenece a cada instalación."""

from __future__ import annotations

import os
import re
import ssl
import stat
import urllib.parse
from pathlib import Path


_BASE64URL = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
MAX_PARES = 15


def secreto(nombre: str, *alias_fichero: str) -> str:
    """Lee un secreto directo o desde un fichero, pero nunca desde ambos."""
    directo = os.environ.get(nombre, "").strip()
    nombres_fichero = (f"{nombre}_FILE", *alias_fichero)
    configurados = [
        (variable, os.environ.get(variable, "").strip())
        for variable in nombres_fichero
        if os.environ.get(variable, "").strip()
    ]
    if directo and configurados:
        raise RuntimeError(
            f"{nombre} y {configurados[0][0]} son excluyentes")
    if len(configurados) > 1:
        raise RuntimeError(
            "sólo se admite una variable de fichero para " + nombre)
    if not configurados:
        return directo

    variable, ruta = configurados[0]
    path = Path(ruta)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise RuntimeError(
            f"no se puede leer {variable}: {type(error).__name__}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RuntimeError(f"{variable} debe ser un fichero regular, no un enlace")
    if metadata.st_size > 16384:
        raise RuntimeError(f"{variable} supera 16 KiB")
    try:
        crudo = path.read_bytes()
    except OSError as error:
        raise RuntimeError(
            f"no se puede leer {variable}: {type(error).__name__}") from error
    try:
        return crudo.decode("utf-8").strip()
    except UnicodeDecodeError as error:
        raise RuntimeError(f"{variable} no contiene UTF-8 válido") from error


def validar_secreto_largo(nombre: str, valor: str) -> None:
    if not _BASE64URL.fullmatch(valor):
        raise RuntimeError(
            f"{nombre} debe tener 32-128 caracteres base64url")


def urls_pares(valor: str) -> list[str]:
    """Normaliza paneles pares y rechaza URLs ambiguas o con credenciales."""
    salida: list[str] = []
    for crudo in valor.split(","):
        crudo = crudo.strip().rstrip("/")
        if not crudo:
            continue
        try:
            url = urllib.parse.urlsplit(crudo)
            puerto = url.port
        except ValueError as error:
            raise RuntimeError(f"URL de par no válida: {crudo}") from error
        if (
            url.scheme not in {"http", "https"}
            or not url.hostname
            or url.username is not None
            or url.password is not None
            or url.path not in {"", "/"}
            or url.query
            or url.fragment
            or puerto is None
            or not 1 <= puerto <= 65535
        ):
            raise RuntimeError(
                "cada FIP_PARES debe ser http(s)://host:puerto, sin ruta, "
                "credenciales, consulta ni fragmento")
        normalizada = urllib.parse.urlunsplit(
            (url.scheme, url.netloc, "", "", ""))
        if normalizada in salida:
            raise RuntimeError(f"par repetido en FIP_PARES: {normalizada}")
        salida.append(normalizada)
        if len(salida) > MAX_PARES:
            raise RuntimeError(
                f"FIP_PARES no puede contener más de {MAX_PARES} paneles")
    return salida


def contexto_tls_cluster() -> ssl.SSLContext:
    ca_file = os.environ.get("FIP_CLUSTER_CA_FILE", "").strip()
    if ca_file:
        path = Path(ca_file)
        try:
            metadata = path.lstat()
        except OSError as error:
            raise RuntimeError("FIP_CLUSTER_CA_FILE no existe o no es legible") from error
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("FIP_CLUSTER_CA_FILE no es un fichero regular")
    return ssl.create_default_context(cafile=ca_file or None)
