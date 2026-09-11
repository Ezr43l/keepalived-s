#!/usr/bin/env python3
"""Genera instaladores de release que apuntan al digest OCI ya verificado."""

from __future__ import annotations

import argparse
import os
import re
import tempfile
from pathlib import Path


PATRON_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
PATRON_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[.-][A-Za-z0-9.-]+)?")
PATRON_IMAGEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]*")


def _escribir_atomico(destino: Path, contenido: str) -> None:
    destino.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporal = tempfile.mkstemp(
        prefix=f".{destino.name}.", dir=destino.parent, text=True,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as salida:
            salida.write(contenido)
            salida.flush()
            os.fsync(salida.fileno())
        os.chmod(temporal, 0o644)
        os.replace(temporal, destino)
    finally:
        try:
            os.unlink(temporal)
        except FileNotFoundError:
            pass


def _render_xml(origen: str, referencia: str, version: str) -> str:
    repositorio = re.compile(
        r"(?m)^(\s*)<Repository>[^<]+</Repository>\s*$",
    )
    salida, cambios = repositorio.subn(
        rf"\1<Repository>{referencia}</Repository>", origen,
    )
    if cambios != 1:
        raise ValueError("la plantilla debe contener un único Repository")
    template_url = re.compile(r"(?m)^(\s*)<TemplateURL>[^<]+</TemplateURL>\s*$")
    salida, urls = template_url.subn(
        rf"\1<TemplateURL>https://github.com/Ezr43l/keepalived-s/releases/download/v{version}/my-Keepalived-{version}.xml</TemplateURL>",
        salida,
    )
    if urls != 1:
        raise ValueError("la plantilla debe contener un único TemplateURL")
    icon = re.compile(r"(?m)^(\s*)<Icon>[^<]+</Icon>\s*$")
    salida, urls = icon.subn(
        rf"\1<Icon>https://raw.githubusercontent.com/Ezr43l/keepalived-s/v{version}/logo/icono.png</Icon>",
        salida,
    )
    if urls != 1:
        raise ValueError("la plantilla debe contener un único Icon")
    return salida


def _render_compose(origen: str, referencia: str) -> str:
    lineas = origen.splitlines(keepends=True)
    salida = [
        "# Generado por la release: imagen inmutable verificada por digest.\n",
    ]
    imagenes = 0
    bloques_build = 0
    indice = 0
    while indice < len(lineas):
        linea = lineas[indice]
        if re.fullmatch(r" {4}image:.*\r?\n?", linea):
            salida.append(f"    image: {referencia}\n")
            imagenes += 1
            indice += 1
            continue
        if re.fullmatch(r" {4}build:\s*\r?\n?", linea):
            bloques_build += 1
            indice += 1
            while indice < len(lineas) and (
                    not lineas[indice].strip()
                    or len(lineas[indice]) - len(lineas[indice].lstrip(" ")) > 4):
                indice += 1
            continue
        salida.append(linea)
        indice += 1
    if imagenes != 1 or bloques_build != 1:
        raise ValueError("Compose debe contener una imagen y un bloque build exactos")
    return "".join(salida)


def generar(raiz: Path, salida: Path, imagen: str, version: str, digest: str) -> list[Path]:
    if not PATRON_IMAGEN.fullmatch(imagen):
        raise ValueError("nombre de imagen no válido")
    if not PATRON_VERSION.fullmatch(version):
        raise ValueError("versión no válida")
    if not PATRON_DIGEST.fullmatch(digest):
        raise ValueError("digest OCI no válido")
    referencia = f"{imagen}@{digest}"
    xml = (raiz / "unraid" / "my-Keepalived.xml").read_text(encoding="utf-8")
    compose = (raiz / "docker-compose.yml").read_text(encoding="utf-8")
    destinos = [
        salida / f"my-Keepalived-{version}.xml",
        salida / f"docker-compose-{version}.yml",
    ]
    _escribir_atomico(destinos[0], _render_xml(xml, referencia, version))
    _escribir_atomico(destinos[1], _render_compose(compose, referencia))
    return destinos


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--digest", required=True)
    args = parser.parse_args()
    generar(args.root.resolve(), args.output.resolve(), args.image, args.version, args.digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
