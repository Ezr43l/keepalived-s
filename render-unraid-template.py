#!/usr/bin/env python3
"""Personaliza una copia de la plantilla pública sin alterar el original."""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def asignacion(valor: str) -> tuple[str, str]:
    if "=" not in valor:
        raise argparse.ArgumentTypeError("se esperaba TARGET=VALOR")
    return tuple(valor.split("=", 1))  # type: ignore[return-value]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("template", type=Path)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--webui", required=True)
    parser.add_argument("--set", dest="values", action="append", default=[], type=asignacion)
    args = parser.parse_args()

    root = ET.parse(args.template).getroot()
    repository = root.find("Repository")
    webui = root.find("WebUI")
    if repository is None or webui is None:
        parser.error("la plantilla no contiene Repository o WebUI")
    repository.text = args.repository
    webui.text = args.webui

    configs = {element.get("Target", ""): element for element in root.findall("Config")}
    for target, value in args.values:
        if target not in configs:
            parser.error(f"Target desconocido: {target}")
        configs[target].text = value

    sys.stdout.buffer.write(b'<?xml version="1.0" encoding="utf-8"?>\n')
    ET.ElementTree(root).write(sys.stdout.buffer, encoding="utf-8", xml_declaration=False)
    sys.stdout.buffer.write(b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
