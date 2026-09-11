#!/usr/bin/env python3
"""Preflight offline y de sólo lectura para snapshots remotos descargados.

El despliegue prepara un directorio temporal privado, descarga allí un
``pool.json`` y un ``security.json`` por nodo y construye un manifiesto. Este
programa no contacta nodos ni modifica los artefactos: exige un quorum de
observaciones y, cuando existe estado, un quorum de ficheros materializados;
después delega la causalidad y la migración legacy en las mismas clases que usa
el runtime.

Formato del manifiesto (``null`` es ausencia comprobada; campo omitido es una
observación fallida que no vota para ese recurso)::

    {
      "schema": 1,
      "topology": ["node-a", "node-b", "node-c"],
      "writer": "node-a",
      "management_ips": ["192.0.2.10", "192.0.2.11", "192.0.2.12"],
      "observations": [
        {"node": "node-a", "pool": "node-a.pool.json",
         "security": "node-a.security.json"},
        {"node": "node-b", "pool": null, "security": null}
      ]
    }

La salida nunca contiene snapshots, cuentas, direcciones ni secretos; sólo
metadatos de quorum, formato y huellas SHA-256.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import stat
import sys
from collections import Counter

import pool
import seguridad


_MAX_MANIFEST_BYTES = 64 * 1024
_MAX_SNAPSHOT_BYTES = 512 * 1024
_MAX_NODOS = 16
_MAX_RUTA = 4096
_PATRON_NODO = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
_CAMPOS_MANIFEST = {
    "schema", "topology", "writer", "management_ips", "observations",
}
_CAMPOS_OBSERVACION = {"node", "pool", "security"}

EXIT_MANIFEST = 2
EXIT_ESTADO = 3
EXIT_COHERENCIA = 4


class ErrorPreflight(Exception):
    """Fallo estable y no sensible para consumo automático del despliegue."""

    def __init__(self, codigo, salida, recurso=None):
        super().__init__(codigo)
        self.codigo = codigo
        self.salida = salida
        self.recurso = recurso


def _fallar(codigo, salida, recurso=None):
    raise ErrorPreflight(codigo, salida, recurso)


def _objeto_sin_duplicados(pares):
    objeto = {}
    for clave, valor in pares:
        if clave in objeto:
            raise ValueError("campo JSON duplicado")
        objeto[clave] = valor
    return objeto


def _json_estricto(crudo, salida, codigo, recurso=None):
    try:
        return json.loads(
            crudo.decode("utf-8"),
            object_pairs_hook=_objeto_sin_duplicados,
            parse_constant=lambda valor: (_ for _ in ()).throw(
                ValueError("constante JSON no válida")),
        )
    except (UnicodeError, ValueError, RecursionError):
        _fallar(codigo, salida, recurso)


def _comprobar_directorio_privado(
        ruta, salida=EXIT_MANIFEST, codigo="PREFLIGHT_DIRECTORY_UNSAFE",
        recurso=None):
    """Valida el descriptor del directorio sin chmod/chown ni otros cambios."""
    try:
        previo = os.lstat(ruta)
        if stat.S_ISLNK(previo.st_mode) or not stat.S_ISDIR(previo.st_mode):
            _fallar(codigo, salida, recurso)
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(ruta, flags)
    except ErrorPreflight:
        raise
    except OSError:
        _fallar(codigo, salida, recurso)
    try:
        abierto = os.fstat(fd)
        posterior = os.lstat(ruta)
        if (not stat.S_ISDIR(abierto.st_mode)
                or stat.S_ISLNK(posterior.st_mode)
                or (abierto.st_dev, abierto.st_ino)
                != (posterior.st_dev, posterior.st_ino)):
            _fallar(codigo, salida, recurso)
        if os.name == "posix" and (
                abierto.st_uid != os.geteuid()
                or stat.S_IMODE(abierto.st_mode) != 0o700):
            _fallar(codigo, salida, recurso)
    except ErrorPreflight:
        raise
    except OSError:
        _fallar(codigo, salida, recurso)
    finally:
        os.close(fd)


def _comprobar_arbol_privado(
        base, padre, salida, codigo, recurso=None):
    try:
        relativo = os.path.relpath(padre, base)
    except ValueError:
        _fallar(codigo, salida, recurso)
    if relativo == os.pardir or relativo.startswith(os.pardir + os.sep):
        _fallar(codigo, salida, recurso)
    actual = base
    _comprobar_directorio_privado(
        actual, salida=salida, codigo=codigo, recurso=recurso)
    if relativo == ".":
        return
    for parte in relativo.split(os.sep):
        if parte in ("", ".", os.pardir):
            _fallar(codigo, salida, recurso)
        actual = os.path.join(actual, parte)
        _comprobar_directorio_privado(
            actual, salida=salida, codigo=codigo, recurso=recurso)


def _leer_regular_privado(ruta, maximo, salida, codigo, base=None,
                          recurso=None):
    """Lee una instantánea de un regular 0600, sin seguir enlaces ni escribir."""
    ruta = os.path.abspath(ruta)
    if base is not None:
        base = os.path.abspath(base)
        _comprobar_arbol_privado(
            base, os.path.dirname(ruta), salida, codigo, recurso)
    else:
        _comprobar_directorio_privado(
            os.path.dirname(ruta), salida=salida, codigo=codigo,
            recurso=recurso)
    try:
        previo = os.lstat(ruta)
        if stat.S_ISLNK(previo.st_mode) or not stat.S_ISREG(previo.st_mode):
            _fallar(codigo, salida, recurso)
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(ruta, flags)
    except ErrorPreflight:
        raise
    except OSError:
        _fallar(codigo, salida, recurso)
    try:
        abierto = os.fstat(fd)
        posterior = os.lstat(ruta)
        if (not stat.S_ISREG(abierto.st_mode)
                or stat.S_ISLNK(posterior.st_mode)
                or (abierto.st_dev, abierto.st_ino)
                != (previo.st_dev, previo.st_ino)
                or (abierto.st_dev, abierto.st_ino)
                != (posterior.st_dev, posterior.st_ino)):
            _fallar(codigo, salida, recurso)
        if os.name == "posix" and (
                abierto.st_uid != os.geteuid()
                or abierto.st_nlink != 1
                or stat.S_IMODE(abierto.st_mode) != 0o600):
            _fallar(codigo, salida, recurso)
        if abierto.st_size > maximo:
            _fallar("PREFLIGHT_STATE_TOO_LARGE" if recurso else codigo,
                    salida, recurso)
        partes = []
        restante = maximo + 1
        while restante:
            trozo = os.read(fd, min(64 * 1024, restante))
            if not trozo:
                break
            partes.append(trozo)
            restante -= len(trozo)
        crudo = b"".join(partes)
        final = os.fstat(fd)
        ultimo = os.lstat(ruta)
        if len(crudo) > maximo:
            _fallar("PREFLIGHT_STATE_TOO_LARGE" if recurso else codigo,
                    salida, recurso)
        if (len(crudo) != abierto.st_size
                or final.st_size != abierto.st_size
                or final.st_nlink != abierto.st_nlink
                or stat.S_ISLNK(ultimo.st_mode)
                or (final.st_dev, final.st_ino)
                != (ultimo.st_dev, ultimo.st_ino)
                or getattr(final, "st_mtime_ns", None)
                != getattr(abierto, "st_mtime_ns", None)
                or getattr(final, "st_ctime_ns", None)
                != getattr(abierto, "st_ctime_ns", None)):
            _fallar("PREFLIGHT_STATE_CHANGED" if recurso else codigo,
                    salida, recurso)
        return crudo
    except ErrorPreflight:
        raise
    except OSError:
        _fallar(codigo, salida, recurso)
    finally:
        os.close(fd)


def _ruta_estado(valor, base, usadas, recurso):
    if valor is None:
        return None
    if not isinstance(valor, str) or not valor or len(valor) > _MAX_RUTA:
        _fallar("PREFLIGHT_MANIFEST_INVALID", EXIT_MANIFEST)
    ruta = os.path.abspath(
        valor if os.path.isabs(valor) else os.path.join(base, valor))
    try:
        dentro = os.path.commonpath((base, ruta)) == base
    except ValueError:
        dentro = False
    if not dentro:
        _fallar("PREFLIGHT_PATH_OUTSIDE_DIRECTORY", EXIT_MANIFEST)
    if ruta in usadas:
        _fallar("PREFLIGHT_PATH_DUPLICATE", EXIT_MANIFEST)
    usadas.add(ruta)
    return ruta


def _leer_manifiesto(ruta_manifest):
    ruta_manifest = os.path.abspath(ruta_manifest)
    base = os.path.dirname(ruta_manifest)
    crudo = _leer_regular_privado(
        ruta_manifest, _MAX_MANIFEST_BYTES, EXIT_MANIFEST,
        "PREFLIGHT_MANIFEST_UNSAFE")
    datos = _json_estricto(
        crudo, EXIT_MANIFEST, "PREFLIGHT_MANIFEST_INVALID")
    if (not isinstance(datos, dict) or set(datos) != _CAMPOS_MANIFEST
            or type(datos.get("schema")) is not int
            or datos.get("schema") != 1):
        _fallar("PREFLIGHT_MANIFEST_INVALID", EXIT_MANIFEST)
    topologia = datos.get("topology")
    escritor = datos.get("writer")
    ips_gestion = datos.get("management_ips")
    observaciones = datos.get("observations")
    if (not isinstance(topologia, list)
            or not 1 <= len(topologia) <= _MAX_NODOS
            or any(not isinstance(nodo, str)
                   or not _PATRON_NODO.fullmatch(nodo) for nodo in topologia)
            or len(topologia) != len(set(topologia))
            or escritor != topologia[0]
            or not isinstance(ips_gestion, list)
            or len(ips_gestion) != len(topologia)
            or len(ips_gestion) != len(set(ips_gestion))
            or not isinstance(observaciones, list)
            or len(observaciones) > len(topologia)):
        _fallar("PREFLIGHT_MANIFEST_INVALID", EXIT_MANIFEST)
    for valor in ips_gestion:
        try:
            direccion = ipaddress.IPv4Address(valor)
            red = ipaddress.IPv4Network(f"{direccion}/24", strict=False)
        except (ipaddress.AddressValueError, TypeError):
            _fallar("PREFLIGHT_MANIFEST_INVALID", EXIT_MANIFEST)
        if (str(direccion) != valor or direccion.is_unspecified
                or direccion.is_loopback or direccion.is_multicast
                or direccion.is_link_local or direccion.is_reserved
                or direccion in {red.network_address, red.broadcast_address}):
            _fallar("PREFLIGHT_MANIFEST_INVALID", EXIT_MANIFEST)
    topologia_set = set(topologia)
    vistas = {}
    usadas = {ruta_manifest}
    for observacion in observaciones:
        if (not isinstance(observacion, dict)
                or not {"node"}.issubset(observacion)
                or set(observacion) - _CAMPOS_OBSERVACION):
            _fallar("PREFLIGHT_MANIFEST_INVALID", EXIT_MANIFEST)
        nodo = observacion.get("node")
        if (nodo not in topologia_set or nodo in vistas):
            _fallar("PREFLIGHT_MANIFEST_INVALID", EXIT_MANIFEST)
        vista = {}
        for recurso in ("pool", "security"):
            if recurso in observacion:
                vista[recurso] = _ruta_estado(
                    observacion[recurso], base, usadas, recurso)
        vistas[nodo] = vista
    return topologia, escritor, frozenset(ips_gestion), vistas, base


def _cargar_estado(ruta, base, recurso, escritor, ips_gestion):
    crudo = _leer_regular_privado(
        ruta, _MAX_SNAPSHOT_BYTES, EXIT_ESTADO,
        "PREFLIGHT_STATE_FILE_UNSAFE", base=base, recurso=recurso)
    datos = _json_estricto(
        crudo, EXIT_ESTADO, "PREFLIGHT_STATE_JSON_INVALID", recurso)
    try:
        if recurso == "pool":
            normalizado = pool.Pool.seleccionar_dominante([datos])
            huella = pool.Pool.huella(normalizado)
        else:
            normalizado = seguridad.AlmacenSeguridad.seleccionar_dominante(
                [datos])
            huella = seguridad.AlmacenSeguridad.huella(normalizado)
    except Exception:  # noqa: BLE001 - cualquier parser debe fallar cerrado.
        _fallar("PREFLIGHT_STATE_INVALID", EXIT_ESTADO, recurso)
    revision = normalizado.get("revision") or {}
    reloj = revision.get("clock") or {}
    if reloj and (revision.get("author") != escritor
                  or set(reloj) != {escritor}):
        _fallar("PREFLIGHT_STATE_IDENTITY_INVALID", EXIT_ESTADO, recurso)
    if recurso == "pool":
        for entrada in normalizado.get("direcciones") or []:
            try:
                direccion = ipaddress.IPv4Address(entrada.get("ip"))
                red = ipaddress.IPv4Network(f"{direccion}/24", strict=False)
            except (ipaddress.AddressValueError, AttributeError, TypeError):
                _fallar("PREFLIGHT_STATE_NETWORK_INVALID", EXIT_ESTADO, recurso)
            if (direccion.is_unspecified or direccion.is_loopback
                    or direccion.is_multicast or direccion.is_link_local
                    or direccion.is_reserved
                    or direccion in {red.network_address, red.broadcast_address}
                    or str(direccion) in ips_gestion):
                _fallar("PREFLIGHT_STATE_NETWORK_INVALID", EXIT_ESTADO, recurso)
    formato = "causal" if revision.get("clock") else "legacy"
    return normalizado, huella, formato


def _validar_recurso(recurso, topologia, escritor, ips_gestion, vistas, base,
                     permitir_fresh):
    quorum = len(topologia) // 2 + 1
    observadas = {
        nodo: vista[recurso]
        for nodo, vista in vistas.items() if recurso in vista
    }
    if len(observadas) < quorum:
        _fallar("PREFLIGHT_OBSERVATION_QUORUM_UNAVAILABLE",
                EXIT_COHERENCIA, recurso)
    ausentes = sum(ruta is None for ruta in observadas.values())
    presentes = {
        nodo: _cargar_estado(
            ruta, base, recurso, escritor, ips_gestion)
        for nodo, ruta in observadas.items() if ruta is not None
    }
    if not presentes:
        if not permitir_fresh:
            _fallar("PREFLIGHT_FRESH_EMPTY_NOT_ALLOWED",
                    EXIT_COHERENCIA, recurso)
        return {
            "status": "fresh-empty",
            "observed": len(observadas),
            "materialized": 0,
            "absent": ausentes,
            "quorum": quorum,
            "format": "absent",
            "formats": {},
            "fingerprint": None,
            "dominant_nodes": [],
        }
    if len(presentes) < quorum:
        _fallar("PREFLIGHT_MATERIALIZED_QUORUM_UNAVAILABLE",
                EXIT_COHERENCIA, recurso)
    candidatos = [entrada[0] for entrada in presentes.values()]
    try:
        if recurso == "pool":
            dominante = pool.Pool.seleccionar_dominante(candidatos)
            huella_dominante = pool.Pool.huella(dominante)
        else:
            dominante = seguridad.AlmacenSeguridad.seleccionar_dominante(
                candidatos)
            huella_dominante = seguridad.AlmacenSeguridad.huella(dominante)
    except Exception:  # noqa: BLE001 - nunca elegir tras un fallo inesperado.
        _fallar("PREFLIGHT_STATE_DIVERGENT", EXIT_COHERENCIA, recurso)
    formatos = Counter(entrada[2] for entrada in presentes.values())
    formato_dominante = (
        "causal" if (dominante.get("revision") or {}).get("clock")
        else "legacy"
    )
    return {
        "status": "recovery-ready" if ausentes else "ready",
        "observed": len(observadas),
        "materialized": len(presentes),
        "absent": ausentes,
        "quorum": quorum,
        "format": formato_dominante,
        "formats": dict(sorted(formatos.items())),
        "fingerprint": huella_dominante,
        "dominant_nodes": sorted(
            nodo for nodo, entrada in presentes.items()
            if entrada[1] == huella_dominante),
    }


def validar_preflight(ruta_manifest, permitir_fresh=False):
    """Valida ambos registros o lanza ``ErrorPreflight`` sin mutar disco."""
    topologia, escritor, ips_gestion, vistas, base = _leer_manifiesto(
        ruta_manifest)
    quorum = len(topologia) // 2 + 1
    resultado = {
        "schema": 1,
        "ok": True,
        "topology_size": len(topologia),
        "quorum": quorum,
    }
    for recurso in ("pool", "security"):
        resultado[recurso] = _validar_recurso(
            recurso, topologia, escritor, ips_gestion, vistas, base,
            permitir_fresh)
    return resultado


def _salida_error(error):
    salida = {
        "schema": 1,
        "ok": False,
        "error": {"code": error.codigo},
    }
    if error.recurso:
        salida["error"]["resource"] = error.recurso
    return salida


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Valida offline quorum y causalidad de pool/security")
    parser.add_argument("--manifest", required=True)
    parser.add_argument(
        "--allow-fresh-empty", action="store_true",
        help="autoriza explícitamente un cluster de instalación sin estado")
    args = parser.parse_args(argv)
    try:
        salida = validar_preflight(
            args.manifest, permitir_fresh=args.allow_fresh_empty)
        codigo = 0
    except ErrorPreflight as error:
        salida = _salida_error(error)
        codigo = error.salida
    print(json.dumps(
        salida, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return codigo


if __name__ == "__main__":
    sys.exit(main())
