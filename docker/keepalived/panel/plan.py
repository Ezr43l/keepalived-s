import os
import re

import configuracion
import pool as pool_mod

_AUTH_RE = re.compile(r"^[A-Za-z0-9._-]{1,8}$")


def _auth_pass():
    valor = configuracion.secreto("FIP_VRRP_AUTH_PASS", "FIP_VRRP_AUTH_FILE")
    if not _AUTH_RE.fullmatch(valor):
        raise ValueError("la clave VRRP no está configurada o no cumple el formato seguro (1-8 caracteres)")
    return valor


def _vip_prefijo():
    valor = os.environ.get("FIP_VIP_PREFIX", "24").strip()
    try:
        prefijo = int(valor)
    except ValueError as e:
        raise ValueError("FIP_VIP_PREFIX no es un numero") from e
    # El contrato de pool v1 reserva por último octeto (dhcp_desde), por lo
    # que sólo /24 tiene una interpretación inequívoca. Otros prefijos requieren
    # un modelo CIDR completo y se rechazan hasta una versión posterior.
    if prefijo != 24:
        raise ValueError("FIP_VIP_PREFIX debe ser 24 en el formato de pool v1")
    return prefijo

"""Decide en que servidor debe vivir cada direccion, y escribe la configuracion
de keepalived que lo hace cumplir.

Dos reglas, y la primera NO SE NEGOCIA:

  1. Si una direccion tiene servidor elegido y ese servidor esta disponible, va
     ahi. Punto. No la mueve el equilibrado, ni el reparto, ni nada que no sea
     que ese servidor deje de estar disponible.

  2. Las que NO tienen servidor elegido —o lo tienen caido o en mantenimiento—
     se reparten equilibradas entre los que quedan: entre dos servidores nunca
     puede haber dos direcciones de diferencia.

La colocacion explícita tiene precedencia sobre el equilibrio: representa una
decision operativa, no una sugerencia. El reparto automatico solo coloca lo que
nadie ha colocado; nunca mueve una direccion elegida para compensar carga.

Un servidor en mantenimiento no entra en el reparto: se le vacia entero.
"""

def _carga_inicial(disponibles):
    return {n: [] for n in disponibles}


def _menos_cargado(carga, disponibles):
    # El nombre solo resuelve empates. La prioridad VRRP no expresa salud ni
    # validez y por eso no participa en este calculo.
    return min(disponibles, key=lambda nombre: (
        carga[nombre] if isinstance(carga[nombre], int) else len(carga[nombre]),
        nombre))

def repartir(direcciones, nodos, mantenimiento):
    """Devuelve {nombre_direccion: nodo_donde_debe_vivir}.

    `direcciones` son dicts con al menos `servicio` y `preferente`.
    `nodos` conserva el orden declarado; la prioridad sólo ordena candidatos
    VRRP y no decide la identidad del escritor causal.
    """
    orden_base = [n["nombre"] for n in nodos]
    if not orden_base:
        return {}
    disponibles = [n for n in orden_base if n not in mantenimiento]

    # Si todos estan en mantenimiento, se conserva una configuracion
    # determinista para no perder el fichero generado.
    if not disponibles:
        disponibles = list(orden_base)

    carga = _carga_inicial(disponibles)
    asignado = {}

    pendientes = []
    fijas = []
    for d in direcciones:
        serv = d.get("servicio")
        if not serv:
            continue
        pref = d.get("preferente")
        if pref and pref in disponibles:
            fijas.append(d)
        else:
            pendientes.append(d)

    # Las decisiones humanas se contabilizan antes que las desplazadas.
    for d in fijas:
        destino = d["preferente"]
        asignado[d["servicio"]] = destino
        carga[destino].append(d["servicio"])

    for d in pendientes:
        destino = _menos_cargado(carga, disponibles)
        asignado[d["servicio"]] = destino
        carga[destino].append(d["servicio"])

    return asignado



def reparto_fallback(direcciones, nodos, mantenimiento):
    """Calcula la segunda opcion para cada destino normal."""
    orden_base = [n["nombre"] for n in nodos]
    normal = repartir(direcciones, nodos, mantenimiento)
    resultado = {}

    for fallido in orden_base:
        disponibles = [n for n in orden_base
                       if n != fallido and n not in mantenimiento]
        if not disponibles:
            continue

        carga = {n: 0 for n in disponibles}
        for d in direcciones:
            servicio = d.get("servicio")
            destino = normal.get(servicio)
            if destino in carga:
                carga[destino] += 1

        desplazadas = sorted(
            (d for d in direcciones if normal.get(d.get("servicio")) == fallido),
            key=lambda d: (d.get("ip") or "", d.get("servicio") or ""),
        )
        for d in desplazadas:
            destino = _menos_cargado(carga, disponibles)
            resultado.setdefault(d["servicio"], {})[fallido] = destino
            carga[destino] += 1

    return resultado


def orden_para(servicio, destino, nodos, mantenimiento, respaldo=None):
    """El orden de nodos para una direccion: primero donde debe vivir, luego el
    resto por prioridad base, y los que estan en mantenimiento al final.

    Los de mantenimiento siguen en la lista a proposito: si se levantara el
    mantenimiento, la configuracion ya es correcta sin regenerarla. Lo que los
    mantiene fuera mientras tanto es que su comprobacion falla.
    """
    orden_base = [
        n["nombre"] for n in sorted(
            nodos, key=lambda valor: (
                -int(valor.get("prioridad", 0)), valor["nombre"]))
    ]
    primeros = []
    for candidato in (destino, respaldo):
        if candidato in orden_base and candidato not in primeros:
            if candidato == destino or candidato not in mantenimiento:
                primeros.append(candidato)
    resto = [n for n in orden_base if n not in primeros and n not in mantenimiento]
    en_mant = [n for n in orden_base if n not in primeros and n in mantenimiento]
    return primeros + resto + en_mant


def prioridades(servicio, destino, nodos, mantenimiento, respaldo=None):
    orden = orden_para(servicio, destino, nodos, mantenimiento, respaldo)
    disponibles = sorted(
        {int(n["prioridad"]) for n in nodos}, reverse=True)
    if len(disponibles) != len(nodos):
        raise ValueError("cada nodo debe tener una prioridad VRRP distinta")
    return {
        nombre: disponibles[indice]
        for indice, nombre in enumerate(orden)
    }


CABECERA = """# GENERADO por el panel de direcciones flotantes — no editar a mano.
# Se reescribe cada vez que cambias el servidor de referencia de una direccion o
# pones un servidor en mantenimiento. Lo que mandas por pantalla acaba aqui.

global_defs {
    # Sin esto keepalived busca un usuario 'keepalived_script' que no existe y
    # lo deja dicho en cada arranque.
    script_user root
    enable_script_security
}
"""

BLOQUE = """
# «Responde» = {servicio} contesta EN ESTE NODO, no solo que la maquina este
# encendida. El guion vive DENTRO de la imagen: montado desde /boot no vale,
# porque el USB es FAT y no guarda el bit de ejecucion — keepalived lo detecta,
# desactiva la comprobacion, y el nodo puede quedarse la direccion aunque no
# sirva nada.
vrrp_script comprobar_{servicio} {{
    script  "/usr/local/bin/check-http {servicio} http://127.0.0.1:{puerto}{ruta}"
    interval 5
    timeout  4
    rise     2
    fall     2
    weight   0
}}

vrrp_instance {mayus} {{
    state           BACKUP
    interface       {iface}
    virtual_router_id {vrid}
    priority        {prioridad}
    advert_int      1
{preferencia}
    authentication {{
        auth_type PASS
        auth_pass {auth_pass}
    }}
    virtual_ipaddress {{
        {vip}/{vip_prefijo} dev {iface}
    }}
    track_script {{
        comprobar_{servicio}
    }}
}}
"""

SIN_REFERENCIA = """    # Sin servidor de referencia: la direccion se queda donde este. Nadie se la
    # quita al que la esta sirviendo bien; un salto de mas es un corte de mas.
    nopreempt"""

CON_REFERENCIA = """    # Vuelve a su servidor de referencia en cuanto responde otra vez. El retardo
    # evita que un arranque se la quite a quien la esta sirviendo antes de estar
    # listo de verdad; se suma a las dos comprobaciones seguidas que ya hacen
    # falta para darse por bueno.
    preempt_delay {delay}"""


def generar_conf(datos_pool, nodo, nodos, retardo=45):
    """La configuracion completa de ESTE nodo."""
    mantenimiento = set(datos_pool.get("mantenimiento") or [])
    activas = [d for d in datos_pool.get("direcciones", [])
               if d.get("estado") == "en_uso" and d.get("servicio") and d.get("chequeo")]
    destinos = repartir(activas, nodos, mantenimiento)
    respaldos = reparto_fallback(activas, nodos, mantenimiento)
    vip_prefijo = _vip_prefijo()

    auth_pass = _auth_pass()
    partes = [CABECERA]
    iface = next((n["interfaz"] for n in nodos if n["nombre"] == nodo), None)
    for d in activas:
        serv = d["servicio"]
        destino = destinos.get(serv)
        respaldo = (respaldos.get(serv) or {}).get(destino)
        prios = prioridades(serv, destino, nodos, mantenimiento, respaldo)
        ch = d.get("chequeo") or {}
        if d.get("preferente"):
            pref = CON_REFERENCIA.format(delay=retardo)
        else:
            pref = SIN_REFERENCIA
        partes.append(BLOQUE.format(
            servicio=serv,
            mayus=pool_mod.identificador_vrrp(serv),
            iface=iface,
            vrid=d.get("vrid"),
            prioridad=prios.get(nodo, 10),
            vip=d.get("ip"),
            puerto=ch.get("puerto"),
            ruta=ch.get("ruta"),
            preferencia=pref,
            auth_pass=auth_pass,
            vip_prefijo=vip_prefijo,
        ))
    return "".join(partes)
