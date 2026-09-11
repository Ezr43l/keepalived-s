/* Panel de direcciones flotantes.
 *
 * Se refresca solo cada 6 s. Todo el estado vive en el servidor; aqui no se
 * guarda nada entre recargas a proposito, para que lo que ves sea siempre lo
 * que hay y no una copia que se quedo vieja.
 *
 * Sobre las palabras: nada de «drenar» ni «sano». Un servidor esta EN SERVICIO
 * o EN MANTENIMIENTO, y un servicio RESPONDE o NO RESPONDE. Quien opera esto no
 * tiene por que hablar en fontanero.
 */
'use strict';

const REFRESCO = 6000;
let temporizador = null;
let ocupado = false;
let refrescando = false;
let refrescoPendiente = false;
let selectorProtegido = false;
let vridsOcupados = new Set();

const $ = (sel) => document.querySelector(sel);

function texto(etiqueta, contenido, clase) {
  const el = document.createElement(etiqueta);
  if (clase) el.className = clase;
  if (contenido !== undefined && contenido !== null) el.textContent = String(contenido);
  return el;
}

const TRAZOS_ICONOS = {
  cambiar: ['M5 12.5l4 4L19 7'],
  liberar: ['M7 10V7a5 5 0 0 1 9.5-2', 'M5 10h14v10H5z', 'M12 14v2'],
  eliminar: ['M4 7h16', 'M9 7V4h6v3', 'M7 7l1 13h8l1-13', 'M10 11v5', 'M14 11v5'],
  aviso: ['M12 3L2.5 20h19z', 'M12 9v5', 'M12 17h.01'],
};

function iconoAccion(nombre) {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');
  for (const d of TRAZOS_ICONOS[nombre] || []) {
    const path = document.createElementNS(ns, 'path');
    path.setAttribute('d', d);
    path.setAttribute('fill', 'none');
    path.setAttribute('stroke', 'currentColor');
    path.setAttribute('stroke-width', '1.8');
    path.setAttribute('stroke-linecap', 'round');
    path.setAttribute('stroke-linejoin', 'round');
    svg.append(path);
  }
  return svg;
}

function botonIcono(icono, etiqueta, clase) {
  const b = texto('button', null, 'boton-icono ' + clase);
  b.type = 'button';
  b.title = etiqueta;
  b.setAttribute('aria-label', etiqueta);
  b.append(iconoAccion(icono));
  return b;
}

function confirmarEnPanel(opciones) {
  const dialogo = $('#dialogo-confirmacion');
  if (!dialogo || dialogo.open) return Promise.resolve(false);

  $('#dialogo-titulo').textContent = opciones.titulo || 'Confirmar acción';
  const cuerpo = $('#dialogo-cuerpo');
  cuerpo.textContent = '';
  for (const mensaje of (opciones.mensajes || [])) {
    cuerpo.append(texto('p', mensaje));
  }
  if ((opciones.elementos || []).length) {
    const lista = document.createElement('ul');
    for (const elemento of opciones.elementos) {
      const item = texto('li', typeof elemento === 'string' ? elemento : elemento.texto);
      if (elemento && elemento.peligro) item.classList.add('riesgo');
      lista.append(item);
    }
    cuerpo.append(lista);
  }

  const bloqueAceptacion = $('#dialogo-aceptacion');
  const casilla = $('#dialogo-casilla');
  const boton = $('#dialogo-confirmar');
  const exigeAceptacion = Boolean(opciones.aceptacion);
  bloqueAceptacion.classList.toggle('oculto', !exigeAceptacion);
  casilla.checked = false;
  $('#dialogo-texto-aceptacion').textContent = opciones.aceptacion || '';
  boton.textContent = opciones.accion || 'Confirmar';
  boton.className = 'accion-dialogo' + (opciones.peligro ? ' peligro' : '');
  boton.disabled = exigeAceptacion;
  casilla.onchange = () => { boton.disabled = exigeAceptacion && !casilla.checked; };

  dialogo.returnValue = 'cancelar';
  return new Promise((resolve) => {
    dialogo.addEventListener('close', () => {
      resolve(dialogo.returnValue === 'confirmar');
    }, { once: true });
    dialogo.showModal();
    (exigeAceptacion ? casilla : boton).focus();
  });
}

function respuestaEnMs(valor) {
  if (typeof valor !== 'number' || !Number.isFinite(valor) || valor < 0) return null;
  return valor.toLocaleString('es-ES', { maximumFractionDigits: 1 }) + ' ms';
}

function recado(donde, mensaje, bien) {
  const el = $(donde);
  el.textContent = mensaje || '';
  el.className = 'recado ' + (bien ? 'bien' : 'mal') + (mensaje ? '' : ' oculto');
}

async function api(ruta, opciones) {
  return window.FIPAuth.request(ruta, opciones);
}

function puedeOperar() {
  const actual = window.FIPAuth.session();
  return Boolean(actual && ['operator', 'admin'].includes(actual.role));
}

function esSelectorServidor(elemento) {
  return elemento && elemento.matches && elemento.matches('#cuerpo-direcciones .selector-servidor');
}

function selectorEnUso() {
  return selectorProtegido || esSelectorServidor(document.activeElement);
}

function puertosDe(direccion) {
  const declarados = Array.isArray(direccion.puertos) ? direccion.puertos : [];
  const puertos = new Set();
  for (const puerto of declarados) {
    const numero = Number(puerto);
    if (Number.isInteger(numero) && numero >= 1 && numero <= 65535) puertos.add(numero);
  }
  // Compatibilidad con registros antiguos que sólo tenían la comprobación.
  if (!puertos.size) {
    const chequeo = direccion.chequeo && Number(direccion.chequeo.puerto);
    if (Number.isInteger(chequeo) && chequeo >= 1 && chequeo <= 65535) puertos.add(chequeo);
  }
  return [...puertos].sort((a, b) => a - b);
}

function urlServicio(ip, puerto) {
  const protocolo = puerto === 443 ? 'https' : 'http';
  const visible = (puerto === 80 || puerto === 443) ? '' : ':' + puerto;
  return protocolo + '://' + ip + visible + '/';
}

function enlacesServicio(direccion, puertos) {
  const caja = texto('div', null, 'enlaces-servicio');
  if (direccion.estado !== 'en_uso') return caja;
  for (const puerto of (puertos || puertosDe(direccion))) {
    const enlace = texto('a', null, 'enlace-servicio');
    enlace.href = urlServicio(direccion.ip, puerto);
    enlace.target = '_blank';
    enlace.rel = 'noopener noreferrer';
    enlace.title = 'Abrir ' + (direccion.servicio || 'servicio') + ' en el puerto ' + puerto;
    enlace.setAttribute('aria-label', enlace.title);
    enlace.append(texto('span', String(puerto), 'puerto-enlace'));
    enlace.append(texto('span', '↗', 'icono-enlace'));
    caja.append(enlace);
  }
  return caja;
}

function pintarVersion(version) {
  const el = $('#version');
  if (!el) return;
  const valor = version && (version.version || version.producto);
  el.textContent = valor ? 'VERSIÓN v' + valor : 'VERSIÓN NO DISPONIBLE';
}

/* ── servidores ──────────────────────────────────────────────────────── */
function pintarNodos(datos, cuadro) {
  const rejilla = $('#rejilla-nodos');
  rejilla.textContent = '';
  const enMantenimiento = new Set(cuadro.mantenimiento || []);

  for (const n of (datos.nodos || [])) {
    const mant = enMantenimiento.has(n.nodo);
    const t = texto('div', null, 'tarjeta' + (n.alcanzable ? '' : ' caida') + (mant ? ' mantenimiento' : ''));

    const cab = document.createElement('header');
    cab.append(texto('h3', n.nodo));
    cab.append(texto('span', n.ip || '', 'desc'));
    cab.append(texto('span', mant ? 'EN MANTENIMIENTO' : 'EN SERVICIO',
                     'insignia ' + (mant ? 'parada' : 'viva')));
    t.append(cab);

    if (!n.alcanzable) {
      t.append(texto('div', 'No se llega a este servidor. Lo que se muestre de él puede estar anticuado.', 'veredicto peligro'));
      const pieCaido = texto('div', null, 'acciones-nodo solo-operador');
      const bCaido = texto('button', 'Servidor no disponible', 'peligro');
      bCaido.disabled = true;
      pieCaido.append(bCaido);
      t.append(pieCaido);
      rejilla.append(t);
      continue;
    }

    const direcciones = n.si_lo_paras || [];
    const sinRespaldo = direcciones.filter((c) => c.sin_red);
    const clase = mant ? 'drena' : sinRespaldo.length ? 'aviso' : direcciones.length ? 'bien' : '';
    const resumen = texto('div', null, 'veredicto ' + clase);
    const cabResumen = texto('div', null, 'resumen-direcciones');
    cabResumen.append(texto('strong', direcciones.length + ' IP '
      + (direcciones.length === 1 ? 'flotante' : 'flotantes')));
    if (!direcciones.length) {
      cabResumen.append(texto('span', mant ? 'Servidor en mantenimiento' : 'Sin direcciones activas'));
    }
    resumen.append(cabResumen);
    if (direcciones.length) {
      const lista = texto('div', null, 'lista-direcciones-nodo');
      for (const direccion of direcciones) {
        const fila = texto('div', null, 'direccion-nodo');
        fila.append(texto('span', direccion.ip, 'ip-nodo'));
        fila.append(texto('span', direccion.servicio || 'sin servicio', 'servicio-nodo'));
        const metricas = texto('span', null, 'metricas-servicio');
        const tiempo = respuestaEnMs(direccion.respuesta_ms);
        if (direccion.sin_red) {
          const riesgo = texto('span', null, 'aviso-respaldo');
          riesgo.title = 'Este servicio sólo tiene un nodo activo';
          riesgo.setAttribute('aria-label', riesgo.title);
          riesgo.append(iconoAccion('aviso'));
          metricas.append(riesgo);
        }
        if (direccion.sano === false) {
          const fallo = texto('span', 'sin respuesta', 'respuesta-servicio fallo');
          fallo.title = direccion.detalle || 'El chequeo de salud no responde';
          metricas.append(fallo);
        } else if (tiempo) {
          const respuesta = texto('span', tiempo, 'respuesta-servicio');
          respuesta.title = 'Tiempo de respuesta del chequeo local en este servidor';
          metricas.append(respuesta);
        }
        fila.append(metricas);
        lista.append(fila);
      }
      resumen.append(lista);
    }
    t.append(resumen);

    const pie = texto('div', null, 'acciones-nodo solo-operador');
    const b = texto('button', mant ? 'Devolver a servicio' : 'Poner en mantenimiento',
                    mant ? 'activo' : 'peligro');
    b.disabled = ocupado || (!mant && n.ultimo_en_servicio === true);
    if (!mant && n.ultimo_en_servicio === true) {
      b.title = 'Es el último servidor en servicio y no puede ponerse en mantenimiento.';
    }
    b.onclick = () => cambiarMantenimiento(n.nodo, !mant, n);
    pie.append(b);
    t.append(pie);
    rejilla.append(t);
  }
}

/* ── direcciones ─────────────────────────────────────────────────────── */
function pintarDirecciones(cuadro) {
  const cuerpo = $('#cuerpo-direcciones');
  cuerpo.textContent = '';
  const filas = cuadro.direcciones || [];
  const nodos = cuadro.orden_nodos || [];
  const enMant = new Set(cuadro.mantenimiento || []);

  if (!filas.length) {
    const tr = document.createElement('tr');
    const td = texto('td', 'Todavía no hay ninguna dirección anotada.', 'vacio');
    td.colSpan = 6;
    tr.append(td);
    cuerpo.append(tr);
    return;
  }

  for (const d of filas) {
    const tr = document.createElement('tr');

    // La dirección y su identificador, juntos. No estaba en ningún sitio de la
    // lista, así que para elegir uno nuevo había que adivinar cuáles estaban
    // cogidos — o irse a los datos en bruto.
    const tdIp = document.createElement('td');
    tdIp.dataset.etiqueta = 'Dirección';
    tdIp.append(texto('div', d.ip, 'ip'));
    if (d.vrid) tdIp.append(texto('div', 'id ' + d.vrid, 'vrid'));
    tr.append(tdIp);

    const tdServicio = document.createElement('td');
    tdServicio.dataset.etiqueta = 'Servicio';
    if (d.servicio) tdServicio.append(texto('div', d.servicio, 'servicio'));
    if (d.descripcion) tdServicio.append(texto('div', d.descripcion, 'desc'));
    if (!d.servicio && !d.descripcion) tdServicio.append(texto('span', '—', 'desc'));
    tr.append(tdServicio);

    const tdPuertos = document.createElement('td');
    tdPuertos.dataset.etiqueta = 'Puertos';
    const puertos = puertosDe(d);
    if (puertos.length) {
      if (d.estado === 'en_uso') {
        const enlaces = enlacesServicio(d, puertos);
        if (enlaces.childElementCount) tdPuertos.append(enlaces);
      } else {
        tdPuertos.append(texto('span', puertos.join(', '), 'puertos'));
      }
    } else {
      tdPuertos.append(texto('span', '—', 'desc'));
    }
    tr.append(tdPuertos);

    // Donde esta de verdad, y si responde en cada servidor.
    const tdDonde = document.createElement('td');
    tdDonde.dataset.etiqueta = 'Ahora en';
    if (d.estado === 'en_uso') {
      const caja = texto('div', null, 'donde' + (d.duplicada ? ' duplicada' : ''));
      const chips = texto('div', null, 'nodos');
      for (const nombre of nodos) {
        const info = (d.nodos || {})[nombre] || {};
        const c = texto('span', null, 'ficha');
        const sostiene = info.sostenida === true;
        const disponible = info.alcanzable && info.sano === true && !enMant.has(nombre);
        if (sostiene) c.classList.add('sostiene');
        else if (disponible) c.classList.add('disponible');
        else c.classList.add('no-disponible');
        c.append(texto('span', null, 'punto'), texto('span', nombre));
        c.title = nombre + ': ' + (sostiene ? 'sostiene esta dirección'
                 : disponible ? 'disponible para sostenerla'
                 : !info.alcanzable ? 'servidor no accesible'
                 : enMant.has(nombre) ? 'servidor en mantenimiento'
                 : 'el servicio no está disponible aquí');
        chips.append(c);
      }
      caja.append(chips);
      const avisos = [];
      if (d.duplicada) avisos.push('Avería: la dirección está activa en varios servidores.');
      if (d.sin_red) avisos.push('Sin respaldo: ningún otro servidor puede recogerla.');
      if (avisos.length) tdDonde.title = avisos.join(' ');
      tdDonde.append(caja);
    } else {
      tdDonde.append(texto('span', '—', 'desc'));
    }
    tr.append(tdDonde);

    // Servidor asignado, editable.
    const tdAsig = document.createElement('td');
    tdAsig.dataset.etiqueta = 'Servidor por defecto';
    const bCambiar = botonIcono('cambiar', 'Aplicar servidor por defecto', 'accion-cambiar');
    bCambiar.disabled = true;
    let detalleAsignacion = '';
    if (d.estado === 'en_uso') {
      const caja = texto('div', null, 'asignar');
      const sel = document.createElement('select');
      sel.className = 'selector-servidor';
      sel.disabled = ocupado || !puedeOperar();
      const sin = document.createElement('option');
      sin.value = '';
      sin.textContent = 'Ninguno';
      sel.append(sin);
      const disponibles = nodos.filter((nombre) => {
        const info = (d.nodos || {})[nombre] || {};
        return info.alcanzable && info.sano === true && !enMant.has(nombre);
      });
      for (const nombre of disponibles) {
        const o = document.createElement('option');
        o.value = nombre;
        o.textContent = nombre;
        sel.append(o);
      }
      if (d.preferente && !disponibles.includes(d.preferente)) {
        detalleAsignacion = 'Servidor por defecto no disponible: ' + d.preferente;
      }
      sel.value = d.preferente && disponibles.includes(d.preferente) ? d.preferente : '';
      bCambiar.disabled = ocupado || !puedeOperar() || sel.value === (d.preferente || '');
      sel.onchange = () => {
        bCambiar.disabled = ocupado || !puedeOperar() || sel.value === (d.preferente || '');
      };
      bCambiar.onclick = () => cambiarAsignado(d, sel.value);
      caja.append(sel);
      const previsto = cuadro.asignado ? cuadro.asignado[d.servicio] : null;
      if (previsto && d.portador && previsto !== d.portador
          && d.nodos && d.nodos[previsto] && d.nodos[previsto].alcanzable
          && d.nodos[previsto].sano === true) {
        detalleAsignacion = 'Moviéndose a ' + previsto + '…';
      } else if (d.preferente && d.portador && d.preferente !== d.portador) {
        detalleAsignacion = 'Volverá a ' + d.preferente + ' cuando responda.';
      }
      if (detalleAsignacion) caja.classList.add('con-aviso');
      tdAsig.append(caja);
    } else if (d.estado === 'libre') {
      tdAsig.append(texto('span', 'Libre', 'etiqueta-libre'));
    } else {
      tdAsig.append(texto('span', '—', 'desc'));
    }
    if (detalleAsignacion) tdAsig.title = detalleAsignacion;
    tr.append(tdAsig);

    const tdAcc = document.createElement('td');
    tdAcc.className = 'celda-acciones solo-operador';
    tdAcc.dataset.etiqueta = 'Acciones';
    const acc = texto('div', null, 'acciones');
    acc.append(bCambiar);

    const libre = d.estado === 'libre';
    const bLib = botonIcono('liberar', 'Liberar la dirección', 'accion-liberar');
    bLib.disabled = ocupado || libre;
    bLib.onclick = () => liberar(d.ip, d.servicio);
    acc.append(bLib);

    const bBaja = botonIcono('eliminar', libre
      ? 'Eliminar la dirección del registro'
      : 'Primero hay que liberar la dirección', 'accion-eliminar');
    bBaja.disabled = ocupado || !libre;
    bBaja.onclick = () => darDeBaja(d.ip);
    acc.append(bBaja);
    tdAcc.append(acc);
    tr.append(tdAcc);

    cuerpo.append(tr);
  }
}

/* ── acciones ────────────────────────────────────────────────────────── */
async function conBloqueo(fn) {
  // Mientras se aplica un cambio se desactivan los botones: dos ordenes a la
  // vez sobre el mismo reparto acabarian peleandose.
  ocupado = true;
  try { await fn(); } finally { ocupado = false; }
  await refrescar();
}

async function cambiarMantenimiento(nodo, activo, info) {
  const direcciones = info.si_lo_paras || [];
  const inmovibles = direcciones.filter((c) => c.sin_red);
  let opciones;
  if (activo) {
    const movibles = direcciones.length - inmovibles.length;
    const mensajes = [direcciones.length
      ? 'Este servidor sostiene ' + direcciones.length + ' IP '
        + (direcciones.length === 1 ? 'flotante.' : 'flotantes.')
      : 'Este servidor no sostiene ninguna IP flotante.'];
    if (movibles) {
      mensajes.push(movibles + (movibles === 1
        ? ' dirección podrá moverse a otro servidor.'
        : ' direcciones podrán moverse a otros servidores.'));
    }
    if (inmovibles.length) {
      mensajes.push(inmovibles.length + (inmovibles.length === 1
        ? ' servicio no podrá moverse y quedará sin IP flotante.'
        : ' servicios no podrán moverse y quedarán sin IP flotante.'));
    }
    mensajes.push('El servidor dejará de coger direcciones hasta que vuelva a servicio.');
    opciones = {
      titulo: 'Poner ' + nodo + ' en mantenimiento',
      mensajes,
      elementos: direcciones.map((c) => ({
        texto: c.ip + ' · ' + (c.servicio || 'sin servicio')
          + (c.sin_red ? ' · NO PUEDE MOVERSE' : ' · se moverá'),
        peligro: c.sin_red,
      })),
      aceptacion: inmovibles.length
        ? 'Acepto que ' + inmovibles.length + (inmovibles.length === 1
          ? ' servicio quedará sin IP flotante.' : ' servicios quedarán sin IP flotante.')
        : null,
      accion: 'Entrar en mantenimiento',
      peligro: true,
    };
  } else {
    opciones = {
      titulo: 'Devolver ' + nodo + ' a servicio',
      mensajes: ['Volverá a admitir direcciones y recuperará las que lo tengan asignado.'],
      accion: 'Devolver a servicio',
    };
  }
  if (!await confirmarEnPanel(opciones)) return;
  recado('#recado-global', '');
  return conBloqueo(async () => {
    try {
      await api('api/mantenimiento', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          nodo,
          activo,
          direcciones_sin_respaldo_aceptadas: activo ? inmovibles.map((c) => c.ip) : [],
        }),
      });
    } catch (e) {
      recado('#recado-global', 'No se pudo cambiar el modo mantenimiento: ' + e.message);
    }
  });
}

async function cambiarAsignado(d, nodo) {
  const opciones = nodo ? {
    titulo: 'Cambiar servidor por defecto',
    mensajes: [
      'Asignar ' + d.ip + ' (' + d.servicio + ') a ' + nodo + '.',
      'La dirección se moverá allí en unos segundos y podrá volver si el servidor se recupera.',
    ],
    accion: 'Cambiar servidor',
  } : {
    titulo: 'Quitar servidor por defecto',
    mensajes: [
      'Dejar ' + d.ip + ' sin servidor por defecto.',
      'Se quedará donde esté mientras funcione.',
    ],
    accion: 'Dejar sin asignar',
  };
  if (!await confirmarEnPanel(opciones)) return;
  recado('#recado-global', '');
  return conBloqueo(async () => {
    try {
      // Puerta propia. El resto de la API no puede tocar dónde descansa una
      // dirección, y ésta sólo sirve para eso: quien coge una dirección decide
      // para qué la usa, no en qué servidor vive.
      await api('api/pool/' + d.ip + '/servidor', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ servidor: nodo || null }),
      });
    } catch (e) {
      recado('#recado-global', 'No se pudo cambiar el servidor asignado: ' + e.message);
    }
  });
}

async function liberar(ip, servicio) {
  if (!await confirmarEnPanel({
    titulo: 'Liberar dirección',
    mensajes: [
      'Liberar ' + ip + (servicio ? ' de «' + servicio + '».' : '.'),
      'Volverá al conjunto de direcciones libres. Si un servicio la usa, se quedará sin IP flotante.',
    ],
    accion: 'Liberar',
    peligro: true,
  })) return;
  recado('#recado-global', '');
  return conBloqueo(async () => {
    try {
      await api('api/pool/' + ip, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ estado: 'libre' }),
      });
    } catch (e) {
      recado('#recado-global', 'No se pudo liberar: ' + e.message);
    }
  });
}

async function darDeBaja(ip) {
  if (!await confirmarEnPanel({
    titulo: 'Eliminar dirección',
    mensajes: ['Eliminar ' + ip + ' del registro.', 'Sólo puede hacerse si está libre.'],
    accion: 'Continuar',
    peligro: true,
  })) return;
  if (!await confirmarEnPanel({
    titulo: 'Confirmación final',
    mensajes: [
      'Eliminar definitivamente ' + ip + '.',
      'Desaparecerá del pool y su VRID volverá a estar disponible.',
    ],
    aceptacion: 'Entiendo que esta acción no se puede deshacer desde el panel.',
    accion: 'Eliminar definitivamente',
    peligro: true,
  })) return;
  recado('#recado-global', '');
  return conBloqueo(async () => {
    try {
      await api('api/pool/' + ip, { method: 'DELETE' });
    } catch (e) {
      recado('#recado-global', 'No se pudo quitar: ' + e.message);
    }
  });
}

const TEXTO_AYUDA_VRID = 'Primer ID libre.';
const campoVrid = $('#campo-vrid');

function validarVridCampo() {
  const ayuda = $('#ayuda-vrid');
  const valor = campoVrid.value.trim();
  campoVrid.setCustomValidity('');
  ayuda.textContent = TEXTO_AYUDA_VRID;
  ayuda.classList.remove('no-disponible');

  if (!valor) return;
  if (!/^\d{1,3}$/.test(valor) || Number(valor) < 1 || Number(valor) > 255) {
    const mensaje = 'Usa un ID entre 1 y 255.';
    campoVrid.setCustomValidity(mensaje);
    ayuda.textContent = mensaje;
    ayuda.classList.add('no-disponible');
    return;
  }
  if (vridsOcupados.has(Number(valor))) {
    const mensaje = 'El ID ' + Number(valor) + ' no está disponible.';
    campoVrid.setCustomValidity(mensaje);
    ayuda.textContent = mensaje;
    ayuda.classList.add('no-disponible');
  }
}

// Si lo escribes tú, el refresco no te lo pisa. Que un campo cambie solo
// mientras lo estás rellenando es de las cosas más molestas que puede hacer una
// pantalla.
campoVrid.addEventListener('input', (ev) => {
  ev.target.dataset.aMano = ev.target.value ? '1' : '0';
  validarVridCampo();
});

$('#form-alta').addEventListener('submit', (ev) => {
  ev.preventDefault();
  const f = new FormData(ev.target);
  const cuerpo = {
    ip: (f.get('ip') || '').trim(),
    vrid: parseInt(f.get('vrid'), 10),
    estado: 'libre',
    servicio: null,
    descripcion: (f.get('descripcion') || '').trim(),
  };
  const boton = $('#boton-alta');
  boton.disabled = true;
  recado('#recado-alta', '');
  conBloqueo(async () => {
    try {
      await api('api/pool', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(cuerpo),
      });
      ev.target.reset();
      // Se olvida que lo habías escrito a mano, para que el refresco vuelva a
      // proponer el primero libre en vez de dejar el campo vacío.
      campoVrid.dataset.aMano = '0';
      recado('#recado-alta', cuerpo.ip + ' anotada. No se ha puesto en marcha nada.', true);
    } catch (e) {
      recado('#recado-alta', e.message);
    } finally {
      boton.disabled = false;
    }
  });
});

/* ── refresco ────────────────────────────────────────────────────────── */
async function refrescar() {
  // Reconstruir la tabla mientras el selector nativo esta abierto lo destruye
  // y cierra el desplegable. Se espera a que termine la interaccion; despues se
  // hace una lectura para recuperar cualquier cambio que haya ocurrido.
  if (ocupado || selectorEnUso()) {
    refrescoPendiente = true;
    return;
  }
  if (refrescando) {
    refrescoPendiente = true;
    return;
  }
  refrescando = true;
  try {
    const [cuadro, nodos, pool] = await Promise.all([
      api('api/direcciones'),
      api('api/nodos'),
      api('api/pool'),
    ]);
    // El selector puede haberse abierto mientras las tres peticiones estaban
    // en vuelo. Compruébalo también justo antes de pintar: de lo contrario un
    // resultado que llega tarde volvería a cerrar el desplegable.
    if (ocupado || selectorEnUso()) {
      refrescoPendiente = true;
      return;
    }
    pintarNodos(nodos, cuadro);
    pintarDirecciones(cuadro);
    pintarVersion(cuadro.version);

    vridsOcupados = new Set(pool.vrids_ocupados || []);
    const aMano = campoVrid.dataset.aMano === '1';
    if (pool.vrid_sugerido
        && (!campoVrid.value || (!aMano && vridsOcupados.has(Number(campoVrid.value))))) {
      campoVrid.value = pool.vrid_sugerido;
    }
    validarVridCampo();

    const enMant = (cuadro.mantenimiento || []).length;
    $('#sub').textContent = 'atendido por ' + (cuadro.yo || '?')
      + ' · ' + (pool.direcciones || []).length + ' direcciones'
      + (enMant ? ' · ' + enMant + ' en mantenimiento' : '');
    $('#pie-nodo').textContent = 'panel de ' + (cuadro.yo || '?');
    const l = $('#latido');
    l.className = 'latido';
    l.innerHTML = 'al día <b>' + new Date().toLocaleTimeString('es-ES') + '</b>';
  } catch (e) {
    const l = $('#latido');
    l.className = 'latido error';
    l.innerHTML = 'sin contacto <b>!</b>';
    recado('#recado-global', 'No se pudo leer el estado: ' + e.message);
  } finally {
    refrescando = false;
    if (refrescoPendiente && !ocupado && !selectorEnUso()) {
      refrescoPendiente = false;
      setTimeout(refrescar, 0);
    }
  }
}

function iniciarPanel() {
  if (temporizador) return;
  refrescar();
  temporizador = setInterval(refrescar, REFRESCO);
}

function detenerPanel() {
  clearInterval(temporizador);
  temporizador = null;
  refrescando = false;
  refrescoPendiente = false;
  ocupado = false;
}

window.keepalivedPanel = { iniciar: iniciarPanel, detener: detenerPanel, refrescar };

document.addEventListener('visibilitychange', () => {
  clearInterval(temporizador);
  temporizador = null;
  if (!document.hidden && window.FIPAuth.session()) iniciarPanel();
});

// `select` se crea al pintar la tabla, por eso estos listeners son delegados.
// El foco dura mientras el desplegable nativo esta abierto en escritorio y en
// movil; al perderlo se aplica el refresco que se hubiera aplazado.
document.addEventListener('focusin', (ev) => {
  if (esSelectorServidor(ev.target)) selectorProtegido = true;
});
document.addEventListener('focusout', (ev) => {
  if (!esSelectorServidor(ev.target)) return;
  setTimeout(() => {
    if (!esSelectorServidor(document.activeElement)) {
      selectorProtegido = false;
      if (refrescoPendiente) {
        refrescoPendiente = false;
        refrescar();
      }
    }
  }, 0);
});

window.FIPAuth.start(iniciarPanel);
