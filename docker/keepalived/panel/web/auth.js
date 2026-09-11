/* Acceso, perfiles, 2FA, usuarios y credenciales de aplicaciones. */
'use strict';

(function () {
  const MUTACIONES = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
  const ETIQUETAS_ROL = { reader: 'Consulta', operator: 'Operador', admin: 'Administrador' };
  const ETIQUETAS_SCOPE = {
    'status:read': 'Consultar estado',
    'claims:write': 'Reclamar y liberar direcciones',
  };
  const VISTAS_CUENTA = {
    perfil: {
      sobrelinea: 'CUENTA', titulo: 'Mi perfil',
      descripcion: 'Identidad y nombre visible de la sesión actual.',
    },
    seguridad: {
      sobrelinea: 'PROTECCIÓN DE LA CUENTA', titulo: 'Seguridad',
      descripcion: 'Contraseña, segundo factor, recuperación y controles de acceso.',
    },
    usuarios: {
      sobrelinea: 'ADMINISTRACIÓN', titulo: 'Usuarios',
      descripcion: 'Cuentas personales, permisos y restablecimiento de accesos.',
    },
    api: {
      sobrelinea: 'INTEGRACIONES', titulo: 'Claves API',
      descripcion: 'Credenciales independientes y permisos limitados para aplicaciones.',
    },
    configuracion: {
      sobrelinea: 'CONFIGURACIÓN DEL SERVICIO', titulo: 'Configuración',
      descripcion: 'Topología, red y comportamiento de este contenedor Keepalived.',
    },
  };
  let sesion = null;
  let estado = null;
  let alPrepararPanel = null;
  let panelIniciado = false;
  let pestanaActual = 'estado';
  let preparacion2FA = null;
  let secretosVisibles = [];
  let tituloSecreto = '';
  let vistaSecreto = null;

  const $ = (selector) => document.querySelector(selector);

  class ErrorAPI extends Error {
    constructor(mensaje, codigo, estadoHttp, detalle) {
      super(mensaje);
      this.name = 'ErrorAPI';
      this.code = codigo || 'REQUEST_ERROR';
      this.status = estadoHttp;
      this.detail = detalle;
    }
  }

  function nodo(etiqueta, clase, contenido) {
    const elemento = document.createElement(etiqueta);
    if (clase) elemento.className = clase;
    if (contenido !== undefined && contenido !== null) elemento.textContent = String(contenido);
    return elemento;
  }

  function boton(texto, clase, tipo = 'button') {
    const elemento = nodo('button', clase, texto);
    elemento.type = tipo;
    return elemento;
  }

  function campo(etiqueta, nombre, tipo = 'text', opciones = {}) {
    const bloque = nodo('label', opciones.clase || 'campo-formulario');
    bloque.append(nodo('span', null, etiqueta));
    const entrada = document.createElement('input');
    entrada.name = nombre;
    entrada.type = tipo;
    entrada.value = opciones.valor || '';
    if (opciones.autocomplete) entrada.autocomplete = opciones.autocomplete;
    if (opciones.maxlength) entrada.maxLength = opciones.maxlength;
    if (opciones.placeholder) entrada.placeholder = opciones.placeholder;
    bloque.append(entrada);
    if (opciones.ayuda) bloque.append(nodo('em', 'ayuda', opciones.ayuda));
    return bloque;
  }

  function recadoFormulario(formulario, mensaje, bien = false) {
    let caja = formulario.querySelector('.recado-formulario');
    if (!caja) {
      caja = nodo('div', 'recado recado-formulario oculto');
      formulario.append(caja);
    }
    caja.textContent = mensaje || '';
    caja.className = 'recado recado-formulario ' + (bien ? 'bien' : 'mal')
      + (mensaje ? '' : ' oculto');
  }

  function aviso(mensaje, bien = true) {
    const caja = $('#avisos-app');
    const elemento = nodo('div', 'aviso-app ' + (bien ? 'bien' : 'mal'), mensaje);
    caja.append(elemento);
    setTimeout(() => elemento.classList.add('sale'), 4200);
    setTimeout(() => elemento.remove(), 4700);
  }

  function valor(formulario, nombre) {
    return String(new FormData(formulario).get(nombre) || '').trim();
  }

  async function request(ruta, opciones = {}) {
    const configuracion = { ...opciones, credentials: 'same-origin' };
    const metodo = String(configuracion.method || 'GET').toUpperCase();
    const cabeceras = new Headers(configuracion.headers || {});
    if (MUTACIONES.has(metodo) && sesion && sesion.csrf_token
        && !cabeceras.has('X-CSRF-Token')) {
      cabeceras.set('X-CSRF-Token', sesion.csrf_token);
    }
    configuracion.headers = cabeceras;
    const respuesta = await fetch(ruta, configuracion);
    let cuerpo = {};
    try { cuerpo = await respuesta.json(); } catch (error) { /* cuerpo vacío */ }
    if (!respuesta.ok) {
      const fallo = new ErrorAPI(
        cuerpo.error || ('La petición ha fallado (HTTP ' + respuesta.status + ')'),
        cuerpo.code, respuesta.status, cuerpo.detail,
      );
      if (respuesta.status === 401 && sesion
          && !String(ruta).includes('/api/auth/session')) {
        cerrarLocalmente('La sesión ha caducado. Vuelve a identificarte.');
      }
      throw fallo;
    }
    return cuerpo;
  }

  function pintarIdentidad() {
    if (!sesion) return;
    const nombre = sesion.display_name || sesion.username;
    $('#nombre-cuenta').textContent = nombre;
    $('#rol-cuenta').textContent = ETIQUETAS_ROL[sesion.role] || sesion.role;
    $('#avatar-cuenta').textContent = nombre.slice(0, 1).toUpperCase();
    document.body.dataset.role = sesion.role;
    document.body.dataset.canOperate = ['operator', 'admin'].includes(sesion.role) ? 'true' : 'false';
    $('#pestana-usuarios').classList.toggle('oculto', sesion.role !== 'admin');
    $('#pestana-api').classList.toggle('oculto', sesion.role !== 'admin');
    $('#pestana-configuracion').classList.toggle('oculto', sesion.role !== 'admin');
    actualizarNavegacionCuenta();
  }

  function mostrarAcceso(mensaje = '') {
    $('#vista-panel').classList.add('oculto');
    $('#vista-acceso').classList.remove('oculto');
    const caja = $('#estado-acceso');
    caja.textContent = mensaje;
    caja.className = 'recado mal' + (mensaje ? '' : ' oculto');
    setTimeout(() => $('#form-acceso [name="username"]').focus(), 0);
  }

  function mostrarPanel() {
    $('#vista-acceso').classList.add('oculto');
    $('#vista-panel').classList.remove('oculto');
    pintarIdentidad();
    void cambiarVista(sesion.password_change_required ? 'seguridad' : 'estado');
  }

  function arrancarPanelSiProcede() {
    if (!panelIniciado && !sesion.password_change_required && alPrepararPanel) {
      panelIniciado = true;
      alPrepararPanel();
    }
  }

  function cerrarLocalmente(mensaje = '') {
    sesion = null;
    panelIniciado = false;
    document.body.removeAttribute('data-role');
    document.body.removeAttribute('data-can-operate');
    if (window.keepalivedPanel) window.keepalivedPanel.detener();
    pestanaActual = 'estado';
    ocultarSecretos();
    mostrarAcceso(mensaje);
  }

  async function cerrarSesion() {
    try {
      await request('/api/auth/session', { method: 'DELETE' });
    } catch (error) {
      // La salida local también debe funcionar si el nodo acaba de cambiar.
    }
    cerrarLocalmente();
  }

  function actualizarEstadoAcceso() {
    const inicial = Boolean(estado && estado.registration_required);
    $('#campo-nombre-inicial').classList.toggle('oculto', !inicial);
    $('#campo-confirmacion-inicial').classList.toggle('oculto', !inicial);
    $('#form-acceso [name="password"]').autocomplete = inicial
      ? 'new-password' : 'current-password';
    $('#titulo-acceso').textContent = inicial
      ? 'Registrar la primera cuenta' : 'Entrar en Keepalived';
    $('#texto-acceso').textContent = inicial
      ? 'Aún no hay usuarios. Registra la primera cuenta administradora; el alta se cerrará al crearla.'
      : 'Identifícate para administrar el reparto y el mantenimiento de los nodos.';
    $('#boton-acceso').textContent = inicial ? 'Registrar administrador' : 'Entrar';
    if (!estado || !estado.configured) {
      $('#estado-configuracion').textContent = 'Acceso sin configurar';
    } else if (inicial) {
      $('#estado-configuracion').textContent = 'Registro inicial disponible';
    } else {
      $('#estado-configuracion').textContent = 'Acceso protegido';
    }
  }

  async function autenticar(evento) {
    evento.preventDefault();
    const formulario = evento.currentTarget;
    const username = valor(formulario, 'username');
    const password = String(new FormData(formulario).get('password') || '');
    const registroInicial = Boolean(estado && estado.registration_required);
    const confirmacion = String(
      new FormData(formulario).get('password_confirmation') || '',
    );
    if (!username || !password) {
      mostrarAcceso('Introduce el usuario y la contraseña.');
      return;
    }
    if (registroInicial && password !== confirmacion) {
      mostrarAcceso('Las contraseñas no coinciden.');
      return;
    }
    const cuerpo = {
      username,
      password,
      password_confirmation: confirmacion,
      display_name: valor(formulario, 'display_name') || username,
      otp: valor(formulario, 'otp'),
    };
    const enviar = $('#boton-acceso');
    enviar.disabled = true;
    enviar.setAttribute('aria-busy', 'true');
    enviar.textContent = registroInicial ? 'Registrando…' : 'Comprobando…';
    $('#estado-acceso').classList.add('oculto');
    try {
      sesion = await request('/api/auth/session', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(cuerpo),
      });
      formulario.reset();
      $('#campo-otp-acceso').classList.add('oculto');
      if (registroInicial) estado.registration_required = false;
      mostrarPanel();
      arrancarPanelSiProcede();
      if (registroInicial) aviso('Cuenta administradora registrada.', true);
    } catch (error) {
      if (error.code === 'TWO_FACTOR_REQUIRED' || error.code === 'INVALID_SECOND_FACTOR') {
        $('#campo-otp-acceso').classList.remove('oculto');
        $('#campo-otp-acceso input').focus();
      }
      mostrarAcceso(error.message);
    } finally {
      enviar.disabled = false;
      enviar.removeAttribute('aria-busy');
      actualizarEstadoAcceso();
    }
  }

  function cabeceraBloque(titulo, texto) {
    const bloque = nodo('div', 'cabecera-bloque');
    bloque.append(nodo('h3', null, titulo));
    if (texto) bloque.append(nodo('p', null, texto));
    return bloque;
  }

  function filaDato(etiqueta, contenido) {
    const fila = nodo('div', 'fila-dato');
    fila.append(nodo('span', null, etiqueta));
    fila.append(nodo('strong', null, contenido));
    return fila;
  }

  function confirmacionAdmin(formulario) {
    const bloque = nodo('fieldset', 'confirmacion-admin');
    bloque.append(nodo('legend', null, 'Confirmación del administrador'));
    bloque.append(campo('Tu contraseña actual', 'current_password', 'password', {
      autocomplete: 'current-password', maxlength: 256,
    }));
    if (sesion.two_factor_enabled) {
      bloque.append(campo('Tu código 2FA', 'otp', 'text', {
        autocomplete: 'one-time-code', maxlength: 24,
      }));
    }
    formulario.append(bloque);
  }

  async function pintarPerfil(contenedor) {
    const resumen = nodo('section', 'bloque-cuenta');
    resumen.append(cabeceraBloque('Identidad', 'Datos asociados a la sesión actual.'));
    const datos = nodo('div', 'lista-datos');
    datos.append(filaDato('Usuario', sesion.username));
    datos.append(filaDato('Permiso', ETIQUETAS_ROL[sesion.role] || sesion.role));
    datos.append(filaDato('Segundo factor', sesion.two_factor_enabled ? 'Activo' : 'No configurado'));
    resumen.append(datos);
    contenedor.append(resumen);

    const perfil = nodo('form', 'bloque-cuenta formulario-cuenta');
    perfil.noValidate = true;
    perfil.append(cabeceraBloque('Nombre visible', 'El usuario de acceso no cambia.'));
    perfil.append(campo('Nombre visible', 'display_name', 'text', {
      valor: sesion.display_name, maxlength: 120,
    }));
    const guardarPerfil = boton('Guardar nombre', 'boton-principal', 'submit');
    guardarPerfil.disabled = sesion.password_change_required;
    perfil.append(guardarPerfil);
    perfil.addEventListener('submit', async (evento) => {
      evento.preventDefault();
      const nombre = valor(perfil, 'display_name');
      if (!nombre) return recadoFormulario(perfil, 'Indica un nombre visible.');
      guardarPerfil.disabled = true;
      try {
        const respuesta = await request('/api/profile', {
          method: 'PATCH', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ display_name: nombre }),
        });
        sesion = { ...sesion, ...respuesta.profile };
        pintarIdentidad();
        recadoFormulario(perfil, 'Nombre actualizado.', true);
      } catch (error) { recadoFormulario(perfil, error.message); }
      finally { guardarPerfil.disabled = false; }
    });
    contenedor.append(perfil);
  }

  function pintarCambioClave(contenedor) {
    if (sesion.password_change_required) {
      const obligatorio = nodo('div', 'recado mal',
        'La contraseña actual es temporal. Debes sustituirla antes de utilizar el panel.');
      contenedor.append(obligatorio);
    }
    const clave = nodo('form', 'bloque-cuenta formulario-cuenta');
    clave.noValidate = true;
    clave.append(cabeceraBloque('Cambiar contraseña',
      'Usa al menos 12 caracteres. El cambio invalida las demás sesiones.'));
    clave.append(campo('Contraseña actual', 'current_password', 'password', {
      autocomplete: 'current-password', maxlength: 256,
    }));
    clave.append(campo('Contraseña nueva', 'new_password', 'password', {
      autocomplete: 'new-password', maxlength: 256,
    }));
    clave.append(campo('Repite la contraseña nueva', 'repeat_password', 'password', {
      autocomplete: 'new-password', maxlength: 256,
    }));
    if (sesion.two_factor_enabled) {
      clave.append(campo('Código 2FA o de recuperación', 'otp', 'text', {
        autocomplete: 'one-time-code', maxlength: 24,
      }));
    }
    const cambiar = boton('Cambiar contraseña', 'boton-principal', 'submit');
    clave.append(cambiar);
    clave.addEventListener('submit', async (evento) => {
      evento.preventDefault();
      const nueva = String(new FormData(clave).get('new_password') || '');
      if (nueva.length < 12) return recadoFormulario(clave, 'La contraseña debe tener al menos 12 caracteres.');
      if (nueva !== String(new FormData(clave).get('repeat_password') || '')) {
        return recadoFormulario(clave, 'Las dos contraseñas nuevas no coinciden.');
      }
      cambiar.disabled = true;
      try {
        sesion = await request('/api/profile/password', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            current_password: String(new FormData(clave).get('current_password') || ''),
            new_password: nueva, otp: valor(clave, 'otp'),
          }),
        });
        pintarIdentidad();
        arrancarPanelSiProcede();
        aviso('Contraseña actualizada.', true);
        await cambiarVista('seguridad');
      } catch (error) { recadoFormulario(clave, error.message); }
      finally { cambiar.disabled = false; }
    });
    contenedor.append(clave);
  }

  function mostrarSecreto(titulo, introduccion, valores) {
    tituloSecreto = titulo;
    vistaSecreto = pestanaActual;
    secretosVisibles = Array.isArray(valores) ? valores : [valores];
    $('#titulo-codigos').textContent = titulo;
    $('#texto-codigos').textContent = introduccion;
    const lista = $('#lista-codigos');
    lista.textContent = '';
    for (const secreto of secretosVisibles) lista.append(nodo('code', null, secreto));
    $('#recado-codigos').classList.add('oculto');
    const panel = $('#panel-secretos');
    panel.classList.remove('oculto');
    setTimeout(() => panel.scrollIntoView({ behavior: 'smooth', block: 'start' }), 0);
  }

  function ocultarSecretos() {
    secretosVisibles = [];
    tituloSecreto = '';
    vistaSecreto = null;
    const panel = $('#panel-secretos');
    if (panel) panel.classList.add('oculto');
    const lista = $('#lista-codigos');
    if (lista) lista.textContent = '';
    const recadoCodigos = $('#recado-codigos');
    if (recadoCodigos) recadoCodigos.className = 'recado bien oculto';
  }

  function formularioActivar2FA(contenedor) {
    const bloque = nodo('section', 'bloque-cuenta configuracion-2fa');
    bloque.append(cabeceraBloque('Vincular aplicación',
      'Escanea el QR con Aegis, 2FAS, Google Authenticator u otra aplicación TOTP.'));
    const qr = document.createElement('img');
    qr.src = preparacion2FA.qr_data_url;
    qr.alt = 'Código QR para configurar el segundo factor';
    bloque.append(qr);
    bloque.append(filaDato('Clave manual', preparacion2FA.secret));
    const form = nodo('form', 'formulario-cuenta');
    form.noValidate = true;
    form.append(campo('Código de seis cifras', 'code', 'text', {
      autocomplete: 'one-time-code', maxlength: 6,
    }));
    const activar = boton('Activar segundo factor', 'boton-principal', 'submit');
    form.append(activar);
    form.addEventListener('submit', async (evento) => {
      evento.preventDefault();
      activar.disabled = true;
      try {
        const respuesta = await request('/api/profile/2fa/enable', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ code: valor(form, 'code') }),
        });
        sesion = respuesta.session;
        preparacion2FA = null;
        pintarIdentidad();
        mostrarSecreto('Códigos de recuperación',
          'Guárdalos ahora. Cada código sustituye al 2FA una sola vez.',
          respuesta.recovery_codes);
        await cambiarVista('seguridad');
      } catch (error) { recadoFormulario(form, error.message); }
      finally { activar.disabled = false; }
    });
    bloque.append(form);
    contenedor.append(bloque);
  }

  async function pintarSeguridad(contenedor) {
    pintarCambioClave(contenedor);
    const estado2FA = nodo('section', 'bloque-cuenta');
    estado2FA.append(cabeceraBloque('Segundo factor', sesion.two_factor_enabled
      ? 'La cuenta exige contraseña y un código temporal para iniciar sesión.'
      : 'Añade una segunda comprobación además de la contraseña.'));
    const insignia = nodo('span', 'estado-seguridad ' + (sesion.two_factor_enabled ? 'activo' : 'inactivo'),
      sesion.two_factor_enabled ? '2FA ACTIVO' : '2FA NO CONFIGURADO');
    estado2FA.append(insignia);
    if (sesion.recovery_codes_remaining !== undefined && sesion.two_factor_enabled) {
      estado2FA.append(nodo('p', 'nota-cuenta',
        sesion.recovery_codes_remaining + ' códigos de recuperación disponibles.'));
    }
    contenedor.append(estado2FA);

    if (preparacion2FA) {
      formularioActivar2FA(contenedor);
      return;
    }

    if (!sesion.two_factor_enabled) {
      const form = nodo('form', 'bloque-cuenta formulario-cuenta');
      form.noValidate = true;
      form.append(cabeceraBloque('Configurar 2FA', 'Confirma primero tu contraseña actual.'));
      form.append(campo('Contraseña actual', 'current_password', 'password', {
        autocomplete: 'current-password', maxlength: 256,
      }));
      const preparar = boton('Generar código QR', 'boton-principal', 'submit');
      form.append(preparar);
      form.addEventListener('submit', async (evento) => {
        evento.preventDefault();
        preparar.disabled = true;
        try {
          preparacion2FA = await request('/api/profile/2fa/setup', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ current_password: String(
              new FormData(form).get('current_password') || '') }),
          });
          await cambiarVista('seguridad');
        } catch (error) { recadoFormulario(form, error.message); }
        finally { preparar.disabled = false; }
      });
      contenedor.append(form);
      return;
    }

    const codigos = nodo('form', 'bloque-cuenta formulario-cuenta');
    codigos.noValidate = true;
    codigos.append(cabeceraBloque('Nuevos códigos de recuperación',
      'Los anteriores dejarán de funcionar inmediatamente.'));
    codigos.append(campo('Contraseña actual', 'current_password', 'password', { maxlength: 256 }));
    codigos.append(campo('Código 2FA', 'code', 'text', { maxlength: 24 }));
    const regenerar = boton('Regenerar códigos', null, 'submit');
    codigos.append(regenerar);
    codigos.addEventListener('submit', async (evento) => {
      evento.preventDefault();
      regenerar.disabled = true;
      try {
        const respuesta = await request('/api/profile/2fa/recovery-codes', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            current_password: String(new FormData(codigos).get('current_password') || ''),
            code: valor(codigos, 'code'),
          }),
        });
        sesion = { ...sesion, ...respuesta.profile };
        mostrarSecreto('Códigos de recuperación',
          'Los códigos anteriores han quedado anulados. Guarda este nuevo juego.',
          respuesta.recovery_codes);
        await cambiarVista('seguridad');
      } catch (error) { recadoFormulario(codigos, error.message); }
      finally { regenerar.disabled = false; }
    });
    contenedor.append(codigos);

    const desactivar = nodo('form', 'bloque-cuenta formulario-cuenta zona-peligro');
    desactivar.noValidate = true;
    desactivar.append(cabeceraBloque('Desactivar 2FA',
      'La cuenta volverá a depender únicamente de su contraseña.'));
    desactivar.append(campo('Contraseña actual', 'current_password', 'password', { maxlength: 256 }));
    desactivar.append(campo('Código 2FA', 'code', 'text', { maxlength: 24 }));
    const quitar = boton('Desactivar segundo factor', 'peligro', 'submit');
    desactivar.append(quitar);
    desactivar.addEventListener('submit', async (evento) => {
      evento.preventDefault();
      quitar.disabled = true;
      try {
        const respuesta = await request('/api/profile/2fa/disable', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            current_password: String(new FormData(desactivar).get('current_password') || ''),
            code: valor(desactivar, 'code'),
          }),
        });
        sesion = respuesta.session;
        pintarIdentidad();
        aviso('Segundo factor desactivado.', true);
        await cambiarVista('seguridad');
      } catch (error) { recadoFormulario(desactivar, error.message); }
      finally { quitar.disabled = false; }
    });
    contenedor.append(desactivar);
  }

  function selectorRol(valor) {
    const select = document.createElement('select');
    select.name = 'role';
    for (const rol of ['reader', 'operator', 'admin']) {
      const opcion = document.createElement('option');
      opcion.value = rol;
      opcion.textContent = ETIQUETAS_ROL[rol];
      opcion.selected = rol === valor;
      select.append(opcion);
    }
    return select;
  }

  function selectorEstado(valor) {
    const select = document.createElement('select');
    select.name = 'status';
    for (const [estadoUsuario, etiqueta] of [['active', 'Activa'], ['disabled', 'Desactivada']]) {
      const opcion = document.createElement('option');
      opcion.value = estadoUsuario;
      opcion.textContent = etiqueta;
      opcion.selected = estadoUsuario === valor;
      select.append(opcion);
    }
    return select;
  }

  function campoConfiguracion(etiqueta, nombre, tipo, valorActual, opciones = {}) {
    const bloque = campo(etiqueta, nombre, tipo, {
      valor: String(valorActual ?? ''), maxlength: opciones.maxlength,
      placeholder: opciones.placeholder, ayuda: opciones.ayuda,
    });
    const control = bloque.querySelector('input');
    control.value = String(valorActual ?? '');
    control.required = opciones.required !== false;
    if (opciones.min !== undefined) control.min = String(opciones.min);
    if (opciones.max !== undefined) control.max = String(opciones.max);
    if (opciones.step !== undefined) control.step = String(opciones.step);
    return bloque;
  }

  async function pintarConfiguracion(contenedor) {
    if (sesion.role !== 'admin') {
      throw new ErrorAPI('Sólo un administrador puede cambiar la configuración.', 'FORBIDDEN', 403);
    }
    const respuesta = await request('/api/settings');
    const ajustes = respuesta.settings;
    const formulario = nodo('form', 'bloque-cuenta formulario-cuenta formulario-configuracion');
    formulario.noValidate = true;
    formulario.append(cabeceraBloque(
      'Topología del clúster',
      'Todos los valores son editables. Al guardar, este contenedor se reinicia con la nueva configuración.',
    ));

    const campoLocal = nodo('label', 'campo-formulario campo-nodo-local');
    campoLocal.append(nodo('span', null, 'Identidad de este contenedor'));
    const selectorLocal = document.createElement('select');
    selectorLocal.name = 'local_node_index';
    campoLocal.append(selectorLocal);
    campoLocal.append(nodo('em', 'ayuda',
      'Equivale al antiguo FIP_NODO y debe señalar una fila de la topología.'));
    formulario.append(campoLocal);

    const listaNodos = nodo('div', 'lista-nodos-configuracion');
    formulario.append(listaNodos);
    let contadorNodos = 0;

    function refrescarSelectorLocal(preferido) {
      const anterior = preferido || selectorLocal.value;
      selectorLocal.textContent = '';
      const tarjetas = [...listaNodos.querySelectorAll('.nodo-configuracion')];
      tarjetas.forEach((tarjeta, indice) => {
        const opcion = document.createElement('option');
        opcion.value = tarjeta.dataset.key;
        const nombre = tarjeta.querySelector('[data-campo="name"]').value.trim();
        opcion.textContent = nombre || ('Nodo ' + (indice + 1));
        selectorLocal.append(opcion);
      });
      selectorLocal.value = tarjetas.some((tarjeta) => tarjeta.dataset.key === anterior)
        ? anterior : (tarjetas[0] ? tarjetas[0].dataset.key : '');
      tarjetas.forEach((tarjeta) => tarjeta.classList.toggle(
        'nodo-local', tarjeta.dataset.key === selectorLocal.value,
      ));
    }

    function crearNodo(configuracionNodo = {}, esLocal = false) {
      const tarjeta = nodo('article', 'item-administracion nodo-configuracion');
      tarjeta.dataset.key = 'nodo-' + contadorNodos++;
      const cabecera = nodo('div', 'cabecera-item');
      const titulo = nodo('div');
      titulo.append(nodo('strong', null, 'Nodo del clúster'));
      titulo.append(nodo('small', null, 'Nombre, red, prioridad y panel'));
      cabecera.append(titulo);
      const quitar = boton('Quitar', 'peligro quitar-nodo');
      quitar.addEventListener('click', () => {
        if (listaNodos.children.length <= 2) {
          return recadoFormulario(formulario, 'La topología necesita al menos dos nodos.');
        }
        tarjeta.remove();
        refrescarSelectorLocal();
      });
      cabecera.append(quitar);
      tarjeta.append(cabecera);
      const rejilla = nodo('div', 'rejilla-nodo-configuracion');
      const definiciones = [
        ['Nombre', 'name', 'text', configuracionNodo.name, { maxlength: 64 }],
        ['IPv4 de gestión', 'ip', 'text', configuracionNodo.ip, { maxlength: 64, placeholder: '192.0.2.10' }],
        ['Interfaz', 'interface', 'text', configuracionNodo.interface, { maxlength: 64, placeholder: 'br0' }],
        ['Prioridad VRRP', 'priority', 'number', configuracionNodo.priority ?? 100, { min: 1, max: 254 }],
        ['URL del panel', 'url', 'url', configuracionNodo.url, { maxlength: 2048, placeholder: 'http://192.0.2.10:6060' }],
      ];
      for (const [etiqueta, nombre, tipo, valorCampo, opciones] of definiciones) {
        const bloque = campoConfiguracion(etiqueta, nombre, tipo, valorCampo, opciones);
        const control = bloque.querySelector('input');
        control.dataset.campo = nombre;
        if (nombre === 'name') control.addEventListener('input', () => refrescarSelectorLocal());
        rejilla.append(bloque);
      }
      tarjeta.append(rejilla);
      listaNodos.append(tarjeta);
      if (esLocal) selectorLocal.dataset.inicial = tarjeta.dataset.key;
      refrescarSelectorLocal(selectorLocal.dataset.inicial);
    }

    ajustes.nodes.forEach((configuracionNodo) => crearNodo(
      configuracionNodo, configuracionNodo.name === ajustes.local_node,
    ));
    selectorLocal.value = selectorLocal.dataset.inicial || selectorLocal.value;
    refrescarSelectorLocal(selectorLocal.value);
    selectorLocal.addEventListener('change', () => refrescarSelectorLocal(selectorLocal.value));
    const anadirNodo = boton('Añadir nodo', 'anadir-nodo-configuracion');
    anadirNodo.addEventListener('click', () => crearNodo({ priority: 100 }));
    formulario.append(anadirNodo);

    const comportamiento = nodo('section', 'seccion-configuracion');
    comportamiento.append(cabeceraBloque(
      'Comportamiento', 'Valores que antes se introducían como variables avanzadas de la plantilla.',
    ));
    const rejillaComportamiento = nodo('div', 'rejilla-formulario rejilla-comportamiento');
    rejillaComportamiento.append(campoConfiguracion(
      'Retardo de vuelta (segundos)', 'preempt_delay', 'number', ajustes.preempt_delay,
      { min: 0, max: 1000, ayuda: 'Espera antes de devolver una VIP al nodo preferente recuperado.' },
    ));
    rejillaComportamiento.append(campoConfiguracion(
      'Prefijo CIDR de las VIP', 'vip_prefix', 'number', ajustes.vip_prefix,
      { min: 1, max: 32, ayuda: 'El formato de pool de esta versión utiliza /24.' },
    ));
    rejillaComportamiento.append(campoConfiguracion(
      'Duración de sesión (horas)', 'session_hours', 'number', ajustes.session_hours,
      { min: 1, max: 168 },
    ));
    rejillaComportamiento.append(campoConfiguracion(
      'Emisor TOTP', 'totp_issuer', 'text', ajustes.totp_issuer,
      { maxlength: 120, ayuda: 'Nombre mostrado por la aplicación de autenticación.' },
    ));
    const cookie = nodo('label', 'opcion-configuracion');
    const cookieControl = document.createElement('input');
    cookieControl.type = 'checkbox';
    cookieControl.name = 'cookie_secure';
    cookieControl.checked = Boolean(ajustes.cookie_secure);
    cookie.append(cookieControl);
    const cookieTexto = nodo('span');
    cookieTexto.append(nodo('strong', null, 'Cookie sólo por HTTPS'));
    cookieTexto.append(nodo('small', null,
      'Actívala cuando el panel se publique exclusivamente mediante HTTPS.'));
    cookie.append(cookieTexto);
    rejillaComportamiento.append(cookie);
    comportamiento.append(rejillaComportamiento);
    formulario.append(comportamiento);

    const nota = nodo('div', 'recado bien nota-configuracion');
    nota.textContent = 'El puerto del panel y el volumen /datos permanecen en la plantilla de Unraid porque pertenecen a Docker. Los secretos se generan y almacenan dentro de /datos; nunca se muestran en el navegador.';
    formulario.append(nota);
    const guardar = boton('Guardar y reiniciar este contenedor', 'boton-principal', 'submit');
    formulario.append(guardar);

    formulario.addEventListener('submit', async (evento) => {
      evento.preventDefault();
      guardar.disabled = true;
      recadoFormulario(formulario, '');
      try {
        const tarjetas = [...listaNodos.querySelectorAll('.nodo-configuracion')];
        const nodos = tarjetas.map((tarjeta) => ({
          name: tarjeta.querySelector('[data-campo="name"]').value.trim(),
          ip: tarjeta.querySelector('[data-campo="ip"]').value.trim(),
          interface: tarjeta.querySelector('[data-campo="interface"]').value.trim(),
          priority: Number(tarjeta.querySelector('[data-campo="priority"]').value),
          url: tarjeta.querySelector('[data-campo="url"]').value.trim(),
        }));
        const indiceLocal = tarjetas.findIndex(
          (tarjeta) => tarjeta.dataset.key === selectorLocal.value,
        );
        const resultado = await request('/api/settings', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            local_node: indiceLocal >= 0 ? nodos[indiceLocal].name : '',
            nodes: nodos,
            preempt_delay: Number(valor(formulario, 'preempt_delay')),
            vip_prefix: Number(valor(formulario, 'vip_prefix')),
            session_hours: Number(valor(formulario, 'session_hours')),
            cookie_secure: cookieControl.checked,
            totp_issuer: valor(formulario, 'totp_issuer'),
          }),
        });
        if (!resultado.restarting) {
          recadoFormulario(formulario, 'No había cambios que guardar.', true);
          guardar.disabled = false;
          return;
        }
        formulario.querySelectorAll('input, select, button').forEach((control) => {
          control.disabled = true;
        });
        recadoFormulario(
          formulario,
          'Configuración guardada. El contenedor se está reiniciando; esta página se recargará automáticamente.',
          true,
        );
        setTimeout(() => window.location.reload(), 8000);
      } catch (error) {
        recadoFormulario(formulario, error.message);
        guardar.disabled = false;
      }
    });
    contenedor.append(formulario);
  }

  async function pintarUsuarios(contenedor) {
    if (sesion.role !== 'admin') throw new ErrorAPI('Sólo un administrador puede gestionar usuarios.', 'FORBIDDEN', 403);
    const respuesta = await request('/api/users');
    const alta = nodo('form', 'bloque-cuenta formulario-cuenta');
    alta.noValidate = true;
    alta.append(cabeceraBloque('Crear usuario', 'La contraseña entregada será temporal.'));
    const rejilla = nodo('div', 'rejilla-formulario');
    rejilla.append(campo('Usuario', 'username', 'text', { maxlength: 64 }));
    rejilla.append(campo('Nombre visible', 'display_name', 'text', { maxlength: 120 }));
    const rol = nodo('label', 'campo-formulario');
    rol.append(nodo('span', null, 'Permiso'));
    rol.append(selectorRol('reader'));
    rejilla.append(rol);
    rejilla.append(campo('Contraseña temporal', 'password', 'password', { maxlength: 256 }));
    alta.append(rejilla);
    confirmacionAdmin(alta);
    const crear = boton('Crear usuario', 'boton-principal', 'submit');
    alta.append(crear);
    alta.addEventListener('submit', async (evento) => {
      evento.preventDefault();
      const datos = new FormData(alta);
      crear.disabled = true;
      try {
        await request('/api/users', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: valor(alta, 'username'), display_name: valor(alta, 'display_name'),
            role: valor(alta, 'role'), password: String(datos.get('password') || ''),
            current_password: String(datos.get('current_password') || ''), otp: valor(alta, 'otp'),
          }),
        });
        aviso('Usuario creado. Debe cambiar su contraseña en el primer acceso.', true);
        await cambiarVista('usuarios');
      } catch (error) { recadoFormulario(alta, error.message); }
      finally { crear.disabled = false; }
    });
    contenedor.append(alta);

    const listado = nodo('section', 'bloque-cuenta');
    listado.append(cabeceraBloque('Usuarios', respuesta.users.length + ' cuentas registradas.'));
    const tarjetas = nodo('div', 'lista-administracion');
    for (const usuario of respuesta.users) {
      const tarjeta = nodo('article', 'item-administracion' + (usuario.status === 'disabled' ? ' desactivado' : ''));
      const cabecera = nodo('div', 'cabecera-item');
      const identidad = nodo('div');
      identidad.append(nodo('strong', null, usuario.display_name));
      identidad.append(nodo('small', null, '@' + usuario.username));
      cabecera.append(identidad);
      cabecera.append(nodo('span', 'estado-seguridad ' + (usuario.status === 'active' ? 'activo' : 'inactivo'),
        usuario.status === 'active' ? 'ACTIVA' : 'DESACTIVADA'));
      tarjeta.append(cabecera);
      const detalle = nodo('div', 'metadatos-item');
      detalle.append(nodo('span', null, ETIQUETAS_ROL[usuario.role]));
      detalle.append(nodo('span', null, usuario.two_factor_enabled ? '2FA activo' : 'Sin 2FA'));
      detalle.append(nodo('span', null, usuario.password_change_required ? 'Cambio de clave pendiente' : 'Clave establecida'));
      tarjeta.append(detalle);

      const editar = nodo('details', 'acciones-item');
      editar.append(nodo('summary', null, 'Editar acceso'));
      const formEditar = nodo('form', 'formulario-cuenta');
      const camposEdicion = nodo('div', 'rejilla-formulario');
      camposEdicion.append(campo('Nombre visible', 'display_name', 'text', { valor: usuario.display_name }));
      const rolUsuario = nodo('label', 'campo-formulario');
      rolUsuario.append(nodo('span', null, 'Permiso'));
      rolUsuario.append(selectorRol(usuario.role));
      camposEdicion.append(rolUsuario);
      const estadoUsuario = nodo('label', 'campo-formulario');
      estadoUsuario.append(nodo('span', null, 'Estado'));
      estadoUsuario.append(selectorEstado(usuario.status));
      camposEdicion.append(estadoUsuario);
      formEditar.append(camposEdicion);
      confirmacionAdmin(formEditar);
      const guardar = boton('Guardar acceso', null, 'submit');
      formEditar.append(guardar);
      formEditar.addEventListener('submit', async (evento) => {
        evento.preventDefault();
        const datos = new FormData(formEditar);
        guardar.disabled = true;
        try {
          await request('/api/users/' + usuario.id, {
            method: 'PATCH', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              display_name: valor(formEditar, 'display_name'), role: valor(formEditar, 'role'),
              status: valor(formEditar, 'status'),
              current_password: String(datos.get('current_password') || ''),
              otp: valor(formEditar, 'otp'),
            }),
          });
          if (usuario.id === sesion.id) return cerrarLocalmente('Tu acceso ha cambiado. Inicia una sesión nueva.');
          aviso('Acceso actualizado.', true);
          await cambiarVista('usuarios');
        } catch (error) { recadoFormulario(formEditar, error.message); }
        finally { guardar.disabled = false; }
      });
      editar.append(formEditar);
      tarjeta.append(editar);

      const reset = nodo('details', 'acciones-item zona-peligro');
      reset.append(nodo('summary', null, 'Restablecer contraseña y 2FA'));
      const formReset = nodo('form', 'formulario-cuenta');
      formReset.append(campo('Nueva contraseña temporal', 'new_password', 'password', { maxlength: 256 }));
      confirmacionAdmin(formReset);
      const ejecutarReset = boton('Restablecer acceso', 'peligro', 'submit');
      formReset.append(ejecutarReset);
      formReset.addEventListener('submit', async (evento) => {
        evento.preventDefault();
        const datos = new FormData(formReset);
        ejecutarReset.disabled = true;
        try {
          await request('/api/users/' + usuario.id + '/reset-password', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              new_password: String(datos.get('new_password') || ''),
              current_password: String(datos.get('current_password') || ''),
              otp: valor(formReset, 'otp'),
            }),
          });
          if (usuario.id === sesion.id) return cerrarLocalmente('Tu acceso ha sido restablecido. Usa la nueva contraseña temporal.');
          aviso('Contraseña y 2FA restablecidos.', true);
          await cambiarVista('usuarios');
        } catch (error) { recadoFormulario(formReset, error.message); }
        finally { ejecutarReset.disabled = false; }
      });
      reset.append(formReset);
      tarjeta.append(reset);
      tarjetas.append(tarjeta);
    }
    listado.append(tarjetas);
    contenedor.append(listado);
  }

  function controlesScopes(valores = ['status:read', 'claims:write']) {
    const bloque = nodo('fieldset', 'scopes-api');
    bloque.append(nodo('legend', null, 'Permisos de la clave'));
    for (const scope of Object.keys(ETIQUETAS_SCOPE)) {
      const etiqueta = nodo('label', 'opcion-scope');
      const control = document.createElement('input');
      control.type = 'checkbox';
      control.name = 'scope';
      control.value = scope;
      control.checked = valores.includes(scope);
      etiqueta.append(control);
      const texto = nodo('span');
      texto.append(nodo('strong', null, ETIQUETAS_SCOPE[scope]));
      texto.append(nodo('small', null, scope));
      etiqueta.append(texto);
      bloque.append(etiqueta);
    }
    return bloque;
  }

  async function pintarClavesAPI(contenedor) {
    if (sesion.role !== 'admin') throw new ErrorAPI('Sólo un administrador puede gestionar claves API.', 'FORBIDDEN', 403);
    const respuesta = await request('/api/api-keys');
    const alta = nodo('form', 'bloque-cuenta formulario-cuenta');
    alta.noValidate = true;
    alta.append(cabeceraBloque('Nueva clave de aplicación',
      'El secreto completo se muestra una sola vez. Crea una clave distinta para cada aplicación.'));
    const campoNombre = campo('Nombre de la aplicación', 'api_key_name', 'text', {
      autocomplete: 'off', maxlength: 120, placeholder: 'base-documental-produccion',
    });
    const controlNombre = campoNombre.querySelector('input');
    alta.append(campoNombre);
    alta.append(controlesScopes());
    confirmacionAdmin(alta);
    const crear = boton('Crear clave API', 'boton-principal', 'submit');
    alta.append(crear);
    alta.addEventListener('submit', async (evento) => {
      evento.preventDefault();
      const datos = new FormData(alta);
      const scopes = datos.getAll('scope').map(String);
      const nombreAplicacion = String(controlNombre.value || '').trim();
      if (!nombreAplicacion) return recadoFormulario(alta, 'Indica el nombre de la aplicación.');
      if (!scopes.length) return recadoFormulario(alta, 'Selecciona al menos un permiso.');
      crear.disabled = true;
      try {
        const creada = await request('/api/api-keys', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: nombreAplicacion, scopes,
            current_password: String(datos.get('current_password') || ''),
            otp: valor(alta, 'otp'),
          }),
        });
        mostrarSecreto('Clave API de ' + creada.api_key.name,
          'Cópiala ahora en la configuración segura de la aplicación. Keepalived no podrá volver a mostrarla.',
          creada.token);
        await cambiarVista('api');
      } catch (error) {
        const ayuda = error.code === 'API_KEY_CONFLICT'
          ? ' Revisa el nombre exacto indicado y la lista de claves registradas.' : '';
        recadoFormulario(alta, error.message + ayuda);
      }
      finally { crear.disabled = false; }
    });
    contenedor.append(alta);

    const listado = nodo('section', 'bloque-cuenta');
    listado.append(cabeceraBloque('Claves registradas',
      respuesta.api_keys.length + ' credenciales creadas, incluidas las revocadas.'));
    const tarjetas = nodo('div', 'lista-administracion');
    for (const clave of respuesta.api_keys) {
      const activa = clave.status === 'active';
      const tarjeta = nodo('article', 'item-administracion' + (activa ? '' : ' desactivado'));
      const cabecera = nodo('div', 'cabecera-item');
      const identidad = nodo('div');
      identidad.append(nodo('strong', null, clave.name));
      identidad.append(nodo('code', null, clave.prefix));
      cabecera.append(identidad);
      cabecera.append(nodo('span', 'estado-seguridad ' + (activa ? 'activo' : 'inactivo'),
        activa ? 'ACTIVA' : 'REVOCADA'));
      tarjeta.append(cabecera);
      const permisos = nodo('div', 'metadatos-item');
      for (const scope of clave.scopes) permisos.append(nodo('span', null, ETIQUETAS_SCOPE[scope] || scope));
      permisos.append(nodo('span', null, 'Creada por ' + clave.created_by));
      tarjeta.append(permisos);
      if (activa) {
        const detalles = nodo('details', 'acciones-item zona-peligro');
        detalles.append(nodo('summary', null, 'Revocar clave'));
        const form = nodo('form', 'formulario-cuenta');
        form.append(nodo('p', 'nota-cuenta',
          'La aplicación dejará de poder usar la API inmediatamente. Esta acción no revela ni recupera el secreto.'));
        confirmacionAdmin(form);
        const revocar = boton('Revocar definitivamente', 'peligro', 'submit');
        form.append(revocar);
        form.addEventListener('submit', async (evento) => {
          evento.preventDefault();
          const datos = new FormData(form);
          revocar.disabled = true;
          try {
            await request('/api/api-keys/' + clave.id, {
              method: 'DELETE', headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                current_password: String(datos.get('current_password') || ''),
                otp: valor(form, 'otp'),
              }),
            });
            aviso('Clave API revocada.', true);
            await cambiarVista('api');
          } catch (error) { recadoFormulario(form, error.message); }
          finally { revocar.disabled = false; }
        });
        detalles.append(form);
        tarjeta.append(detalles);
      }
      tarjetas.append(tarjeta);
    }
    if (!respuesta.api_keys.length) tarjetas.append(nodo('p', 'vacio', 'Todavía no hay claves API.'));
    listado.append(tarjetas);
    contenedor.append(listado);
  }

  function actualizarNavegacionCuenta() {
    if (!sesion) return;
    const obligatorio = Boolean(sesion.password_change_required);
    $('#cerrar-sesion').textContent = obligatorio ? 'Salir y completar más tarde' : 'Salir';
    document.querySelectorAll('.pestanas-app button').forEach((elemento) => {
      elemento.disabled = obligatorio && elemento.dataset.vista !== 'seguridad';
    });
  }

  async function cambiarVista(nombre) {
    if (!sesion) return;
    if (sesion.password_change_required && nombre !== 'seguridad') {
      nombre = 'seguridad';
    }
    if (['usuarios', 'api', 'configuracion'].includes(nombre)
        && sesion.role !== 'admin') nombre = 'perfil';
    if (nombre !== 'estado' && !VISTAS_CUENTA[nombre]) nombre = 'estado';
    pestanaActual = nombre;
    document.querySelectorAll('.pestanas-app button').forEach((elemento) => {
      elemento.classList.toggle('activa', elemento.dataset.vista === nombre);
    });
    $('#vista-operacion').classList.toggle('oculto', nombre !== 'estado');
    $('#vista-cuenta').classList.toggle('oculto', nombre === 'estado');
    $('#panel-secretos').classList.toggle(
      'oculto', !secretosVisibles.length || vistaSecreto !== nombre,
    );
    if (nombre === 'estado') return;

    const informacion = VISTAS_CUENTA[nombre];
    $('#sobrelinea-vista').textContent = informacion.sobrelinea;
    $('#titulo-vista').textContent = informacion.titulo;
    $('#descripcion-vista').textContent = informacion.descripcion;
    const contenido = $('#contenido-cuenta');
    contenido.textContent = '';
    contenido.append(nodo('p', 'vacio', 'Cargando…'));
    try {
      contenido.textContent = '';
      if (nombre === 'perfil') await pintarPerfil(contenido);
      else if (nombre === 'seguridad') await pintarSeguridad(contenido);
      else if (nombre === 'usuarios') await pintarUsuarios(contenido);
      else if (nombre === 'api') await pintarClavesAPI(contenido);
      else if (nombre === 'configuracion') await pintarConfiguracion(contenido);
    } catch (error) {
      contenido.textContent = '';
      contenido.append(nodo('div', 'recado mal', error.message));
    }
  }

  function abrirCuenta(pestana = 'perfil') {
    if (!sesion) return;
    void cambiarVista(pestana);
  }

  async function copiarSecretos() {
    const texto = secretosVisibles.join('\n');
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(texto);
      } else {
        const temporal = document.createElement('textarea');
        temporal.value = texto;
        temporal.style.position = 'fixed';
        temporal.style.opacity = '0';
        document.body.append(temporal);
        temporal.select();
        document.execCommand('copy');
        temporal.remove();
      }
      const caja = $('#recado-codigos');
      caja.textContent = 'Copiado al portapapeles.';
      caja.className = 'recado bien';
    } catch (error) {
      const caja = $('#recado-codigos');
      caja.textContent = 'No se ha podido copiar. Selecciona el texto manualmente.';
      caja.className = 'recado mal';
    }
  }

  function descargarSecretos() {
    const contenido = tituloSecreto + '\n' + '='.repeat(tituloSecreto.length) + '\n\n'
      + secretosVisibles.join('\n') + '\n';
    const enlace = document.createElement('a');
    enlace.href = URL.createObjectURL(new Blob([contenido], { type: 'text/plain;charset=utf-8' }));
    enlace.download = tituloSecreto.toLowerCase().replace(/[^a-z0-9]+/g, '-') + '.txt';
    enlace.click();
    URL.revokeObjectURL(enlace.href);
  }

  function instalarEventos() {
    $('#form-acceso').addEventListener('submit', autenticar);
    $('#boton-cuenta').addEventListener('click', () => abrirCuenta('perfil'));
    $('#cerrar-sesion').addEventListener('click', cerrarSesion);
    $('.pestanas-app').addEventListener('click', (evento) => {
      const control = evento.target.closest('[data-vista]');
      if (control && !control.disabled) void cambiarVista(control.dataset.vista);
    });
    $('#copiar-codigos').addEventListener('click', copiarSecretos);
    $('#descargar-codigos').addEventListener('click', descargarSecretos);
    $('#aceptar-codigos').addEventListener('click', ocultarSecretos);
  }

  async function start(prepararPanel) {
    alPrepararPanel = prepararPanel;
    instalarEventos();
    try {
      const [configuracion, salud] = await Promise.all([
        request('/api/auth/status'), request('/api/health'),
      ]);
      estado = configuracion;
      const version = salud.version && salud.version.version;
      $('#version-acceso').textContent = version ? 'v' + version : 'versión no disponible';
      actualizarEstadoAcceso();
      if (!estado.configured) {
        mostrarAcceso('El contenedor no tiene configurado FIP_SESSION_SECRET.');
        return;
      }
      try {
        sesion = await request('/api/auth/session');
        mostrarPanel();
        arrancarPanelSiProcede();
      } catch (error) {
        mostrarAcceso();
      }
    } catch (error) {
      mostrarAcceso('No se ha podido comprobar el acceso: ' + error.message);
    }
  }

  window.FIPAuth = {
    start,
    request,
    session: () => sesion,
    openAccount: abrirCuenta,
  };
}());
