"""Rutas HTTP de autenticación y administración de cuentas."""
from __future__ import annotations

import hmac
import os
import re
import threading
import time
from contextlib import contextmanager
from http.cookies import SimpleCookie
from urllib.parse import urlparse

import seguridad


_VENTANA_FALLOS_LOGIN = 300
_MAX_FALLOS_POR_ORIGEN = 8
_MAX_ORIGENES_FALLOS = 4096


class ControlAcceso:
    """Control HTTP del estado sensible con una barrera previa a escrituras.

    En clúster, ``preflight_mutacion`` debe exigir el escritor lógico fijo y
    reconciliar un quorum antes de cada cambio. Esto sacrifica disponibilidad
    del control-plane cuando ese escritor no está disponible, pero mantiene el
    failover de datos/VIP y evita crear ramas de credenciales concurrentes.
    """

    def __init__(self, almacen, proteccion, sesiones, reconciliar, replicar,
                 preflight_mutacion=None):
        self.almacen = almacen
        self.proteccion = proteccion
        self.sesiones = sesiones
        self.reconciliar = reconciliar
        self.replicar = replicar
        self.preflight_mutacion = preflight_mutacion or (lambda: None)
        self.cookie_segura = os.environ.get("FIP_COOKIE_SECURE", "0").lower() in (
            "1", "true", "yes", "on", "si", "sí",
        )
        self._fallos = {}
        self._candado_fallos = threading.Lock()
        self._candado_mutaciones = threading.RLock()
        self._fase_mutacion = threading.local()

    @property
    def configurado(self):
        return self.proteccion.disponible and self.sesiones.disponible

    def _cookie(self, manejador):
        cookies = SimpleCookie()
        try:
            cookies.load(manejador.headers.get("Cookie") or "")
        except Exception:  # noqa: BLE001
            return ""
        valor = cookies.get(seguridad.COOKIE)
        return valor.value if valor else ""

    @staticmethod
    def _cuerpo(manejador):
        """Lee y fija una sola vista del cuerpo para toda la ruta de acceso.

        ``Manejador._cuerpo`` aplica el framing, el límite y el plazo total de
        lectura HTTP. Esta segunda caché conserva además el objeto ya parseado:
        el preflight puede leerlo antes de tomar la barrera global y la fase
        autorizada posterior no vuelve al socket ni obtiene otra vista.
        """
        if not hasattr(manejador, "_auth_cuerpo_cache"):
            manejador._auth_cuerpo_cache = manejador._cuerpo()
        return manejador._auth_cuerpo_cache

    def _cabecera_cookie(self, token, borrar=False):
        cookie = SimpleCookie()
        cookie[seguridad.COOKIE] = token
        cookie[seguridad.COOKIE]["path"] = "/"
        cookie[seguridad.COOKIE]["httponly"] = True
        cookie[seguridad.COOKIE]["samesite"] = "Strict"
        if self.cookie_segura:
            cookie[seguridad.COOKIE]["secure"] = True
        if borrar:
            cookie[seguridad.COOKIE]["max-age"] = 0
        else:
            cookie[seguridad.COOKIE]["max-age"] = self.sesiones.duracion
        return cookie.output(header="").strip()

    def _identidad(self, manejador):
        identidad = self.sesiones.leer(self._cookie(manejador))
        if not identidad:
            raise seguridad.ErrorAcceso(
                "La sesión no es válida o ha caducado", "SESSION_REQUIRED", 401,
            )
        usuario = self.almacen.por_id(identidad.usuario_id)
        if (not usuario or usuario.get("status") != "active"
                or int(usuario.get("session_version") or 1) != identidad.version_sesion):
            raise seguridad.ErrorAcceso(
                "La cuenta asociada a la sesión ya no está disponible",
                "SESSION_INVALIDATED", 401,
            )
        return identidad, usuario

    @staticmethod
    def _mismo_origen(manejador):
        sitio = (manejador.headers.get("Sec-Fetch-Site") or "").lower()
        if sitio == "cross-site":
            return False
        origen = manejador.headers.get("Origin")
        if not origen:
            return True
        try:
            return urlparse(origen).netloc.casefold() == (
                manejador.headers.get("Host") or "").casefold()
        except ValueError:
            return False

    def _validar_mutacion(self, manejador, identidad):
        if not self._mismo_origen(manejador):
            raise seguridad.ErrorAcceso(
                "La petición procede de otro origen", "CROSS_SITE_REQUEST", 403,
            )
        csrf = manejador.headers.get("X-CSRF-Token") or ""
        if not csrf or not hmac.compare_digest(csrf, identidad.csrf):
            raise seguridad.ErrorAcceso("Falta un CSRF válido", "CSRF_REQUIRED", 403)

    def exigir(self, manejador, rol="reader", mutacion=False,
                permitir_cambio_pendiente=False):
        if (mutacion
                and not getattr(self._fase_mutacion, "activa", False)):
            # También protege las mutaciones del pool: un operador revocado en
            # el escritor no puede aprovechar una copia local obsoleta. No se
            # exige ser el escritor de seguridad porque aquí no se modifican
            # credenciales; sólo se exige reconciliación con quorum.
            with self._candado_mutaciones:
                self.reconciliar()
                return self._exigir_local(
                    manejador, rol, mutacion, permitir_cambio_pendiente)
        return self._exigir_local(
            manejador, rol, mutacion, permitir_cambio_pendiente)

    def _exigir_local(self, manejador, rol, mutacion,
                      permitir_cambio_pendiente):
        identidad, usuario = self._identidad(manejador)
        if mutacion:
            self._validar_mutacion(manejador, identidad)
        if not seguridad.rol_permite(usuario.get("role"), rol):
            raise seguridad.ErrorAcceso(
                "La cuenta no tiene permiso para esta operación", "FORBIDDEN", 403,
            )
        if usuario.get("password_change_required") and not permitir_cambio_pendiente:
            raise seguridad.ErrorAcceso(
                "Debes cambiar la contraseña temporal antes de operar",
                "PASSWORD_CHANGE_REQUIRED", 403,
            )
        return identidad, usuario

    @staticmethod
    def _token_api(manejador):
        autorizacion = manejador.headers.get("Authorization") or ""
        if autorizacion.startswith("Bearer "):
            return autorizacion[7:].strip()
        return (manejador.headers.get("X-API-Key") or "").strip()

    def exigir_clave_api(self, manejador, permiso, mutacion=False):
        if (mutacion
                and not getattr(self._fase_mutacion, "activa", False)):
            with self._candado_mutaciones:
                self.reconciliar()
                return self._exigir_clave_api_local(manejador, permiso)
        return self._exigir_clave_api_local(manejador, permiso)

    def _exigir_clave_api_local(self, manejador, permiso):
        token = self._token_api(manejador)
        coincidencia = re.fullmatch(r"fip_([0-9a-f]{32})_[A-Za-z0-9_-]{40,}", token)
        if not coincidencia:
            raise seguridad.ErrorAcceso(
                "Falta una clave API válida", "API_KEY_REQUIRED", 401,
            )
        clave = self.almacen.clave_api_por_id(coincidencia.group(1))
        if (not clave or clave.get("status", "active") != "active"
                or not self.proteccion.comprobar_clave_api(
                    token, clave.get("token_hash"))):
            raise seguridad.ErrorAcceso(
                "La clave API no es válida o ha sido revocada", "INVALID_API_KEY", 401,
            )
        if permiso not in (clave.get("scopes") or []):
            raise seguridad.ErrorAcceso(
                "La clave API no tiene permiso para esta operación",
                "API_SCOPE_REQUIRED", 403,
            )
        return {"id": clave["id"], "name": clave["name"], "scope": permiso}

    def exigir_api_o_usuario(self, manejador, permiso, rol="reader", mutacion=False):
        if self._token_api(manejador):
            return self.exigir_clave_api(
                manejador, permiso, mutacion=mutacion)
        return self.exigir(manejador, rol, mutacion=mutacion)

    @contextmanager
    def bloquear_estado_seguridad(self):
        """Barrera común para toda lectura/instalación causal de security.json.

        La capa de servidor debe tomarla antes de su propio candado de
        reconciliación y antes del flock del almacén. El orden global queda:
        ControlAcceso → reconciliación del servidor → AlmacenSeguridad. Es un
        RLock para que preflight y réplica llamados desde una fase HTTP ya
        autorizada puedan reentrar sin deadlock.
        """
        with self._candado_mutaciones:
            yield

    @contextmanager
    def autorizar_mutacion(self, manejador, rol="reader", permiso_api=None,
                           permitir_cambio_pendiente=False):
        """Mantiene autorización y escritura externa en una fase linealizable.

        El llamador debe ejecutar la mutación del pool *dentro* del ``with``.
        El orden de candados es siempre acceso → pool: primero se toma este
        RLock, luego el servidor puede tomar su candado de mutaciones del pool.
        Ningún worker debe adquirirlos en orden inverso.

        ``permiso_api`` habilita Bearer/X-API-Key para endpoints mixtos; si no
        se indica, la ruta sigue siendo exclusiva de sesión de usuario.
        """
        with self.bloquear_estado_seguridad():
            self.reconciliar()
            if permiso_api is not None and self._token_api(manejador):
                identidad = self._exigir_clave_api_local(
                    manejador, permiso_api)
            else:
                identidad = self._exigir_local(
                    manejador, rol, True, permitir_cambio_pendiente)
            yield identidad

    @staticmethod
    def _sesion_publica(identidad, usuario):
        return {
            **seguridad.AlmacenSeguridad.publico(usuario),
            "csrf_token": identidad.csrf,
            "expires_at": identidad.vence,
        }

    def _emitir(self, manejador, usuario, extra=None):
        token, identidad = self.sesiones.crear(usuario)
        datos = self._sesion_publica(identidad, usuario)
        if extra:
            datos.update(extra)
        return manejador._json(
            datos, cabeceras={"Set-Cookie": self._cabecera_cookie(token)},
        )

    def _replicar(self, snapshot):
        # Un fallo tras persistir localmente no es un resultado benigno. El
        # callback debe exponer AUTH_COMMIT_UNCERTAIN y la ruta lo devuelve al
        # cliente sin fingir éxito ni intentar sustituir otra rama.
        return self.replicar(snapshot)

    def _preflight(self):
        """Barrera estricta inmediatamente anterior a toda escritura sensible."""
        return self.preflight_mutacion()

    def _ejecutar_mutacion(self, operacion):
        """Serializa preflight, escritura y confirmación como una sola fase.

        El resultado de los métodos históricos del almacén es bien un snapshot
        o una pareja ``(valor, snapshot)``. Se conserva ese contrato y se añade
        por separado el resultado de réplica.
        """
        with self._candado_mutaciones:
            if not getattr(self._fase_mutacion, "activa", False):
                self._preflight()
            resultado = operacion()
            snapshot = (
                resultado[-1]
                if isinstance(resultado, tuple) and len(resultado) == 2
                else resultado
            )
            replica = self._replicar(snapshot)
            return resultado, replica

    def _reconciliar(self):
        try:
            return self.reconciliar()
        except Exception:  # noqa: BLE001
            return None

    def _limitado(self, origen):
        ahora = time.monotonic()
        with self._candado_fallos:
            self._depurar_fallos(ahora)
            if (origen not in self._fallos
                    and len(self._fallos) >= _MAX_ORIGENES_FALLOS):
                # Bajo una avalancha de orígenes únicos se falla cerrado en vez
                # de crecer sin límite o expulsar al atacante más antiguo para
                # regalarle otros ocho intentos.
                return True
            return len(self._fallos.get(origen, [])) >= _MAX_FALLOS_POR_ORIGEN

    def _fallar(self, origen):
        with self._candado_fallos:
            ahora = time.monotonic()
            self._depurar_fallos(ahora)
            if (origen not in self._fallos
                    and len(self._fallos) >= _MAX_ORIGENES_FALLOS):
                return
            marcas = self._fallos.setdefault(origen, [])
            if len(marcas) < _MAX_FALLOS_POR_ORIGEN:
                marcas.append(ahora)

    def _depurar_fallos(self, ahora):
        limite = ahora - _VENTANA_FALLOS_LOGIN
        for origen, marcas in list(self._fallos.items()):
            vigentes = [marca for marca in marcas if marca > limite]
            if vigentes:
                self._fallos[origen] = vigentes[-_MAX_FALLOS_POR_ORIGEN:]
            else:
                self._fallos.pop(origen, None)

    def _limpiar_fallos(self, origen):
        with self._candado_fallos:
            self._fallos.pop(origen, None)

    def _factor(self, usuario, codigo, consumir=False, actor=None):
        if not (usuario.get("totp") or {}).get("enabled"):
            return usuario, None
        if not codigo:
            raise seguridad.ErrorAcceso(
                "Introduce el código 2FA o uno de recuperación",
                "TWO_FACTOR_REQUIRED", 401,
            )
        comprobacion = self.proteccion.validar_factor(usuario, codigo)
        if not comprobacion:
            raise seguridad.ErrorAcceso(
                "El segundo factor no es válido", "INVALID_SECOND_FACTOR", 401,
            )
        metodo, indice = comprobacion
        if consumir and metodo == "recovery":
            resultado, _ = self._ejecutar_mutacion(lambda: self.almacen.consumir_codigo(
                usuario["id"], indice, actor or usuario["username"],
                self.proteccion.hash_recuperacion(codigo),
            ))
            usuario, _ = resultado
        return usuario, metodo

    def _confirmar_admin(self, manejador, cuerpo):
        identidad, usuario = self.exigir(manejador, "admin", mutacion=True)
        if not self.proteccion.comprobar_clave(
                str(cuerpo.get("current_password") or ""), usuario.get("password_hash") or ""):
            raise seguridad.ErrorAcceso(
                "La contraseña actual no es válida", "CURRENT_PASSWORD_INVALID", 403,
            )
        usuario, _ = self._factor(
            usuario, cuerpo.get("otp"), consumir=True, actor=identidad.usuario)
        return identidad, usuario

    def _login(self, manejador):
        if not self.configurado:
            raise seguridad.ErrorAcceso(
                "El acceso no está configurado", "AUTH_NOT_CONFIGURED", 503,
            )
        if not self._mismo_origen(manejador):
            raise seguridad.ErrorAcceso(
                "La petición procede de otro origen", "CROSS_SITE_REQUEST", 403,
            )
        origen = manejador.client_address[0] if manejador.client_address else "?"
        if self._limitado(origen):
            raise seguridad.ErrorAcceso(
                "Demasiados intentos; espera cinco minutos", "LOGIN_RATE_LIMIT", 429,
            )
        cuerpo = self._cuerpo(manejador)
        # Autenticar contra una copia obsoleta podría reactivar de hecho una
        # cuenta deshabilitada o una contraseña revocada. El login es de sólo
        # lectura y puede hacerse en cualquier nodo, pero exige reconciliación
        # con quorum antes de consultar el usuario.
        self.reconciliar()
        nombre = str(cuerpo.get("username") or "").strip()
        clave = str(cuerpo.get("password") or "")
        usuario = self.almacen.por_nombre(nombre)
        registro_inicial = False
        if not self.almacen.tiene_usuarios():
            nombre = seguridad.normalizar_usuario(nombre)
            self.proteccion.validar_clave(clave, nombre)
            confirmacion = str(cuerpo.get("password_confirmation") or "")
            if not confirmacion or not hmac.compare_digest(
                    clave.encode(), confirmacion.encode()):
                raise seguridad.ErrorAcceso(
                    "Las contraseñas no coinciden",
                    "PASSWORD_CONFIRMATION_MISMATCH", 422,
                )
            resultado, _ = self._ejecutar_mutacion(
                lambda: self.almacen.crear_propietario(
                    nombre,
                    seguridad.normalizar_nombre(cuerpo.get("display_name") or nombre),
                    self.proteccion.hash_clave(clave),
                ))
            usuario, _ = resultado
            registro_inicial = True
        if (not usuario or usuario.get("status") != "active"
                or not self.proteccion.comprobar_clave(clave, usuario.get("password_hash") or "")):
            self._fallar(origen)
            raise seguridad.ErrorAcceso("Usuario o contraseña no válidos")
        try:
            usuario, metodo_factor = self._factor(
                usuario, cuerpo.get("otp"), consumir=True, actor=usuario["username"])
        except seguridad.ErrorAcceso:
            self._fallar(origen)
            raise
        self._limpiar_fallos(origen)
        return self._emitir(manejador, usuario, {
            "login_method": "registration" if registro_inicial else (
                "password+" + metodo_factor if metodo_factor else "password"),
        })

    def _cambiar_clave(self, manejador):
        identidad, usuario = self.exigir(
            manejador, "reader", mutacion=True, permitir_cambio_pendiente=True)
        cuerpo = self._cuerpo(manejador)
        actual = str(cuerpo.get("current_password") or "")
        nueva = str(cuerpo.get("new_password") or "")
        if not self.proteccion.comprobar_clave(actual, usuario.get("password_hash") or ""):
            raise seguridad.ErrorAcceso(
                "La contraseña actual no es válida", "CURRENT_PASSWORD_INVALID", 403,
            )
        usuario, _ = self._factor(
            usuario, cuerpo.get("otp"), consumir=True, actor=identidad.usuario)
        self.proteccion.validar_clave(nueva, usuario["username"])
        if self.proteccion.comprobar_clave(nueva, usuario.get("password_hash") or ""):
            raise seguridad.ErrorAcceso(
                "La contraseña nueva debe ser distinta", "PASSWORD_UNCHANGED", 422,
            )
        resultado, replica = self._ejecutar_mutacion(
            lambda: self.almacen.cambiar_clave(
                usuario["id"], self.proteccion.hash_clave(nueva),
                identidad.usuario))
        usuario, _ = resultado
        return self._emitir(manejador, usuario, {"replication": replica})

    def _preparar_2fa(self, manejador):
        identidad, usuario = self.exigir(manejador, "reader", mutacion=True)
        cuerpo = self._cuerpo(manejador)
        if not self.proteccion.comprobar_clave(
                str(cuerpo.get("current_password") or ""), usuario.get("password_hash") or ""):
            raise seguridad.ErrorAcceso(
                "La contraseña actual no es válida", "CURRENT_PASSWORD_INVALID", 403,
            )
        secreto = self.proteccion.generar_secreto_totp()
        _, _ = self._ejecutar_mutacion(lambda: self.almacen.preparar_2fa(
            usuario["id"], self.proteccion.cifrar(secreto), identidad.usuario))
        uri = self.proteccion.uri_totp(usuario["username"], secreto)
        return manejador._json({
            "secret": secreto, "otpauth_uri": uri,
            "qr_data_url": self.proteccion.qr_totp(uri), "issuer": self.proteccion.emisor,
        })

    def _activar_2fa(self, manejador):
        identidad, usuario = self.exigir(manejador, "reader", mutacion=True)
        cuerpo = self._cuerpo(manejador)
        pendiente = (usuario.get("totp") or {}).get("pending_secret")
        if not pendiente:
            raise seguridad.ErrorAcceso(
                "Inicia primero la configuración 2FA", "TWO_FACTOR_SETUP_MISSING", 409,
            )
        secreto = self.proteccion.descifrar(pendiente)
        if not self.proteccion.comprobar_totp(secreto, cuerpo.get("code")):
            raise seguridad.ErrorAcceso(
                "El código no coincide; comprueba la hora del dispositivo",
                "INVALID_SECOND_FACTOR", 401,
            )
        codigos = self.proteccion.generar_codigos()
        hashes = [self.proteccion.hash_recuperacion(codigo) for codigo in codigos]
        resultado, replica = self._ejecutar_mutacion(
            lambda: self.almacen.activar_2fa(
                usuario["id"], hashes, identidad.usuario))
        usuario, _ = resultado
        token, nueva_identidad = self.sesiones.crear(usuario)
        return manejador._json({
            "profile": seguridad.AlmacenSeguridad.publico(usuario),
            "session": self._sesion_publica(nueva_identidad, usuario),
            "recovery_codes": codigos, "replication": replica,
        }, cabeceras={"Set-Cookie": self._cabecera_cookie(token)})

    def _desactivar_2fa(self, manejador):
        identidad, usuario = self.exigir(manejador, "reader", mutacion=True)
        cuerpo = self._cuerpo(manejador)
        if not self.proteccion.comprobar_clave(
                str(cuerpo.get("current_password") or ""), usuario.get("password_hash") or ""):
            raise seguridad.ErrorAcceso(
                "La contraseña actual no es válida", "CURRENT_PASSWORD_INVALID", 403,
            )
        usuario, _ = self._factor(
            usuario, cuerpo.get("code"), consumir=True, actor=identidad.usuario)
        resultado, replica = self._ejecutar_mutacion(
            lambda: self.almacen.desactivar_2fa(
                usuario["id"], identidad.usuario))
        usuario, _ = resultado
        token, nueva_identidad = self.sesiones.crear(usuario)
        return manejador._json({
            "profile": seguridad.AlmacenSeguridad.publico(usuario),
            "session": self._sesion_publica(nueva_identidad, usuario),
            "replication": replica,
        }, cabeceras={"Set-Cookie": self._cabecera_cookie(token)})

    def _regenerar_codigos(self, manejador):
        identidad, usuario = self.exigir(manejador, "reader", mutacion=True)
        cuerpo = self._cuerpo(manejador)
        if not self.proteccion.comprobar_clave(
                str(cuerpo.get("current_password") or ""), usuario.get("password_hash") or ""):
            raise seguridad.ErrorAcceso(
                "La contraseña actual no es válida", "CURRENT_PASSWORD_INVALID", 403,
            )
        usuario, _ = self._factor(
            usuario, cuerpo.get("code"), consumir=True, actor=identidad.usuario)
        codigos = self.proteccion.generar_codigos()
        hashes = [self.proteccion.hash_recuperacion(codigo) for codigo in codigos]
        resultado, replica = self._ejecutar_mutacion(
            lambda: self.almacen.reemplazar_codigos(
                usuario["id"], hashes, identidad.usuario))
        usuario, _ = resultado
        return manejador._json({
            "profile": seguridad.AlmacenSeguridad.publico(usuario),
            "recovery_codes": codigos, "replication": replica,
        })

    def _crear_usuario(self, manejador):
        cuerpo = self._cuerpo(manejador)
        identidad, _ = self._confirmar_admin(manejador, cuerpo)
        usuario = seguridad.normalizar_usuario(cuerpo.get("username"))
        nombre = seguridad.normalizar_nombre(cuerpo.get("display_name") or usuario)
        rol = seguridad.validar_rol(cuerpo.get("role") or "reader")
        clave = str(cuerpo.get("password") or "")
        self.proteccion.validar_clave(clave, usuario)
        resultado, replica = self._ejecutar_mutacion(
            lambda: self.almacen.crear_usuario(
                usuario, nombre, self.proteccion.hash_clave(clave), rol,
                identidad.usuario))
        creado, _ = resultado
        return manejador._json({
            "user": creado, "replication": replica,
        }, 201)

    def _actualizar_usuario(self, manejador, usuario_id):
        cuerpo = self._cuerpo(manejador)
        identidad, _ = self._confirmar_admin(manejador, cuerpo)
        cambios = {clave: cuerpo[clave] for clave in (
            "username", "display_name", "role", "status") if clave in cuerpo}
        if not cambios:
            raise seguridad.ErrorAcceso("No se ha indicado ningún cambio", "USER_UNCHANGED", 422)
        resultado, replica = self._ejecutar_mutacion(
            lambda: self.almacen.actualizar_acceso(
                usuario_id, identidad.usuario, cambios))
        usuario, _ = resultado
        return manejador._json({
            "user": usuario, "replication": replica,
        })

    def _restablecer_usuario(self, manejador, usuario_id):
        cuerpo = self._cuerpo(manejador)
        identidad, _ = self._confirmar_admin(manejador, cuerpo)
        objetivo = self.almacen.por_id(usuario_id)
        if not objetivo:
            raise seguridad.ErrorAcceso("La cuenta no existe", "USER_NOT_FOUND", 404)
        clave = str(cuerpo.get("new_password") or "")
        self.proteccion.validar_clave(clave, objetivo["username"])
        resultado, replica = self._ejecutar_mutacion(
            lambda: self.almacen.restablecer_usuario(
                usuario_id, self.proteccion.hash_clave(clave),
                identidad.usuario))
        usuario, _ = resultado
        return manejador._json({
            "user": usuario, "two_factor_reset": True,
            "replication": replica,
        })

    def _crear_clave_api(self, manejador):
        cuerpo = self._cuerpo(manejador)
        identidad, _ = self._confirmar_admin(manejador, cuerpo)
        permisos = cuerpo.get("scopes") or ["status:read", "claims:write"]
        identificador, token, hash_token = self.proteccion.generar_clave_api()
        resultado, replica = self._ejecutar_mutacion(
            lambda: self.almacen.crear_clave_api(
                identificador, cuerpo.get("name"), token[:20] + "...",
                hash_token, permisos, identidad.usuario,
            ))
        clave, _ = resultado
        return manejador._json({
            "api_key": clave, "token": token,
            "replication": replica,
        }, 201)

    def _revocar_clave_api(self, manejador, identificador):
        cuerpo = self._cuerpo(manejador)
        identidad, _ = self._confirmar_admin(manejador, cuerpo)
        resultado, replica = self._ejecutar_mutacion(
            lambda: self.almacen.revocar_clave_api(
                identificador, identidad.usuario))
        clave, _ = resultado
        return manejador._json({
            "api_key": clave, "replication": replica,
        })

    @staticmethod
    def _ruta_seguridad_mutante(metodo, ruta):
        if metodo == "PATCH" and (
                ruta == "/api/profile" or ruta.startswith("/api/users/")):
            return True
        if metodo == "DELETE" and (
                ruta == "/api/profile/2fa/setup"
                or ruta.startswith("/api/api-keys/")):
            return True
        if metodo != "POST":
            return False
        if ruta in {
            "/api/profile/password",
            "/api/profile/2fa/setup",
            "/api/profile/2fa/enable",
            "/api/profile/2fa/disable",
            "/api/profile/2fa/recovery-codes",
            "/api/users",
            "/api/api-keys",
        }:
            return True
        return bool(re.fullmatch(
            r"/api/users/[0-9a-f-]{36}/reset-password", ruta))

    @classmethod
    def _ruta_auth_con_cuerpo(cls, metodo, ruta):
        """Indica qué rutas consumen JSON antes de entrar en la barrera.

        La cancelación de un setup 2FA es la única mutación de seguridad sin
        cuerpo. No se fuerza un ``Content-Length`` artificial en esa ruta.
        """
        if metodo == "POST" and ruta == "/api/auth/session":
            return True
        if not cls._ruta_seguridad_mutante(metodo, ruta):
            return False
        return not (
            metodo == "DELETE" and ruta == "/api/profile/2fa/setup"
        )

    def manejar(self, manejador, metodo, ruta):
        """Aplica preflight antes incluso de autorizar una ruta mutante.

        El RLock permanece tomado hasta que la réplica confirma quorum. Así una
        sesión, rol o contraseña revocados no pueden autorizar una escritura
        entre la reconciliación y la persistencia local.
        """
        # Una conexión lenta nunca retiene el candado de seguridad ni dispara
        # reconciliación. El manejador limita framing/tamaño/tiempo y `_cuerpo`
        # fija la vista parseada que usarán después autorización y mutación.
        if self._ruta_auth_con_cuerpo(metodo, ruta):
            self._cuerpo(manejador)
        if self._ruta_seguridad_mutante(metodo, ruta):
            with self._candado_mutaciones:
                self._preflight()
                anterior = getattr(self._fase_mutacion, "activa", False)
                self._fase_mutacion.activa = True
                try:
                    return self._manejar(manejador, metodo, ruta)
                finally:
                    self._fase_mutacion.activa = anterior
        if metodo == "POST" and ruta == "/api/auth/session":
            # Login y mutaciones locales comparten orden en el escritor. En un
            # no-writer este candado sólo protege la vista reconciliada durante
            # la comprobación; no impide iniciar sesión allí.
            with self._candado_mutaciones:
                return self._manejar(manejador, metodo, ruta)
        return self._manejar(manejador, metodo, ruta)

    def _manejar(self, manejador, metodo, ruta):
        if not (ruta.startswith("/api/auth/") or ruta == "/api/profile"
                or ruta.startswith("/api/profile/") or ruta == "/api/users"
                or ruta.startswith("/api/users/") or ruta == "/api/api-keys"
                or ruta.startswith("/api/api-keys/")):
            return False
        try:
            if metodo == "GET" and ruta == "/api/auth/status":
                self._reconciliar()
                return manejador._json({
                    "configured": self.configurado,
                    "registration_required": not self.almacen.tiene_usuarios(),
                    "session_cookie_secure": self.cookie_segura,
                    "roles": list(seguridad.ROLES),
                }) or True
            if metodo == "POST" and ruta == "/api/auth/session":
                self._login(manejador)
                return True
            if metodo == "GET" and ruta == "/api/auth/session":
                identidad, usuario = self.exigir(
                    manejador, "reader", permitir_cambio_pendiente=True)
                manejador._json(self._sesion_publica(identidad, usuario))
                return True
            if metodo == "DELETE" and ruta == "/api/auth/session":
                identidad, _ = self.exigir(
                    manejador, "reader", mutacion=True, permitir_cambio_pendiente=True)
                manejador._json({"logged_out": True, "actor": identidad.usuario},
                                cabeceras={"Set-Cookie": self._cabecera_cookie("", True)})
                return True
            if metodo == "GET" and ruta == "/api/profile":
                identidad, usuario = self.exigir(
                    manejador, "reader", permitir_cambio_pendiente=True)
                manejador._json(self._sesion_publica(identidad, usuario))
                return True
            if metodo == "PATCH" and ruta == "/api/profile":
                identidad, usuario = self.exigir(manejador, "reader", mutacion=True)
                cuerpo = self._cuerpo(manejador)
                resultado, replica = self._ejecutar_mutacion(
                    lambda: self.almacen.actualizar_perfil(
                        usuario["id"], cuerpo.get("display_name"),
                        identidad.usuario))
                perfil, _ = resultado
                manejador._json({"profile": perfil, "replication": replica})
                return True
            if metodo == "POST" and ruta == "/api/profile/password":
                self._cambiar_clave(manejador)
                return True
            if metodo == "POST" and ruta == "/api/profile/2fa/setup":
                self._preparar_2fa(manejador)
                return True
            if metodo == "DELETE" and ruta == "/api/profile/2fa/setup":
                identidad, usuario = self.exigir(manejador, "reader", mutacion=True)
                _, replica = self._ejecutar_mutacion(
                    lambda: self.almacen.cancelar_2fa(
                        usuario["id"], identidad.usuario))
                manejador._json({"cancelled": True, "replication": replica})
                return True
            if metodo == "POST" and ruta == "/api/profile/2fa/enable":
                self._activar_2fa(manejador)
                return True
            if metodo == "POST" and ruta == "/api/profile/2fa/disable":
                self._desactivar_2fa(manejador)
                return True
            if metodo == "POST" and ruta == "/api/profile/2fa/recovery-codes":
                self._regenerar_codigos(manejador)
                return True
            if metodo == "GET" and ruta == "/api/users":
                self.exigir(manejador, "admin")
                manejador._json({"users": self.almacen.listar()})
                return True
            if metodo == "POST" and ruta == "/api/users":
                self._crear_usuario(manejador)
                return True
            coincidencia = re.fullmatch(r"/api/users/([0-9a-f-]{36})", ruta)
            if metodo == "PATCH" and coincidencia:
                self._actualizar_usuario(manejador, coincidencia.group(1))
                return True
            coincidencia = re.fullmatch(
                r"/api/users/([0-9a-f-]{36})/reset-password", ruta)
            if metodo == "POST" and coincidencia:
                self._restablecer_usuario(manejador, coincidencia.group(1))
                return True
            if metodo == "GET" and ruta == "/api/api-keys":
                self.exigir(manejador, "admin")
                manejador._json({
                    "api_keys": self.almacen.listar_claves_api(),
                    "available_scopes": list(seguridad.PERMISOS_API),
                })
                return True
            if metodo == "POST" and ruta == "/api/api-keys":
                self._crear_clave_api(manejador)
                return True
            coincidencia = re.fullmatch(r"/api/api-keys/([0-9a-f]{32})", ruta)
            if metodo == "DELETE" and coincidencia:
                self._revocar_clave_api(manejador, coincidencia.group(1))
                return True
            manejador._error("No existe", 404, "NOT_FOUND")
            return True
        except seguridad.ErrorAcceso as error:
            manejador._error(str(error), error.http, error.codigo)
            return True
        except Exception as error:  # noqa: BLE001
            manejador._error(
                "No se pudo completar la operación de acceso", 500,
                "AUTH_INTERNAL_ERROR", detalle=type(error).__name__,
            )
            return True
