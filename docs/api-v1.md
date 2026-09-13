# API v1 para aplicaciones

La API conserva las rutas de reclamación de `1.0.0`, pero ahora exige una clave por
aplicación. Las credenciales se crean y revocan en **Cuenta → Claves API**.

## Autenticación

Enviar la clave mediante uno de estos encabezados:

```http
Authorization: Bearer fip_ID_SECRETO
```

```http
X-API-Key: fip_ID_SECRETO
```

Se recomienda `Authorization`. La clave completa se muestra una sola vez y Keepalived sólo
conserva un hash. No usarla en query strings, nombres de fichero, logs ni mensajes de error.

## Permisos

| Scope | Rutas |
|---|---|
| `status:read` | `GET /api/direcciones`, `GET /api/direcciones/{ip}` |
| `claims:write` | `POST /api/claims`, `DELETE /api/claims/{idempotency-key}` |

`GET /api/health` no requiere credencial. El resto de rutas no está disponible para claves
de aplicación aunque la clave tenga ambos scopes.

Las operaciones `POST /api/claims` y `DELETE /api/claims/{idempotency-key}` deben enviarse al
primer nodo de `FIP_NODOS`, que es el escritor lógico. No existe elección automática ni
redirección hacia otro escritor. Un usuario `reader` puede consultar `GET /api/status` para
ver `pool_writer`, `pool_writable` y `pool_ready`; una aplicación debe recibir el endpoint del
escritor como parte de su configuración de despliegue.

## Salud pública

```http
GET /api/health
```

```json
{
  "estado": "ok",
  "version": {"version": "1.0.7"}
}
```

La salud pública no revela topología ni estado de autenticación. Un usuario
con rol `reader` puede consultar esos detalles en `GET /api/status`.

Una respuesta `200` sólo confirma el proceso del panel y su versión. No revela nodo, pares,
escritor, preparación del pool ni estado de autenticación. La salud de cada servicio está en
la vista de direcciones autenticada.

## Consultar las direcciones

```bash
curl --fail-with-body \
  -H "Authorization: Bearer $KEEPALIVED_API_KEY" \
  http://keepalived.example:6060/api/direcciones
```

La respuesta indica el nodo que atiende, portadores reales, duplicados, salud local,
mantenimiento y colocación prevista. Para una sola IP:

```http
GET /api/direcciones/192.0.2.100
Authorization: Bearer fip_...
```

## Reclamar una dirección

```http
POST /api/claims
Authorization: Bearer fip_...
Idempotency-Key: provision:service-a:production
Content-Type: application/json
```

```json
{
  "servicio": "service-a",
  "descripcion": "Servicio de ejemplo",
  "puertos": [8080, 8443],
  "chequeo": {
    "puerto": 8080,
    "ruta": "/health"
  }
}
```

Reglas:

- `servicio`: 1-64 caracteres; letras, números, `_` o `-`.
- El clúster admite como máximo 64 VIP host-unicast `/24`; nunca se asignan direcciones de red,
  broadcast, loopback, multicast, link-local ni una IP de gestión de los nodos.
- `descripcion`: opcional, máximo 200 caracteres.
- `puertos`: lista única de enteros entre 1 y 65535.
- `chequeo`: obligatorio; el puerto se incorpora también a `puertos`.
- `Idempotency-Key`: 8-128 caracteres; debe identificar de forma estable la operación.

Respuesta de una operación nueva (`201`):

```json
{
  "reclamacion": {
    "ip": "192.0.2.100",
    "vrid": 7,
    "estado": "en_uso",
    "servicio": "service-a",
    "puertos": [8080, 8443],
    "chequeo": {"puerto": 8080, "ruta": "/health"},
    "preferente": null
  },
  "repetida": false,
  "local": {},
  "pares": {}
}
```

Repetir exactamente el mismo cuerpo con la misma clave devuelve la misma IP y `200` con
`repetida: true`. Reutilizar la clave con otro cuerpo devuelve `409` y no cambia el pool. El
éxito se devuelve después de que la revisión causal quede confirmada por una mayoría de
identidades lógicas.

La selección busca primero una dirección previamente reservada para `servicio`; si no existe,
toma la primera dirección libre. La aplicación no puede elegir el nodo preferido.

## Liberar una reclamación

```bash
curl --fail-with-body -X DELETE \
  -H "Authorization: Bearer $KEEPALIVED_API_KEY" \
  http://keepalived.example:6060/api/claims/provision:service-a:production
```

La liberación también es idempotente. Si la reclamación utilizó una dirección reservada para
el mismo servicio, vuelve a `reservada`; en los demás casos vuelve a `libre`.

## Errores

```json
{
  "error": "La clave API no tiene permiso para esta operación",
  "code": "API_SCOPE_REQUIRED"
}
```

| HTTP | Significado habitual | Acción del cliente |
|---:|---|---|
| 400 | cuerpo o `Idempotency-Key` inválido | corregir la petición |
| 401 | clave ausente, desconocida o revocada | detener reintentos y revisar secreto |
| 403 | scope insuficiente | solicitar otra clave o permiso |
| 404 | IP o reclamación inexistente | revisar identificador |
| 409 | conflicto causal, idempotencia o nodo no escritor | consultar estado; no crear otra operación a ciegas |
| 422 | dato válido como JSON pero no aceptable | corregir campos |
| 500/503 | falta de cuórum, commit incierto o fallo temporal | consultar primero; reintento limitado con backoff |

Durante una transacción de despliegue, una barrera `.deploy-freeze` válida hace que las
mutaciones externas respondan `503 DEPLOY_FROZEN`; una barrera con metadatos o contenido
incorrectos responde `503 DEPLOY_FREEZE_INVALID`. El coordinador N/N recupera esa barrera y su
journal en una nueva invocación, revirtiendo antes del commit o completándolo hacia delante si
la decisión ya era duradera. Los clientes no deben reintentar hasta que el operador confirme
el fin o la recuperación de la transacción.

Nunca hacer reintentos ilimitados. Para `POST`, conservar la misma `Idempotency-Key` durante
todos los reintentos de una misma provisión. Ante `POOL_COMMIT_UNCERTAIN`, leer la reclamación
o el pool antes de reintentar: el cambio puede haberse persistido aunque la respuesta no haya
podido confirmar el cuórum.

## Migración desde la API anónima

1. Crear una clave por aplicación con los scopes mínimos.
2. Guardarla en el mecanismo de secretos de esa aplicación.
3. Añadir el encabezado a todas las llamadas a `/api/direcciones` y `/api/claims`.
4. Verificar `200/201` y el mismo comportamiento idempotente.
5. No reutilizar una clave entre producción, pruebas y herramientas manuales.

No cambian los cuerpos ni las rutas de reclamación; cambia únicamente la autenticación.
