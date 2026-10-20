# Backend – Favoritos (Flask)

API protegida con JWT (Bearer). Valida firma (RS256 vía JWKS de Keycloak), emisor, audiencia y expiración.

| Método | Ruta | Descripción |
|---|---|---|
| GET | `/api/items` | Lista los elementos del usuario del token |
| POST | `/api/items` | Agrega `{ "name": "...", "category": "..." }` |
| GET | `/health` | Sin autenticación |

Sin `Authorization: Bearer <jwt>` válido responde **401**.

```bash
docker compose up --build   # http://localhost:5000
```
Requiere el stack de LDAP + Keycloak corriendo (puerto 8081). Los datos viven en memoria.
# backend-fail2ban
