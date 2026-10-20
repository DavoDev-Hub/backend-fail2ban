import logging
import os
import time
from functools import wraps
from itertools import count
from logging.handlers import RotatingFileHandler

import jwt
from jwt import PyJWKClient
from flask import Flask, jsonify, request, g
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # permite que el frontend (otro puerto) mande el header Authorization

# --- Log de acceso para Fail2Ban -------------------------------------------
# Una línea por request, en un formato fijo y fácil de parsear con una regex:
#   <ip> - - [<fecha>] "<método> <ruta> HTTP/1.1" <status>
# Fail2Ban vigila este archivo (ver fail2ban/filter.d/http-flood.conf) y banea
# con iptables a cualquier IP que exceda el límite de requests configurado.
LOG_DIR = "/var/log/backend"
os.makedirs(LOG_DIR, exist_ok=True)

access_logger = logging.getLogger("access")
access_logger.setLevel(logging.INFO)
_handler = RotatingFileHandler(f"{LOG_DIR}/access.log", maxBytes=5_000_000, backupCount=2)
_handler.setFormatter(logging.Formatter("%(message)s"))
access_logger.addHandler(_handler)


@app.after_request
def log_access(response):
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    ts = time.strftime("%d/%b/%Y:%H:%M:%S %z")
    access_logger.info(
        '%s - - [%s] "%s %s HTTP/1.1" %s', ip, ts, request.method, request.path, response.status_code
    )
    return response

# --- Configuración de Keycloak (el que emite el JWT) ---------------------------
# ISSUER: debe coincidir EXACTO con el campo "iss" del token (KC_HOSTNAME de Keycloak).
# JWKS_URL: de dónde se baja la llave pública para verificar la firma. Desde el
# contenedor, "localhost" es el propio contenedor, por eso se usa host.docker.internal.
ISSUER = os.environ.get("KEYCLOAK_ISSUER", "http://localhost:8081/realms/cybersecurity")
JWKS_URL = os.environ.get(
    "KEYCLOAK_JWKS_URL",
    "http://host.docker.internal:8081/realms/cybersecurity/protocol/openid-connect/certs",
)
CLIENT_ID = os.environ.get("KEYCLOAK_CLIENT_ID", "fastapi-api")

jwks_client = PyJWKClient(JWKS_URL)

# --- "Base de datos" en memoria: { usuario: [items] } ------------------------
items_por_usuario = {}
_ids = count(1)


def require_bearer_jwt(f):
    """Exige 'Authorization: Bearer <jwt>' y valida firma, emisor, audiencia y expiración."""

    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")

        if not auth.startswith("Bearer ") or len(auth) <= len("Bearer "):
            return jsonify({"error": "Falta el Bearer token"}), 401

        token = auth[len("Bearer "):]
        try:
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                audience=CLIENT_ID,
                issuer=ISSUER,
            )
        except Exception as e:  # firma inválida, expirado, audiencia/emisor incorrectos, etc.
            return jsonify({"error": f"Token inválido: {e}"}), 401

        g.user = claims.get("preferred_username") or claims.get("sub")
        return f(*args, **kwargs)

    return wrapper


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.get("/api/items")
@require_bearer_jwt
def listar_items():
    return jsonify({"user": g.user, "items": items_por_usuario.get(g.user, [])})


@app.post("/api/items")
@require_bearer_jwt
def agregar_item():
    body = request.get_json(silent=True) or {}
    nombre = (body.get("name") or "").strip()
    categoria = (body.get("category") or "").strip()

    if not nombre:
        return jsonify({"error": "El campo 'name' es obligatorio"}), 400

    item = {"id": next(_ids), "name": nombre, "category": categoria or "Otros"}
    items_por_usuario.setdefault(g.user, []).append(item)
    return jsonify(item), 201


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
