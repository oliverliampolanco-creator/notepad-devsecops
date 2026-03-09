"""
SecureNotes - Aplicación de bloc de notas con controles de seguridad completos.
Materia: DevSecOps
Cubre: Los 13 puntos de seguridad del documento de requerimientos.
"""

import os
import re
import logging
import logging.handlers
from datetime import datetime, timedelta, timezone
from functools import wraps

from dotenv import load_dotenv
from flask import (
    Flask, request, jsonify, render_template,
    redirect, url_for, make_response, g
)
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect, generate_csrf
import jwt

# ─────────────────────────────────────────────
# [SEC-10] SECRETOS FUERA DEL CÓDIGO — .env
# ─────────────────────────────────────────────
load_dotenv()

# ─────────────────────────────────────────────
# INICIALIZACIÓN DE LA APP
# ─────────────────────────────────────────────
app = Flask(__name__)

# ─────────────────────────────────────────────
# CONFIGURACIÓN SEGURA
# ─────────────────────────────────────────────
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY"),                          # [SEC-10] Nunca hardcodeado
    JWT_SECRET=os.getenv("JWT_SECRET"),                          # [SEC-10]
    SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL", "sqlite:///notepad.db"),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_TIME_LIMIT=3600,
    SESSION_COOKIE_HTTPONLY=True,                                # [SEC-6] HttpOnly
    SESSION_COOKIE_SECURE=os.getenv("FLASK_ENV") == "production",  # [SEC-11] Solo HTTPS en prod
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,                          # [SEC-2] Max 1MB por request
)

# Validar que los secretos están definidos al iniciar
if not app.config["SECRET_KEY"] or not app.config["JWT_SECRET"]:
    raise RuntimeError("❌ SECRET_KEY y JWT_SECRET deben estar definidos en .env")

# ─────────────────────────────────────────────
# EXTENSIONES
# ─────────────────────────────────────────────
db     = SQLAlchemy(app)
bcrypt = Bcrypt(app)
csrf   = CSRFProtect(app)

# [SEC-5] Rate limiting — protección contra fuerza bruta
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["300 per day", "60 per hour"],
    storage_uri="memory://",
)

# [SEC-11] CORS — solo orígenes permitidos
CORS(app, resources={r"/api/*": {
    "origins": os.getenv("ALLOWED_ORIGINS", "http://localhost:5000").split(","),
    "supports_credentials": True,
}})

# ─────────────────────────────────────────────
# [SEC-8] LOGGING Y AUDITORÍA
# ─────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)

# Logger de seguridad — eventos importantes
security_logger = logging.getLogger("security")
security_logger.setLevel(logging.INFO)
handler = logging.handlers.RotatingFileHandler(
    "logs/security.log", maxBytes=5_000_000, backupCount=5
)
handler.setFormatter(logging.Formatter(
    "%(asctime)s | %(levelname)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
))
security_logger.addHandler(handler)

# Logger general de app
logging.basicConfig(
    level=logging.WARNING,
    handlers=[
        logging.handlers.RotatingFileHandler("logs/app.log", maxBytes=5_000_000, backupCount=3),
        logging.StreamHandler()
    ],
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)
app_logger = logging.getLogger("app")


def audit(action: str, user_id=None, extra: str = ""):
    """Registra un evento de auditoría en DB y en archivo."""
    ip = request.remote_addr or "unknown"
    security_logger.info(f"ACTION={action} | USER={user_id} | IP={ip} | {extra}")
    try:
        log = AuditLog(
            user_id=user_id,
            action=action,
            ip_address=ip,
            details=extra[:500],
        )
        db.session.add(log)
        db.session.commit()
    except Exception:
        pass  # No interrumpir el flujo por fallo de log


# ─────────────────────────────────────────────
# MODELOS DE BASE DE DATOS
# ─────────────────────────────────────────────
class User(db.Model):
    __tablename__ = "users"

    id             = db.Column(db.Integer, primary_key=True)
    username       = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email          = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash  = db.Column(db.String(255), nullable=False)           # [SEC-4] Hash bcrypt
    role           = db.Column(db.String(20), nullable=False, default="user")  # [SEC-5] Roles
    is_active      = db.Column(db.Boolean, default=True)
    failed_logins  = db.Column(db.Integer, default=0)
    locked_until   = db.Column(db.DateTime, nullable=True)               # Bloqueo por intentos
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
    last_login     = db.Column(db.DateTime, nullable=True)

    notes = db.relationship("Note", backref="owner", lazy=True, cascade="all, delete-orphan")

    def set_password(self, plaintext: str):
        """[SEC-4] Hash seguro con bcrypt (work factor 12)."""
        self.password_hash = bcrypt.generate_password_hash(plaintext, rounds=12).decode("utf-8")

    def check_password(self, plaintext: str) -> bool:
        return bcrypt.check_password_hash(self.password_hash, plaintext)

    def is_locked(self) -> bool:
        if self.locked_until and self.locked_until > datetime.utcnow():
            return True
        return False

    def to_safe_dict(self):
        """Nunca expone password_hash."""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "created_at": self.created_at.isoformat(),
        }


class Note(db.Model):
    __tablename__ = "notes"

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    title      = db.Column(db.String(200), nullable=False)
    content    = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_deleted = db.Column(db.Boolean, default=False)  # Soft delete

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "content": self.content,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


class AuditLog(db.Model):
    """[SEC-8] Registro de auditoría en base de datos."""
    __tablename__ = "audit_logs"

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    action     = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(45))
    details    = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ─────────────────────────────────────────────
# [SEC-2] VALIDACIÓN DE ENTRADAS (Backend)
# ─────────────────────────────────────────────
USERNAME_RE = re.compile(r'^[a-zA-Z0-9_]{3,50}$')
EMAIL_RE    = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
# [SEC-4] Política de contraseñas: mínimo 8 chars, mayús, minús, número, especial
PASSWORD_RE = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&_\-])[A-Za-z\d@$!%*#?&_\-]{8,128}$')

def validate_register(data: dict) -> list[str]:
    errors = []
    username = data.get("username", "").strip()
    email    = data.get("email", "").strip()
    password = data.get("password", "")

    if not USERNAME_RE.match(username):
        errors.append("Usuario: 3-50 chars, solo letras, números y _")
    if not EMAIL_RE.match(email):
        errors.append("Email inválido")
    if not PASSWORD_RE.match(password):
        errors.append(
            "Contraseña debe tener mínimo 8 caracteres, mayúscula, minúscula, número y símbolo (@$!%*#?&_-)"
        )
    return errors


def validate_note(data: dict) -> list[str]:
    errors = []
    title   = data.get("title", "").strip()
    content = data.get("content", "").strip()
    if not title or len(title) > 200:
        errors.append("Título requerido (máx 200 caracteres)")
    if not content or len(content) > 50_000:
        errors.append("Contenido requerido (máx 50,000 caracteres)")
    return errors


# ─────────────────────────────────────────────
# [SEC-6] JWT — TOKENS CON EXPIRACIÓN
# ─────────────────────────────────────────────
ACCESS_EXPIRE  = timedelta(minutes=30)
REFRESH_EXPIRE = timedelta(days=7)

def create_token(user_id: int, role: str, token_type: str = "access") -> str:
    exp = datetime.now(timezone.utc) + (
        ACCESS_EXPIRE if token_type == "access" else REFRESH_EXPIRE
    )
    payload = {
        "sub": user_id,
        "role": role,
        "type": token_type,
        "exp": exp,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, app.config["JWT_SECRET"], algorithm="HS256")


def decode_token(token: str) -> dict:
    return jwt.decode(token, app.config["JWT_SECRET"], algorithms=["HS256"])


# ─────────────────────────────────────────────
# DECORADORES DE AUTORIZACIÓN
# ─────────────────────────────────────────────
def login_required(f):
    """[SEC-5] Verifica token JWT en cookie HttpOnly."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("access_token")
        if not token:
            token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        if not token:
            return jsonify({"error": "Autenticación requerida"}), 401
        try:
            payload = decode_token(token)
            if payload.get("type") != "access":
                raise jwt.InvalidTokenError("Tipo de token incorrecto")
            user = db.session.get(User, payload["sub"])
            if not user or not user.is_active:
                raise jwt.InvalidTokenError("Usuario no encontrado")
            g.current_user = user
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Sesión expirada, inicia sesión nuevamente"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token inválido"}), 401
        except Exception:
            app_logger.exception("Error inesperado al validar token")         # [SEC-7] log interno
            return jsonify({"error": "Error de autenticación"}), 401          # [SEC-7] mensaje genérico
        return f(*args, **kwargs)
    return decorated


def role_required(*roles):
    """[SEC-5] Control de acceso por rol."""
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated(*args, **kwargs):
            if g.current_user.role not in roles:
                audit("UNAUTHORIZED_ACCESS", g.current_user.id,
                      f"intentó acceder a ruta de rol {roles}")
                return jsonify({"error": "Acceso denegado"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


# ─────────────────────────────────────────────
# [SEC-11] HEADERS DE SEGURIDAD
# ─────────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-Frame-Options"]           = "DENY"
    response.headers["X-XSS-Protection"]          = "1; mode=block"
    response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"]   = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.tailwindcss.com 'unsafe-inline'; "
        "style-src 'self' https://cdn.tailwindcss.com 'unsafe-inline';"
    )
    if os.getenv("FLASK_ENV") == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# ─────────────────────────────────────────────
# [SEC-11] FORZAR HTTPS EN PRODUCCIÓN
# ─────────────────────────────────────────────
@app.before_request
def enforce_https():
    if os.getenv("FLASK_ENV") == "production":
        if request.headers.get("X-Forwarded-Proto", "https") == "http":
            return redirect(request.url.replace("http://", "https://"), code=301)


# ─────────────────────────────────────────────
# RUTAS — FRONTEND (renderiza templates)
# ─────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/register")
def register_page():
    return render_template("register.html")

@app.route("/notes")
def notes_page():
    return render_template("notes.html")

@app.route("/admin")
def admin_page():
    return render_template("admin.html")


# ─────────────────────────────────────────────
# API — AUTENTICACIÓN
# ─────────────────────────────────────────────
@app.route("/api/auth/register", methods=["POST"])
@limiter.limit("5 per hour")                     # [SEC-5] Límite de registro
@csrf.exempt                                      # API usa JWT, no sesión de cookie
def api_register():
    data = request.get_json(silent=True) or {}

    # [SEC-2] Validación de entradas backend
    errors = validate_register(data)
    if errors:
        return jsonify({"error": "Datos inválidos", "details": errors}), 400

    username = data["username"].strip()
    email    = data["email"].strip().lower()
    password = data["password"]

    # [SEC-3] ORM → queries parametrizadas (sin SQL injection)
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "El nombre de usuario ya existe"}), 409
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "El email ya está registrado"}), 409

    user = User(username=username, email=email, role="user")
    user.set_password(password)                    # [SEC-4] bcrypt hash

    db.session.add(user)
    db.session.commit()

    audit("REGISTER", user.id, f"username={username}")
    return jsonify({"message": "Cuenta creada exitosamente"}), 201


@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("10 per 15 minutes")              # [SEC-5] Protección fuerza bruta
@csrf.exempt
def api_login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Credenciales requeridas"}), 400

    # [SEC-3] Query parametrizado vía ORM
    user = User.query.filter_by(username=username).first()

    # [SEC-7] Mensaje genérico — no revelar si usuario existe o no
    generic_error = "Usuario o contraseña incorrectos"

    if not user or not user.is_active:
        audit("LOGIN_FAILED", None, f"username={username} (no existe/inactivo)")
        return jsonify({"error": generic_error}), 401

    # Cuenta bloqueada por intentos fallidos
    if user.is_locked():
        audit("LOGIN_BLOCKED", user.id, f"cuenta bloqueada hasta {user.locked_until}")
        return jsonify({"error": "Cuenta bloqueada temporalmente. Intenta más tarde."}), 423

    if not user.check_password(password):
        user.failed_logins += 1
        # Bloquear tras 5 intentos fallidos por 15 minutos
        if user.failed_logins >= 5:
            user.locked_until = datetime.utcnow() + timedelta(minutes=15)
            audit("ACCOUNT_LOCKED", user.id, "5 intentos fallidos")
        db.session.commit()
        audit("LOGIN_FAILED", user.id, f"intento {user.failed_logins}/5")
        return jsonify({"error": generic_error}), 401

    # Login exitoso — resetear contadores
    user.failed_logins = 0
    user.locked_until  = None
    user.last_login    = datetime.utcnow()
    db.session.commit()

    # [SEC-6] Generar tokens JWT con expiración
    access_token  = create_token(user.id, user.role, "access")
    refresh_token = create_token(user.id, user.role, "refresh")

    audit("LOGIN_SUCCESS", user.id)

    # [SEC-6] Tokens en cookies HttpOnly + Secure
    response = make_response(jsonify({
        "message": "Inicio de sesión exitoso",
        "user": user.to_safe_dict(),
    }))
    is_prod = os.getenv("FLASK_ENV") == "production"
    response.set_cookie("access_token",  access_token,  httponly=True, secure=is_prod,
                        samesite="Lax", max_age=int(ACCESS_EXPIRE.total_seconds()))
    response.set_cookie("refresh_token", refresh_token, httponly=True, secure=is_prod,
                        samesite="Lax", max_age=int(REFRESH_EXPIRE.total_seconds()),
                        path="/api/auth/refresh")
    return response, 200


@app.route("/api/auth/refresh", methods=["POST"])
@csrf.exempt
def api_refresh():
    """[SEC-6] Renovar access token con refresh token."""
    token = request.cookies.get("refresh_token")
    if not token:
        return jsonify({"error": "Refresh token no encontrado"}), 401
    try:
        payload = decode_token(token)
        if payload.get("type") != "refresh":
            raise jwt.InvalidTokenError()
        user = db.session.get(User, payload["sub"])
        if not user or not user.is_active:
            raise jwt.InvalidTokenError()
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Sesión expirada"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Token inválido"}), 401

    new_access = create_token(user.id, user.role, "access")
    response = make_response(jsonify({"message": "Token renovado"}))
    is_prod = os.getenv("FLASK_ENV") == "production"
    response.set_cookie("access_token", new_access, httponly=True, secure=is_prod,
                        samesite="Lax", max_age=int(ACCESS_EXPIRE.total_seconds()))
    return response, 200


@app.route("/api/auth/logout", methods=["POST"])
@csrf.exempt
def api_logout():
    user_id = None
    try:
        token = request.cookies.get("access_token")
        if token:
            payload = decode_token(token)
            user_id = payload.get("sub")
    except Exception:
        pass

    audit("LOGOUT", user_id)
    response = make_response(jsonify({"message": "Sesión cerrada"}))
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token", path="/api/auth/refresh")
    return response, 200


@app.route("/api/auth/me", methods=["GET"])
@login_required
def api_me():
    return jsonify(g.current_user.to_safe_dict())


# ─────────────────────────────────────────────
# API — NOTAS (CRUD protegido)
# ─────────────────────────────────────────────
@app.route("/api/notes", methods=["GET"])
@login_required
@csrf.exempt
def api_get_notes():
    """[SEC-5] Cada usuario solo ve sus propias notas."""
    notes = Note.query.filter_by(
        user_id=g.current_user.id,
        is_deleted=False
    ).order_by(Note.updated_at.desc()).all()
    return jsonify([n.to_dict() for n in notes])


@app.route("/api/notes", methods=["POST"])
@login_required
@csrf.exempt
def api_create_note():
    data = request.get_json(silent=True) or {}

    # [SEC-2] Validación backend
    errors = validate_note(data)
    if errors:
        return jsonify({"error": "Datos inválidos", "details": errors}), 400

    note = Note(
        user_id=g.current_user.id,
        title=data["title"].strip(),
        content=data["content"].strip(),
    )
    db.session.add(note)
    db.session.commit()
    audit("NOTE_CREATED", g.current_user.id, f"note_id={note.id}")
    return jsonify(note.to_dict()), 201


@app.route("/api/notes/<int:note_id>", methods=["GET"])
@login_required
@csrf.exempt
def api_get_note(note_id):
    # [SEC-5] Verificar que la nota pertenece al usuario (IDOR prevention)
    note = Note.query.filter_by(
        id=note_id, user_id=g.current_user.id, is_deleted=False
    ).first()
    if not note:
        return jsonify({"error": "Nota no encontrada"}), 404
    return jsonify(note.to_dict())


@app.route("/api/notes/<int:note_id>", methods=["PUT"])
@login_required
@csrf.exempt
def api_update_note(note_id):
    note = Note.query.filter_by(
        id=note_id, user_id=g.current_user.id, is_deleted=False
    ).first()
    if not note:
        return jsonify({"error": "Nota no encontrada"}), 404

    data = request.get_json(silent=True) or {}
    errors = validate_note(data)
    if errors:
        return jsonify({"error": "Datos inválidos", "details": errors}), 400

    note.title   = data["title"].strip()
    note.content = data["content"].strip()
    note.updated_at = datetime.utcnow()
    db.session.commit()
    audit("NOTE_UPDATED", g.current_user.id, f"note_id={note_id}")
    return jsonify(note.to_dict())


@app.route("/api/notes/<int:note_id>", methods=["DELETE"])
@login_required
@csrf.exempt
def api_delete_note(note_id):
    note = Note.query.filter_by(
        id=note_id, user_id=g.current_user.id, is_deleted=False
    ).first()
    if not note:
        return jsonify({"error": "Nota no encontrada"}), 404

    note.is_deleted = True  # Soft delete
    db.session.commit()
    audit("NOTE_DELETED", g.current_user.id, f"note_id={note_id}")
    return jsonify({"message": "Nota eliminada"}), 200


# ─────────────────────────────────────────────
# API — ADMIN (solo rol admin)
# ─────────────────────────────────────────────
@app.route("/api/admin/users", methods=["GET"])
@role_required("admin")                          # [SEC-5] Solo admins
@csrf.exempt
def api_admin_users():
    users = User.query.all()
    audit("ADMIN_LIST_USERS", g.current_user.id)
    return jsonify([u.to_safe_dict() for u in users])


@app.route("/api/admin/audit-logs", methods=["GET"])
@role_required("admin")
@csrf.exempt
def api_admin_audit_logs():
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(200).all()
    audit("ADMIN_VIEW_LOGS", g.current_user.id)
    return jsonify([{
        "id":         l.id,
        "user_id":    l.user_id,
        "action":     l.action,
        "ip_address": l.ip_address,
        "details":    l.details,
        "created_at": l.created_at.isoformat(),
    } for l in logs])


@app.route("/api/admin/users/<int:uid>/toggle", methods=["POST"])
@role_required("admin")
@csrf.exempt
def api_admin_toggle_user(uid):
    if uid == g.current_user.id:
        return jsonify({"error": "No puedes desactivarte a ti mismo"}), 400
    user = db.session.get(User, uid)
    if not user:
        return jsonify({"error": "Usuario no encontrado"}), 404
    user.is_active = not user.is_active
    db.session.commit()
    action = "ADMIN_ACTIVATE_USER" if user.is_active else "ADMIN_DEACTIVATE_USER"
    audit(action, g.current_user.id, f"target_user={uid}")
    return jsonify({"message": f"Usuario {'activado' if user.is_active else 'desactivado'}"})


# ─────────────────────────────────────────────
# [SEC-7] MANEJO GLOBAL DE ERRORES
# ─────────────────────────────────────────────
@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Solicitud inválida"}), 400

@app.errorhandler(401)
def unauthorized(e):
    return jsonify({"error": "No autenticado"}), 401

@app.errorhandler(403)
def forbidden(e):
    return jsonify({"error": "Acceso denegado"}), 403

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Recurso no encontrado"}), 404

@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "Solicitud demasiado grande"}), 413

@app.errorhandler(429)
def rate_limit_hit(e):
    audit("RATE_LIMIT", None, f"path={request.path}")
    return jsonify({"error": "Demasiadas solicitudes. Intenta más tarde."}), 429

@app.errorhandler(500)
def server_error(e):
    # [SEC-7] Loguear internamente pero NO exponer stack trace al usuario
    app_logger.exception("Error interno del servidor")
    return jsonify({"error": "Error interno del servidor"}), 500

@app.errorhandler(Exception)
def unhandled_exception(e):
    app_logger.exception(f"Excepción no manejada: {e}")
    return jsonify({"error": "Error inesperado"}), 500


# ─────────────────────────────────────────────
# CSRF TOKEN para frontend
# ─────────────────────────────────────────────
@app.route("/api/csrf-token", methods=["GET"])
def get_csrf_token():
    return jsonify({"csrf_token": generate_csrf()})


# ─────────────────────────────────────────────
# ARRANQUE
# ─────────────────────────────────────────────
with app.app_context():
    db.create_all()
    # Crear usuario admin por defecto si no existe
    if not User.query.filter_by(username="admin").first():
        admin = User(
            username="admin",
            email=os.getenv("ADMIN_EMAIL", "admin@example.com"),
            role="admin"
        )
        admin.set_password(os.getenv("ADMIN_PASSWORD", "Admin@1234!"))
        db.session.add(admin)
        db.session.commit()
        security_logger.info("Usuario admin creado por defecto")

if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_ENV") != "production"
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", 5000)),
        debug=debug_mode,     # [SEC-7] Debug OFF en producción
    )
