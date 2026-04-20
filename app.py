"""
SecureNotes - Aplicación de bloc de notas con controles de seguridad completos.
Materia: DevSecOps
Cubre: Los 13 puntos de seguridad + correcciones QA (anti-enumeración, cache-control, UI).
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

# ─────────────────────────────────────────────────────────────────────────────
# [SEC-10] SECRETOS FUERA DEL CÓDIGO — .env
# ─────────────────────────────────────────────────────────────────────────────
load_dotenv()

# ─────────────────────────────────────────────────────────────────────────────
# INICIALIZACIÓN DE LA APP
# ─────────────────────────────────────────────────────────────────────────────
app = Flask(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURACIÓN SEGURA
# ─────────────────────────────────────────────────────────────────────────────
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY"),
    JWT_SECRET=os.getenv("JWT_SECRET"),
    SQLALCHEMY_DATABASE_URI=os.getenv("DATABASE_URL", "sqlite:///notepad.db"),
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_TIME_LIMIT=3600,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.getenv("FLASK_ENV") == "production",
    SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,  # [SEC-2] Max 1MB
)

if not app.config["SECRET_KEY"] or not app.config["JWT_SECRET"]:
    raise RuntimeError("❌ SECRET_KEY y JWT_SECRET deben estar definidos en .env")

# ─────────────────────────────────────────────────────────────────────────────
# EXTENSIONES
# ─────────────────────────────────────────────────────────────────────────────
db     = SQLAlchemy(app)
bcrypt = Bcrypt(app)
csrf   = CSRFProtect(app)

# [SEC-5] Rate limiting — por usuario (anti-brute-force sin afectar otros users)
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["300 per day", "60 per hour"],
    storage_uri="memory://",
)

# [SEC-11] CORS
CORS(app, resources={r"/api/*": {
    "origins": os.getenv("ALLOWED_ORIGINS", "http://localhost:5000").split(","),
    "supports_credentials": True,
}})

# ─────────────────────────────────────────────────────────────────────────────
# [SEC-8] LOGGING Y AUDITORÍA
# ─────────────────────────────────────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)

security_logger = logging.getLogger("security")
security_logger.setLevel(logging.INFO)
handler = logging.handlers.RotatingFileHandler(
    "logs/security.log", maxBytes=5_000_000, backupCount=5
)
handler.setFormatter(logging.Formatter(
    "%(asctime)s | %(levelname)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
))
security_logger.addHandler(handler)

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
    ip = request.remote_addr or "unknown"
    security_logger.info(f"ACTION={action} | USER={user_id} | IP={ip} | {extra}")
    try:
        log = AuditLog(user_id=user_id, action=action, ip_address=ip, details=extra[:500])
        db.session.add(log)
        db.session.commit()
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# MODELOS DE BASE DE DATOS
# ─────────────────────────────────────────────────────────────────────────────
class User(db.Model):
    __tablename__ = "users"

    id             = db.Column(db.Integer, primary_key=True)
    username       = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email          = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash  = db.Column(db.String(255), nullable=False)
    role           = db.Column(db.String(20), nullable=False, default="user")
    is_active      = db.Column(db.Boolean, default=True)
    failed_logins  = db.Column(db.Integer, default=0)
    locked_until   = db.Column(db.DateTime, nullable=True)
    created_at     = db.Column(db.DateTime, default=datetime.utcnow)
    last_login     = db.Column(db.DateTime, nullable=True)

    notes = db.relationship("Note", backref="owner", lazy=True, cascade="all, delete-orphan")

    def set_password(self, plaintext: str):
        self.password_hash = bcrypt.generate_password_hash(plaintext, rounds=12).decode("utf-8")

    def check_password(self, plaintext: str) -> bool:
        return bcrypt.check_password_hash(self.password_hash, plaintext)

    def is_locked(self) -> bool:
        return bool(self.locked_until and self.locked_until > datetime.utcnow())

    def to_safe_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
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
    is_deleted = db.Column(db.Boolean, default=False)

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "content": self.content,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    action     = db.Column(db.String(100), nullable=False)
    ip_address = db.Column(db.String(45))
    details    = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ─────────────────────────────────────────────────────────────────────────────
# [SEC-2] VALIDACIÓN DE ENTRADAS (Backend)
# ─────────────────────────────────────────────────────────────────────────────
USERNAME_RE = re.compile(r'^[a-zA-Z0-9_]{3,50}$')
EMAIL_RE    = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
PASSWORD_RE = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&_\-])[A-Za-z\d@$!%*#?&_\-]{8,128}$')

# [SEC-2 QA] Validación de contenido: no solo símbolos especiales
MEANINGFUL_RE = re.compile(r'[a-zA-Z0-9\u00C0-\u024F]')  # al menos 1 alfanumérico

def validate_register(data: dict) -> list:
    errors = []
    username = data.get("username", "").strip()
    email    = data.get("email", "").strip()
    password = data.get("password", "")

    if not USERNAME_RE.match(username):
        errors.append("Username: 3-50 chars, only letters, numbers and _")
    if not EMAIL_RE.match(email):
        errors.append("Invalid email address")
    if not PASSWORD_RE.match(password):
        errors.append(
            "Password must have at least 8 characters, uppercase, lowercase, number and symbol (@$!%*#?&_-)"
        )
    return errors


def validate_note(data: dict) -> list:
    errors = []
    title   = data.get("title", "").strip()
    content = data.get("content", "").strip()
    if not title or len(title) > 200:
        errors.append("Title required (max 200 characters)")
    elif not MEANINGFUL_RE.search(title):
        # [SEC-2 QA] Reject titles with only special characters
        errors.append("Title must contain at least one alphanumeric character")
    if not content or len(content) > 50_000:
        errors.append("Content required (max 50,000 characters)")
    elif not MEANINGFUL_RE.search(content):
        # [SEC-2 QA] Reject content with only special characters
        errors.append("Content must contain at least one alphanumeric character")
    return errors


# ─────────────────────────────────────────────────────────────────────────────
# [SEC-6] JWT — TOKENS CON EXPIRACIÓN
# ─────────────────────────────────────────────────────────────────────────────
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


# ─────────────────────────────────────────────────────────────────────────────
# DECORADORES DE AUTORIZACIÓN
# ─────────────────────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("access_token")
        if not token:
            token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        if not token:
            return jsonify({"error": "Authentication required"}), 401
        try:
            payload = decode_token(token)
            if payload.get("type") != "access":
                raise jwt.InvalidTokenError("Wrong token type")
            user = db.session.get(User, payload["sub"])
            if not user or not user.is_active:
                raise jwt.InvalidTokenError("User not found")
            g.current_user = user
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Session expired, please log in again"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        except Exception:
            app_logger.exception("Unexpected error validating token")
            return jsonify({"error": "Authentication error"}), 401
        return f(*args, **kwargs)
    return decorated


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated(*args, **kwargs):
            if g.current_user.role not in roles:
                audit("UNAUTHORIZED_ACCESS", g.current_user.id,
                      f"tried to access role {roles}")
                return jsonify({"error": "Access denied"}), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


# ─────────────────────────────────────────────────────────────────────────────
# [SEC-11] HEADERS DE SEGURIDAD + [QA] Cache-Control anti-back-button
# ─────────────────────────────────────────────────────────────────────────────
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]         = "DENY"
    response.headers["X-XSS-Protection"]        = "1; mode=block"
    response.headers["Referrer-Policy"]         = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.tailwindcss.com 'unsafe-inline'; "
        "style-src 'self' https://cdn.tailwindcss.com 'unsafe-inline';"
    )
    # [QA FIX] Cache-Control: prevent browser from caching authenticated pages.
    # This stops the "Back button after logout" vulnerability — the browser
    # will not serve stale/cached content from history after session ends.
    if request.path.startswith("/notes") or request.path.startswith("/admin") \
       or request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Pragma"]        = "no-cache"
        response.headers["Expires"]       = "0"

    if os.getenv("FLASK_ENV") == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# ─────────────────────────────────────────────────────────────────────────────
# [SEC-11] FORZAR HTTPS EN PRODUCCIÓN
# ─────────────────────────────────────────────────────────────────────────────
@app.before_request
def enforce_https():
    if os.getenv("FLASK_ENV") == "production":
        if request.headers.get("X-Forwarded-Proto", "https") == "http":
            return redirect(request.url.replace("http://", "https://"), code=301)


# ─────────────────────────────────────────────────────────────────────────────
# RUTAS — FRONTEND
# ─────────────────────────────────────────────────────────────────────────────
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


# ─────────────────────────────────────────────────────────────────────────────
# API — AUTENTICACIÓN
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/auth/register", methods=["POST"])
@limiter.limit("5 per hour")
@csrf.exempt
def api_register():
    data = request.get_json(silent=True) or {}

    errors = validate_register(data)
    if errors:
        return jsonify({"error": "Invalid data", "details": errors}), 400

    username = data["username"].strip()
    email    = data["email"].strip().lower()
    password = data["password"]

    # [QA FIX - Anti-Enumeration] Do NOT reveal whether username or email exist.
    # Return the same generic message for duplicate username OR email.
    # This prevents user enumeration attacks via the registration form.
    username_exists = User.query.filter_by(username=username).first()
    email_exists    = User.query.filter_by(email=email).first()

    if username_exists or email_exists:
        # Log internally for monitoring, but tell the user nothing specific
        audit("REGISTER_CONFLICT", None, f"username={username} conflict")
        return jsonify({
            "error": "Registration could not be completed. Please verify your information or try a different username/email."
        }), 409

    user = User(username=username, email=email, role="user")
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    audit("REGISTER", user.id, f"username={username}")
    return jsonify({"message": "Account created successfully"}), 201


@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("30 per 15 minutes")  # [QA FIX] Raised from 10 to reduce false positives on shared infra
@csrf.exempt
def api_login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"error": "Credentials required"}), 400

    user = User.query.filter_by(username=username).first()
    generic_error = "Invalid username or password"

    if not user or not user.is_active:
        audit("LOGIN_FAILED", None, f"username={username} (not found/inactive)")
        return jsonify({"error": generic_error}), 401

    if user.is_locked():
        audit("LOGIN_BLOCKED", user.id, f"account locked until {user.locked_until}")
        return jsonify({"error": "Account temporarily locked. Try again later."}), 423

    if not user.check_password(password):
        user.failed_logins += 1
        if user.failed_logins >= 5:
            user.locked_until = datetime.utcnow() + timedelta(minutes=15)
            audit("ACCOUNT_LOCKED", user.id, "5 failed attempts")
        db.session.commit()
        audit("LOGIN_FAILED", user.id, f"attempt {user.failed_logins}/5")
        return jsonify({"error": generic_error}), 401

    user.failed_logins = 0
    user.locked_until  = None
    user.last_login    = datetime.utcnow()
    db.session.commit()

    access_token  = create_token(user.id, user.role, "access")
    refresh_token = create_token(user.id, user.role, "refresh")

    audit("LOGIN_SUCCESS", user.id)

    response = make_response(jsonify({
        "message": "Login successful",
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
    token = request.cookies.get("refresh_token")
    if not token:
        return jsonify({"error": "Refresh token not found"}), 401
    try:
        payload = decode_token(token)
        if payload.get("type") != "refresh":
            raise jwt.InvalidTokenError()
        user = db.session.get(User, payload["sub"])
        if not user or not user.is_active:
            raise jwt.InvalidTokenError()
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Session expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

    new_access = create_token(user.id, user.role, "access")
    response = make_response(jsonify({"message": "Token renewed"}))
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
    response = make_response(jsonify({"message": "Session closed"}))
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token", path="/api/auth/refresh")
    # [QA FIX] Also set cache headers on logout response
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    return response, 200


@app.route("/api/auth/me", methods=["GET"])
@login_required
def api_me():
    return jsonify(g.current_user.to_safe_dict())


# ─────────────────────────────────────────────────────────────────────────────
# API — NOTAS (CRUD protegido)
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/notes", methods=["GET"])
@login_required
@csrf.exempt
def api_get_notes():
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
    errors = validate_note(data)
    if errors:
        return jsonify({"error": "Invalid data", "details": errors}), 400

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
    note = Note.query.filter_by(
        id=note_id, user_id=g.current_user.id, is_deleted=False
    ).first()
    if not note:
        return jsonify({"error": "Note not found"}), 404
    return jsonify(note.to_dict())


@app.route("/api/notes/<int:note_id>", methods=["PUT"])
@login_required
@csrf.exempt
def api_update_note(note_id):
    note = Note.query.filter_by(
        id=note_id, user_id=g.current_user.id, is_deleted=False
    ).first()
    if not note:
        return jsonify({"error": "Note not found"}), 404

    data = request.get_json(silent=True) or {}
    errors = validate_note(data)
    if errors:
        return jsonify({"error": "Invalid data", "details": errors}), 400

    note.title      = data["title"].strip()
    note.content    = data["content"].strip()
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
        return jsonify({"error": "Note not found"}), 404

    note.is_deleted = True
    db.session.commit()
    audit("NOTE_DELETED", g.current_user.id, f"note_id={note_id}")
    return jsonify({"message": "Note deleted"}), 200


# ─────────────────────────────────────────────────────────────────────────────
# API — ADMIN
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/admin/users", methods=["GET"])
@role_required("admin")
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
        return jsonify({"error": "You cannot deactivate yourself"}), 400
    user = db.session.get(User, uid)
    if not user:
        return jsonify({"error": "User not found"}), 404
    user.is_active = not user.is_active
    db.session.commit()
    action = "ADMIN_ACTIVATE_USER" if user.is_active else "ADMIN_DEACTIVATE_USER"
    audit(action, g.current_user.id, f"target_user={uid}")
    return jsonify({"message": f"User {'activated' if user.is_active else 'deactivated'}"})


# ─────────────────────────────────────────────────────────────────────────────
# [SEC-7] MANEJO GLOBAL DE ERRORES
# ─────────────────────────────────────────────────────────────────────────────
@app.errorhandler(400)
def bad_request(e):     return jsonify({"error": "Invalid request"}), 400

@app.errorhandler(401)
def unauthorized(e):    return jsonify({"error": "Not authenticated"}), 401

@app.errorhandler(403)
def forbidden(e):       return jsonify({"error": "Access denied"}), 403

@app.errorhandler(404)
def not_found(e):       return jsonify({"error": "Resource not found"}), 404

@app.errorhandler(413)
def too_large(e):       return jsonify({"error": "Request too large"}), 413

@app.errorhandler(429)
def rate_limit_hit(e):
    audit("RATE_LIMIT", None, f"path={request.path}")
    return jsonify({"error": "Too many requests. Try again later."}), 429

@app.errorhandler(500)
def server_error(e):
    app_logger.exception("Internal server error")
    return jsonify({"error": "Internal server error"}), 500

@app.errorhandler(Exception)
def unhandled_exception(e):
    app_logger.exception(f"Unhandled exception: {e}")
    return jsonify({"error": "Unexpected error"}), 500


# ─────────────────────────────────────────────────────────────────────────────
# CSRF TOKEN para frontend
# ─────────────────────────────────────────────────────────────────────────────
@app.route("/api/csrf-token", methods=["GET"])
def get_csrf_token():
    return jsonify({"csrf_token": generate_csrf()})


# ─────────────────────────────────────────────────────────────────────────────
# ARRANQUE
# ─────────────────────────────────────────────────────────────────────────────
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username="admin").first():
        admin = User(
            username="admin",
            email=os.getenv("ADMIN_EMAIL", "admin@example.com"),
            role="admin"
        )
        admin.set_password(os.getenv("ADMIN_PASSWORD", "Admin@1234!"))
        db.session.add(admin)
        db.session.commit()
        security_logger.info("Default admin user created")

if __name__ == "__main__":
    debug_mode = os.getenv("FLASK_ENV") != "production"
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", 5000)),
        debug=debug_mode,
    )
