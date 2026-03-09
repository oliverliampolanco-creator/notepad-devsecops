# 🔐 SecureNotes — Bloc de Notas con DevSecOps

Aplicación web de bloc de notas construida con Python + Flask que implementa los **13 puntos de seguridad** del documento de requerimientos de la materia DevSecOps.

---

## 🏗️ Stack Tecnológico

| Capa | Tecnología |
|---|---|
| Backend | Python 3.11 + Flask 3.0 |
| Base de datos | SQLite (dev) / PostgreSQL (prod) |
| ORM | SQLAlchemy 2.0 |
| Hashing | bcrypt (work factor 12) |
| Autenticación | JWT (PyJWT) en cookies HttpOnly |
| Rate limiting | Flask-Limiter |
| CSRF | Flask-WTF |
| Frontend | HTML + Tailwind CSS + Vanilla JS |
| Servidor prod | Gunicorn |

---

## ✅ Controles de Seguridad Implementados

### 1. Requisitos de seguridad definidos
- Datos manejados: credenciales (hashed), notas personales
- Roles: `admin` y `user`
- CIA: confidencialidad (autenticación), integridad (validaciones), disponibilidad (rate limiting)

### 2. Validación de entradas (backend)
```python
# app.py — funciones validate_register() y validate_note()
# - Tipo de dato, longitud mínima/máxima, formato regex
# - SIEMPRE en backend, nunca solo en frontend
USERNAME_RE = re.compile(r'^[a-zA-Z0-9_]{3,50}$')
PASSWORD_RE = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&_\-])...$')
```

### 3. Protección contra inyección SQL
```python
# SQLAlchemy ORM — queries 100% parametrizadas, cero SQL raw
user = User.query.filter_by(username=username).first()
note = Note.query.filter_by(id=note_id, user_id=g.current_user.id).first()
```

### 4. Contraseñas con hash seguro (bcrypt)
```python
# work_factor=12, salt automático por usuario
self.password_hash = bcrypt.generate_password_hash(plaintext, rounds=12).decode()
# La BD NUNCA almacena contraseñas en texto plano
```

### 5. Autenticación y autorización (RBAC)
- Roles: `admin` (panel completo) y `user` (solo sus notas)
- Decoradores `@login_required` y `@role_required("admin")`
- Bloqueo de cuenta tras **5 intentos fallidos** por 15 minutos
- **Prevención de IDOR**: cada nota se filtra siempre por `user_id`

### 6. Sesiones/tokens gestionados
```
Access token:  expiración 30 minutos  → cookie HttpOnly + Secure
Refresh token: expiración 7 días      → cookie HttpOnly, path=/api/auth/refresh
```
- `HttpOnly` = JavaScript NO puede leer la cookie (protección XSS)
- `Secure` = solo viaja por HTTPS en producción
- `SameSite=Lax` = protección CSRF adicional

### 7. Errores controlados
```python
# Al usuario: mensaje genérico
return jsonify({"error": "Usuario o contraseña incorrectos"}), 401
# En logs: detalle completo
app_logger.exception("Error interno del servidor")
# Stack traces NUNCA al cliente
app.run(debug=False)  # debug=False en producción
```

### 8. Logs y auditoría
- Archivo `logs/security.log` con rotación (5 MB × 5 backups)
- Archivo `logs/app.log` para errores de aplicación
- Tabla `audit_logs` en base de datos con IP, timestamp, acción, usuario
- Eventos registrados: LOGIN_SUCCESS, LOGIN_FAILED, REGISTER, NOTE_CREATED, NOTE_UPDATED, NOTE_DELETED, ACCOUNT_LOCKED, UNAUTHORIZED_ACCESS, RATE_LIMIT, ADMIN_*

### 9. Dependencias actualizadas y escaneadas
```bash
# Auditoría de vulnerabilidades conocidas
pip install pip-audit
pip-audit -r requirements.txt

pip install safety
safety check -r requirements.txt

# Análisis estático del código [SEC-12 SAST]
pip install bandit
bandit -r app.py
```

### 10. Secretos fuera del código
```bash
# .env (en .gitignore — NUNCA al repositorio)
SECRET_KEY=valor-aleatorio
JWT_SECRET=otro-valor-aleatorio
ADMIN_PASSWORD=contraseña-segura
DATABASE_URL=postgresql://...
```

### 11. HTTPS en todo
- En producción: `SESSION_COOKIE_SECURE=True`, `STRICT_TRANSPORT_SECURITY` header
- Redirección automática HTTP → HTTPS via middleware `enforce_https()`
- En Render.com: TLS/HTTPS gratuito y automático ✅

### 12. Pruebas de seguridad
```bash
# SAST — Análisis estático
bandit -r app.py -f html -o sast-report.html

# Dependencias vulnerables
pip-audit -r requirements.txt

# Pruebas manuales a verificar:
# ✓ Registrar usuario con contraseña débil → debe fallar
# ✓ Login con credenciales incorrectas 6 veces → cuenta bloqueada
# ✓ Acceder a /api/notes sin token → 401
# ✓ Cambiar note_id de otro usuario en URL → 404
# ✓ Inyección SQL en username: admin'-- → 400/rechazado por regex
# ✓ XSS en título de nota: <script>alert(1)</script> → escapeado en UI
# ✓ Más de 10 logins en 15 min → 429 rate limit
```

### 13. Ambiente de despliegue endurecido
- `debug=False` en producción (nunca exponer traceback)
- `MAX_CONTENT_LENGTH = 1MB` (protección DoS)
- Headers de seguridad: `X-Frame-Options: DENY`, `CSP`, `X-Content-Type-Options`
- Gunicorn como servidor WSGI (no el servidor de desarrollo de Flask)

---

## 🚀 Instalación Local

```bash
# 1. Clonar y crear entorno virtual
git clone <tu-repo>
cd notepad
python -m venv venv
source venv/bin/activate     # Windows: venv\Scripts\activate

# 2. Instalar dependencias
pip install -r requirements.txt

# 3. Configurar variables de entorno
cp .env.example .env
# Editar .env con tus valores reales

# 4. Ejecutar
python app.py
# Abrir: http://localhost:5000
```

**Credenciales admin por defecto:**
- Usuario: `admin`
- Contraseña: la que pongas en `ADMIN_PASSWORD` en `.env` (default: `Admin@1234!`)
- ⚠️ Cámbiala inmediatamente en producción

---

## ☁️ Despliegue en Render.com (GRATIS — soporte Python)

> ⚠️ **¿Por qué Render y no Netlify?**
> Netlify solo soporta sitios estáticos (HTML/JS/CSS). Para correr Python/Flask necesitas un servidor real. **Render.com** ofrece un tier gratuito perfecto para esto.

### Pasos:

1. Sube el código a **GitHub** (asegúrate de que `.env` está en `.gitignore`)
2. Ve a [render.com](https://render.com) → **New Web Service**
3. Conecta tu repositorio de GitHub
4. Configura:
   - **Runtime:** Python 3
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn app:app`
5. En **Environment Variables**, agrega todas las del `.env.example` con valores reales
6. Render asigna automáticamente un dominio `https://tu-app.onrender.com` ✅
7. HTTPS es gratuito y automático 🔒

---

## 📂 Estructura del Proyecto

```
notepad/
├── app.py              # Aplicación principal (rutas, modelos, seguridad)
├── requirements.txt    # Dependencias con versiones fijadas
├── .env.example        # Plantilla de variables de entorno
├── .gitignore          # Excluye .env, DB y logs
├── logs/               # Archivos de log (generados en runtime)
│   ├── security.log    # Eventos de seguridad y auditoría
│   └── app.log         # Errores de aplicación
└── templates/
    ├── base.html       # Layout base
    ├── index.html      # Landing page
    ├── login.html      # Inicio de sesión
    ├── register.html   # Registro con validación de contraseña
    ├── notes.html      # CRUD de notas
    └── admin.html      # Panel admin (usuarios + audit logs)
```

---

## 🔍 Lo que debes hacer MANUALMENTE para verificar

| Acción | Cómo verificarlo |
|--------|-----------------|
| Revisar JWT | Copia la cookie `access_token` → pégala en [jwt.io](https://jwt.io) para ver el payload |
| Ver logs | Después de varias acciones: `cat logs/security.log` |
| Revisar hashes | Abre `notepad.db` con DB Browser for SQLite — verifica que `password_hash` empieza con `$2b$` |
| Probar bloqueo | Intenta login incorrecto 5 veces → la cuenta se bloquea 15 min |
| Probar rate limit | Envía +10 requests de login en 15 min → obtienes 429 |
| SAST | `bandit -r app.py` → genera reporte de análisis estático |
| Dependencias | `pip-audit -r requirements.txt` → verifica vulnerabilidades CVE |
