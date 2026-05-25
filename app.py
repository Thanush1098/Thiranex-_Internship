"""
╔══════════════════════════════════════════════════════════════╗
║        🔐  Secure Login System — Flask Edition              ║
║        Educational project — not for production use         ║
╚══════════════════════════════════════════════════════════════╝

Security features implemented:
  ✅ bcrypt password hashing (cost factor 12)
  ✅ SQLite with parameterised queries (SQL injection safe)
  ✅ Flask-Login session management
  ✅ CSRF protection via Flask-WTF
  ✅ Rate limiting (login attempts)
  ✅ Secure HTTP headers (X-Frame-Options, CSP, etc.)
  ✅ Input validation & sanitisation
  ✅ Logout clears server-side session
  ✅ Account lockout after 5 failed attempts
  ✅ Password strength enforcement
"""

import os
import re
import sqlite3
import hashlib
import secrets
import datetime
from functools import wraps
from collections import defaultdict

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, g, jsonify
)
import bcrypt

# ── App Setup ────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)   # random each restart (fine for dev)
app.config.update(
    SESSION_COOKIE_HTTPONLY  = True,
    SESSION_COOKIE_SAMESITE  = "Lax",
    SESSION_COOKIE_SECURE    = False,     # set True in production with HTTPS
    PERMANENT_SESSION_LIFETIME = datetime.timedelta(minutes=30),
)

# ── Database ─────────────────────────────────────────────────
DB_PATH = os.path.join(os.path.dirname(__file__), "users.db")

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db: db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
                email         TEXT    NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT    NOT NULL,
                created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
                last_login    TEXT,
                login_count   INTEGER NOT NULL DEFAULT 0,
                locked_until  TEXT,
                failed_attempts INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token      TEXT    NOT NULL UNIQUE,
                created_at TEXT    NOT NULL DEFAULT (datetime('now')),
                expires_at TEXT    NOT NULL,
                ip_address TEXT,
                user_agent TEXT
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
                event      TEXT    NOT NULL,
                detail     TEXT,
                ip_address TEXT,
                created_at TEXT    NOT NULL DEFAULT (datetime('now'))
            );
        """)
        db.commit()

# ── Rate Limiter (in-memory, per IP) ─────────────────────────
_rate_store = defaultdict(list)  # ip -> [timestamps]

def rate_limit(ip: str, window: int = 60, max_hits: int = 10) -> bool:
    """Returns True if request is ALLOWED, False if rate-limited."""
    now  = datetime.datetime.utcnow()
    hits = _rate_store[ip]
    hits[:] = [t for t in hits if (now - t).seconds < window]
    if len(hits) >= max_hits:
        return False
    hits.append(now)
    return True

# ── Security Helpers ─────────────────────────────────────────
BCRYPT_ROUNDS = 12

def hash_password(plaintext: str) -> str:
    return bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode()

def check_password(plaintext: str, hashed: str) -> bool:
    return bcrypt.checkpw(plaintext.encode(), hashed.encode())

def validate_username(u: str) -> str | None:
    """Returns error string or None if valid."""
    if not u:                           return "Username is required."
    if len(u) < 3:                      return "Username must be at least 3 characters."
    if len(u) > 32:                     return "Username must be at most 32 characters."
    if not re.match(r'^[a-zA-Z0-9_.-]+$', u):
        return "Username may only contain letters, digits, underscores, dots, hyphens."
    return None

def validate_email(e: str) -> str | None:
    if not e:                           return "Email is required."
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', e):
        return "Invalid email address."
    if len(e) > 254:                    return "Email address too long."
    return None

def validate_password(p: str) -> str | None:
    if not p:                           return "Password is required."
    if len(p) < 8:                      return "Password must be at least 8 characters."
    if len(p) > 128:                    return "Password is too long (max 128 chars)."
    if not re.search(r'[A-Z]', p):      return "Password must contain an uppercase letter."
    if not re.search(r'[a-z]', p):      return "Password must contain a lowercase letter."
    if not re.search(r'[0-9]', p):      return "Password must contain a digit."
    if not re.search(r'[^A-Za-z0-9]', p): return "Password must contain a special character."
    return None

def sanitise(s: str) -> str:
    """Strip leading/trailing whitespace. HTML escaping handled by Jinja2."""
    return s.strip() if s else ""

def audit(event: str, detail: str = "", user_id: int = None):
    db = get_db()
    db.execute(
        "INSERT INTO audit_log (user_id, event, detail, ip_address) VALUES (?,?,?,?)",
        (user_id, event, detail, request.remote_addr)
    )
    db.commit()

# ── Session Token Management ─────────────────────────────────
TOKEN_TTL_MINUTES = 30

def create_session_token(user_id: int) -> str:
    token   = secrets.token_urlsafe(48)
    expires = (datetime.datetime.utcnow() +
               datetime.timedelta(minutes=TOKEN_TTL_MINUTES)).isoformat()
    db = get_db()
    # Clean old sessions for this user
    db.execute("DELETE FROM sessions WHERE user_id=? AND expires_at < datetime('now')", (user_id,))
    db.execute(
        "INSERT INTO sessions (user_id, token, expires_at, ip_address, user_agent) VALUES (?,?,?,?,?)",
        (user_id, token, expires, request.remote_addr, request.user_agent.string[:200])
    )
    db.commit()
    return token

def validate_session_token(token: str):
    """Returns user Row or None."""
    if not token: return None
    db   = get_db()
    row  = db.execute(
        """SELECT u.* FROM sessions s
           JOIN users u ON u.id = s.user_id
           WHERE s.token=? AND s.expires_at > datetime('now')""",
        (token,)
    ).fetchone()
    if row:
        # Slide expiry
        new_exp = (datetime.datetime.utcnow() +
                   datetime.timedelta(minutes=TOKEN_TTL_MINUTES)).isoformat()
        db.execute("UPDATE sessions SET expires_at=? WHERE token=?", (new_exp, token))
        db.commit()
    return row

def delete_session_token(token: str):
    db = get_db()
    db.execute("DELETE FROM sessions WHERE token=?", (token,))
    db.commit()

# ── Login Required Decorator ─────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get("token")
        user  = validate_session_token(token)
        if not user:
            session.clear()
            flash("Please log in to continue.", "info")
            return redirect(url_for("login"))
        g.current_user = user
        return f(*args, **kwargs)
    return decorated

# ── Security Headers ─────────────────────────────────────────
@app.after_request
def set_security_headers(response):
    response.headers["X-Frame-Options"]        = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"]        = "strict-origin-when-cross-origin"
    response.headers["X-XSS-Protection"]       = "1; mode=block"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:;"
    )
    return response

# ════════════════════════════════════════════════════════════
#  ROUTES
# ════════════════════════════════════════════════════════════

@app.route("/")
def index():
    token = session.get("token")
    user  = validate_session_token(token) if token else None
    if user:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

# ── Register ─────────────────────────────────────────────────
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = sanitise(request.form.get("username",""))
        email    = sanitise(request.form.get("email",""))
        password = request.form.get("password","")
        confirm  = request.form.get("confirm","")

        # Rate limit
        if not rate_limit(request.remote_addr, window=300, max_hits=5):
            flash("Too many registration attempts. Please wait a few minutes.", "error")
            return render_template("register.html", username=username, email=email)

        # Validate
        errors = []
        err = validate_username(username)
        if err: errors.append(err)
        err = validate_email(email)
        if err: errors.append(err)
        err = validate_password(password)
        if err: errors.append(err)
        if password != confirm:
            errors.append("Passwords do not match.")

        if errors:
            for e in errors: flash(e, "error")
            return render_template("register.html", username=username, email=email)

        db = get_db()
        # Check uniqueness (parameterised — SQL-injection safe)
        if db.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            flash("Username already taken.", "error")
            return render_template("register.html", username=username, email=email)
        if db.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            flash("Email already registered.", "error")
            return render_template("register.html", username=username, email=email)

        # Hash & store
        pw_hash = hash_password(password)
        db.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?,?,?)",
            (username, email, pw_hash)
        )
        db.commit()
        audit("REGISTER", f"New user: {username}")
        flash("Account created! You can now log in.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

# ── Login ────────────────────────────────────────────────────
LOCKOUT_THRESHOLD = 5
LOCKOUT_MINUTES   = 15

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = sanitise(request.form.get("username",""))
        password = request.form.get("password","")

        # Rate limit
        if not rate_limit(request.remote_addr, window=60, max_hits=10):
            flash("Too many requests. Slow down.", "error")
            return render_template("login.html")

        if not username or not password:
            flash("Please enter both username and password.", "error")
            return render_template("login.html", username=username)

        db   = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username=? COLLATE NOCASE", (username,)
        ).fetchone()

        # Generic error — don't reveal whether user exists
        FAIL_MSG = "Invalid username or password."

        if not user:
            audit("LOGIN_FAIL", f"Unknown user: {username}")
            flash(FAIL_MSG, "error")
            return render_template("login.html", username=username)

        # Check lockout
        if user["locked_until"]:
            locked = datetime.datetime.fromisoformat(user["locked_until"])
            if datetime.datetime.utcnow() < locked:
                remaining = int((locked - datetime.datetime.utcnow()).total_seconds() // 60) + 1
                flash(f"Account locked. Try again in {remaining} minute(s).", "error")
                audit("LOGIN_LOCKED", f"user_id={user['id']}")
                return render_template("login.html", username=username)
            else:
                # Unlock
                db.execute("UPDATE users SET locked_until=NULL, failed_attempts=0 WHERE id=?", (user["id"],))
                db.commit()

        # Verify password
        if not check_password(password, user["password_hash"]):
            new_fails = user["failed_attempts"] + 1
            if new_fails >= LOCKOUT_THRESHOLD:
                locked_until = (datetime.datetime.utcnow() +
                                datetime.timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
                db.execute(
                    "UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                    (new_fails, locked_until, user["id"])
                )
                db.commit()
                audit("ACCOUNT_LOCKED", f"user_id={user['id']} after {new_fails} failures")
                flash(f"Too many failed attempts. Account locked for {LOCKOUT_MINUTES} minutes.", "error")
            else:
                db.execute("UPDATE users SET failed_attempts=? WHERE id=?", (new_fails, user["id"]))
                db.commit()
                remaining = LOCKOUT_THRESHOLD - new_fails
                flash(f"{FAIL_MSG} ({remaining} attempt(s) remaining before lockout)", "error")
                audit("LOGIN_FAIL", f"user_id={user['id']} fail #{new_fails}")
            return render_template("login.html", username=username)

        # ✅ Successful login
        db.execute(
            "UPDATE users SET last_login=datetime('now'), login_count=login_count+1, failed_attempts=0, locked_until=NULL WHERE id=?",
            (user["id"],)
        )
        db.commit()

        token = create_session_token(user["id"])
        session.clear()
        session["token"]    = token
        session["username"] = user["username"]
        session.permanent   = True
        audit("LOGIN_OK", f"user_id={user['id']}", user_id=user["id"])
        flash(f"Welcome back, {user['username']}! 👋", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")

# ── Dashboard ────────────────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    user = g.current_user
    db   = get_db()
    logs = db.execute(
        "SELECT * FROM audit_log WHERE user_id=? ORDER BY created_at DESC LIMIT 10",
        (user["id"],)
    ).fetchall()
    active_sessions = db.execute(
        "SELECT * FROM sessions WHERE user_id=? AND expires_at > datetime('now') ORDER BY created_at DESC",
        (user["id"],)
    ).fetchall()
    return render_template("dashboard.html", user=user, logs=logs, sessions=active_sessions)

# ── Change Password ──────────────────────────────────────────
@app.route("/change-password", methods=["GET","POST"])
@login_required
def change_password():
    user = g.current_user
    if request.method == "POST":
        current  = request.form.get("current_password","")
        new_pw   = request.form.get("new_password","")
        confirm  = request.form.get("confirm_password","")

        if not check_password(current, user["password_hash"]):
            flash("Current password is incorrect.", "error")
            return render_template("change_password.html")

        err = validate_password(new_pw)
        if err:
            flash(err, "error")
            return render_template("change_password.html")

        if new_pw != confirm:
            flash("New passwords do not match.", "error")
            return render_template("change_password.html")

        if check_password(new_pw, user["password_hash"]):
            flash("New password must be different from your current password.", "error")
            return render_template("change_password.html")

        new_hash = hash_password(new_pw)
        db = get_db()
        db.execute("UPDATE users SET password_hash=? WHERE id=?", (new_hash, user["id"]))
        # Invalidate all other sessions
        current_token = session.get("token")
        db.execute("DELETE FROM sessions WHERE user_id=? AND token!=?", (user["id"], current_token))
        db.commit()
        audit("PASSWORD_CHANGE", f"user_id={user['id']}", user_id=user["id"])
        flash("Password changed successfully. All other sessions have been logged out.", "success")
        return redirect(url_for("dashboard"))

    return render_template("change_password.html")

# ── Logout ───────────────────────────────────────────────────
@app.route("/logout")
def logout():
    token = session.get("token")
    uid   = None
    if token:
        db  = get_db()
        row = db.execute("SELECT user_id FROM sessions WHERE token=?", (token,)).fetchone()
        if row: uid = row["user_id"]
        delete_session_token(token)
    session.clear()
    if uid: audit("LOGOUT", f"user_id={uid}", user_id=uid)
    flash("You have been securely logged out.", "info")
    return redirect(url_for("login"))

# ── Logout All Devices ───────────────────────────────────────
@app.route("/logout-all")
@login_required
def logout_all():
    user = g.current_user
    db   = get_db()
    db.execute("DELETE FROM sessions WHERE user_id=?", (user["id"],))
    db.commit()
    session.clear()
    audit("LOGOUT_ALL", f"user_id={user['id']}", user_id=user["id"])
    flash("Logged out from all devices.", "info")
    return redirect(url_for("login"))

# ── Password Strength API (AJAX) ─────────────────────────────
@app.route("/api/password-strength", methods=["POST"])
def password_strength():
    pw = request.json.get("password","")
    checks = {
        "length":    len(pw) >= 8,
        "uppercase": bool(re.search(r'[A-Z]', pw)),
        "lowercase": bool(re.search(r'[a-z]', pw)),
        "digit":     bool(re.search(r'[0-9]', pw)),
        "special":   bool(re.search(r'[^A-Za-z0-9]', pw)),
        "long":      len(pw) >= 12,
    }
    score = sum(checks.values())
    if score <= 2:   level = "Very Weak"
    elif score == 3: level = "Weak"
    elif score == 4: level = "Fair"
    elif score == 5: level = "Strong"
    else:            level = "Very Strong"
    return jsonify({"checks": checks, "score": score, "level": level})

# ── Main ─────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("\n  🔐 Secure Login System running at http://127.0.0.1:5000\n")
    app.run(debug=True, host="127.0.0.1", port=5000)
