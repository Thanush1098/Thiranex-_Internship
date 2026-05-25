# 🔐 Secure Login System — Flask Edition

> Educational secure web application with industry-standard security practices.

---

## 🚀 Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the app
python app.py

# 3. Open in browser
# → http://127.0.0.1:5000
```

---

## 🛡️ Security Features

| Feature | Implementation |
|---------|---------------|
| **Password Hashing** | bcrypt with cost factor 12 (adaptive) |
| **SQL Injection Prevention** | Parameterised queries throughout |
| **Session Management** | Server-side token (48-byte random, urlsafe) |
| **Account Lockout** | 5 failed attempts → 15-minute lockout |
| **Rate Limiting** | Per-IP request throttling |
| **Input Validation** | Server-side regex + length checks |
| **Secure Headers** | CSP, X-Frame-Options, X-Content-Type-Options |
| **Session Expiry** | 30-minute sliding window |
| **Logout All Devices** | Invalidates all session tokens at once |
| **Audit Log** | Every login, logout, failure recorded |
| **Password Strength API** | Live AJAX feedback during registration |
| **Cookie Flags** | HttpOnly, SameSite=Lax |

---

## 📁 Project Structure

```
secure-login/
├── app.py                  # Main Flask application
├── requirements.txt        # Dependencies
├── users.db                # SQLite database (auto-created)
├── README.md
└── templates/
    ├── base.html           # Shared layout + dark UI
    ├── login.html          # Login page
    ├── register.html       # Registration + live password strength
    ├── dashboard.html      # User dashboard + audit log
    └── change_password.html # Password change form
```

---

## 🗄️ Database Schema

```sql
-- Stores user accounts
CREATE TABLE users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT UNIQUE NOT NULL,
    email           TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,          -- bcrypt hash
    created_at      TEXT NOT NULL,
    last_login      TEXT,
    login_count     INTEGER DEFAULT 0,
    locked_until    TEXT,                   -- NULL = not locked
    failed_attempts INTEGER DEFAULT 0
);

-- Server-side session tokens
CREATE TABLE sessions (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER REFERENCES users(id),
    token      TEXT UNIQUE NOT NULL,        -- 48-byte random token
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT
);

-- Immutable audit trail
CREATE TABLE audit_log (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER,
    event      TEXT NOT NULL,              -- LOGIN_OK, LOGIN_FAIL, etc.
    detail     TEXT,
    ip_address TEXT,
    created_at TEXT NOT NULL
);
```

---

## 🔑 Password Requirements

- Minimum 8 characters
- At least one uppercase letter (A–Z)
- At least one lowercase letter (a–z)
- At least one digit (0–9)
- At least one special character (!@#$%…)

---

## 🎓 Security Concepts Learned

- **bcrypt** — Adaptive hashing algorithm; cost factor controls computation time
- **Parameterised queries** — Separate code from data, preventing SQL injection
- **Session tokens** — Cryptographically random identifiers stored server-side
- **Account lockout** — Throttles brute-force attacks automatically
- **Audit logging** — Creates an immutable trail for incident response
- **CSP headers** — Content Security Policy prevents XSS attacks
- **SameSite cookies** — Prevents CSRF attacks on session cookies

---

## ⚠️ Production Checklist

Before deploying to production:
- [ ] Set `SESSION_COOKIE_SECURE = True` (requires HTTPS)
- [ ] Use a persistent `SECRET_KEY` (not regenerated on restart)
- [ ] Add HTTPS / TLS (Let's Encrypt)
- [ ] Move to PostgreSQL or MySQL for production databases
- [ ] Set up proper logging (not just audit_log table)
- [ ] Add email verification on registration
- [ ] Consider adding TOTP-based 2FA
