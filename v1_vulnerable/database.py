import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "authx_v1.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            email       TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role        TEXT NOT NULL DEFAULT 'USER',
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            locked      INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS tickets (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            title       TEXT NOT NULL,
            description TEXT,
            severity    TEXT DEFAULT 'LOW',
            status      TEXT DEFAULT 'OPEN',
            owner_id    INTEGER NOT NULL,
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS reset_tokens (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            token       TEXT NOT NULL,
            used        INTEGER DEFAULT 0,
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER,
            action      TEXT NOT NULL,
            resource    TEXT,
            resource_id TEXT,
            ip_address  TEXT,
            timestamp   TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)

    conn.commit()
    conn.close()
    print("[DB] Baza de date initializata.")


# ---------- USERS ----------

def get_user_by_email(email):
    conn = get_connection()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    conn.close()
    return user


def get_user_by_id(user_id):
    conn = get_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return user


def create_user(email, password_hash, role="USER"):
    conn = get_connection()
    conn.execute(
        "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
        (email, password_hash, role)
    )
    conn.commit()
    conn.close()


def update_password(user_id, password_hash):
    conn = get_connection()
    conn.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (password_hash, user_id)
    )
    conn.commit()
    conn.close()


# ---------- RESET TOKENS ----------

def save_reset_token(user_id, token):
    conn = get_connection()
    conn.execute(
        "INSERT INTO reset_tokens (user_id, token) VALUES (?, ?)",
        (user_id, token)
    )
    conn.commit()
    conn.close()


def get_reset_token(token):
    conn = get_connection()
    # VULNERABIL: nu verifica daca token-ul a fost deja folosit
    row = conn.execute(
        "SELECT * FROM reset_tokens WHERE token = ?",
        (token,)
    ).fetchone()
    conn.close()
    return row


# ---------- TICKETS ----------

def get_tickets_by_user(user_id):
    conn = get_connection()
    tickets = conn.execute(
        "SELECT * FROM tickets WHERE owner_id = ? ORDER BY created_at DESC",
        (user_id,)
    ).fetchall()
    conn.close()
    return tickets


def create_ticket(title, description, severity, owner_id):
    conn = get_connection()
    conn.execute(
        "INSERT INTO tickets (title, description, severity, owner_id) VALUES (?, ?, ?, ?)",
        (title, description, severity, owner_id)
    )
    conn.commit()
    conn.close()


# ---------- AUDIT ----------

def log_action(user_id, action, resource, resource_id, ip_address):
    conn = get_connection()
    conn.execute(
        "INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address) VALUES (?, ?, ?, ?, ?)",
        (user_id, action, resource, str(resource_id), ip_address)
    )
    conn.commit()
    conn.close()
