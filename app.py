import os
import base64
import sqlite3
import time
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet  # Changement d'import

app = Flask(__name__)
app.secret_key = os.urandom(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)
login_manager = LoginManager(app)
DB_PATH = "vault.db"

def get_db():
    return sqlite3.connect(DB_PATH)

def init_db():
    with get_db() as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_salt BLOB, password_hash BLOB)''')
        c.execute('''CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY, user_id INTEGER, username TEXT, label TEXT,
            token BLOB, FOREIGN KEY(user_id) REFERENCES users(id))''')  # Schéma modifié
        c.execute('''CREATE TABLE IF NOT EXISTS shares (
            id INTEGER PRIMARY KEY, link_id TEXT, token BLOB, expires_at INTEGER)''')  # Schéma modifié
init_db()

class User(UserMixin):
    def __init__(self, id_, username): self.id, self.username = id_, username

@login_manager.user_loader
def load_user(user_id):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
        row = c.fetchone()
        return User(*row) if row else None

def get_user(username):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT id, username, password_salt, password_hash FROM users WHERE username = ?", (username,))
        return c.fetchone()

def hash_password(password, salt=None):
    salt = salt or os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100_000)
    return salt, kdf.derive(password.encode())

def verify_password(stored_salt, stored_hash, password):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=stored_salt, iterations=100_000)
    try:
        kdf.verify(password.encode(), stored_hash)
        return True
    except Exception:
        return False

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username, password = request.form["username"], request.form["password"]
        user = get_user(username)
        if user and verify_password(user[2], user[3], password):
            login_user(User(user[0], user[1]))
            session["key"] = base64.urlsafe_b64encode(hash_password(password, user[2])[1]).decode()  # Encodage modifié
            return redirect(url_for("vault"))
        flash("Identifiants invalides.")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username, password = request.form["username"], request.form["password"]
        if get_user(username):
            flash("Utilisateur déjà existant.")
        else:
            salt, key = hash_password(password)
            with get_db() as conn:
                conn.execute("INSERT INTO users (username, password_salt, password_hash) VALUES (?, ?, ?)", (username, salt, key))
                conn.commit()
            flash("Inscription réussie. Connectez-vous.")
            return redirect(url_for("login"))
    return render_template("login.html", register=True)

@app.route("/logout")
@login_required
def logout():
    session.clear()
    logout_user()
    return redirect(url_for("login"))

@app.route("/vault")
@login_required
def vault():
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT id, token, username, label FROM passwords WHERE user_id = ?", (current_user.id,))
        items = c.fetchall()
    passwords = []
    for item in items:
        try:
            fernet = Fernet(session["key"].encode())
            decrypted = fernet.decrypt(item[1]).decode()  # Déchiffrement simplifié
            passwords.append({"id": item[0], "username": item[2], "label": item[3], "password": decrypted})
        except Exception:
            passwords.append({"id": item[0], "username": item[2], "label": item[3], "password": "***"})
    return render_template("vault.html", passwords=passwords)

@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "POST":
        label, pwd, username = request.form["label"], request.form["password"], request.form["username"]
        fernet = Fernet(session["key"].encode())
        token = fernet.encrypt(pwd.encode())  # Chiffrement simplifié
        with get_db() as conn:
            conn.execute("INSERT INTO passwords (user_id, username, label, token) VALUES (?, ?, ?, ?)",
                         (current_user.id, username, label, token))
            conn.commit()
        return redirect(url_for("vault"))
    return render_template("add.html")

@app.route("/delete/<int:id>")
@login_required
def delete(id):
    with get_db() as conn:
        conn.execute("DELETE FROM passwords WHERE id = ? AND user_id = ?", (id, current_user.id))
        conn.commit()
    return redirect(url_for("vault"))

@app.route("/generate")
@login_required
def generate():
    import secrets, string
    alphabet = string.ascii_letters + string.digits + string.punctuation
    pwd = ''.join(secrets.choice(alphabet) for _ in range(16))
    return {"password": pwd}

@app.route("/share/<int:id>", methods=["GET", "POST"])
@login_required
def share(id):
    if request.method == "POST":
        expires = int(request.form.get("expires", 300))
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT token FROM passwords WHERE id = ? AND user_id = ?", (id, current_user.id))
            row = c.fetchone()
            if not row: abort(404)
            link_id = base64.urlsafe_b64encode(os.urandom(9)).decode().rstrip("=")
            c.execute("INSERT INTO shares (link_id, token, expires_at) VALUES (?, ?, ?)",
                      (link_id, row[0], int(time.time()) + expires))
            conn.commit()
        return render_template("share.html", link_id=link_id)
    return render_template("share.html", link_id=None)

@app.route("/shared/<link_id>")
def shared(link_id):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT token, expires_at FROM shares WHERE link_id = ?", (link_id,))
        row = c.fetchone()
        if not row or row[1] < int(time.time()): abort(404)
        c.execute("DELETE FROM shares WHERE link_id = ?", (link_id,))
        conn.commit()
    return render_template("shared.html", token=row[0].decode())  # Simplification du token

if __name__ == "__main__":
    app.run(debug=True)
