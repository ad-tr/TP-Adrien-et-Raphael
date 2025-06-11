import os
import base64
import re
import sqlite3
import time
import json
from datetime import timedelta
import bcrypt
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import secrets
import string
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
            id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, salt BLOB)''')
        c.execute('''CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY, user_id INTEGER, username TEXT, label TEXT,
            token BLOB, category TEXT, FOREIGN KEY(user_id) REFERENCES users(id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS shares (
            id INTEGER PRIMARY KEY, link_id TEXT, token BLOB, expires_at INTEGER)''')
init_db()

class User(UserMixin):
    def __init__(self, id_, username):
        self.id, self.username = id_, username

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
        c.execute("SELECT id, username, password, salt FROM users WHERE username = ?", (username,))
        return c.fetchone()

def create_fernet_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600_000,
    )
    key_bytes = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(key_bytes)

def encrypt_password_fernet(password, key):
    f = Fernet(key)
    return f.encrypt(password.encode())

def decrypt_password_fernet(encrypted_data, key):
    try:
        f = Fernet(key)
        return f.decrypt(encrypted_data).decode()
    except Exception:
        return None
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username, password = request.form["username"], request.form["password"]
        user = get_user(username)
        if user and bcrypt.checkpw(password.encode(), user[2]):
            print(user)
            salt = user[3]

            session["key"] = create_fernet_key(password, salt)
            login_user(User(user[0], user[1]))
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
            with get_db() as conn:
                salt = os.urandom(16)
                hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
                conn.execute("INSERT INTO users (username, password, salt) VALUES (?, ?, ?)", (username, hashed, salt))
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
        c.execute("SELECT id, token, username, label, category FROM passwords WHERE user_id = ?", (current_user.id,))
        items = c.fetchall()
    passwords = []
    key = session.get("key")

    for item in items:
        decrypted = decrypt_password_fernet(item[1], key)
        print(decrypted)
        print(item[1])
        if decrypted:
            passwords.append({"id": item[0], "username": item[2], "label": item[3],"category": item[4], "password": decrypted})
        else:
            passwords.append({"id": item[0], "username": item[2], "label": item[3],"category": item[4], "password": "***"})

    return render_template("vault.html", passwords=passwords)

@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "POST":
        label, pwd, username, category = request.form["label"], request.form["password"], request.form["username"], request.form["category"]
        key = session.get("key")
        token = encrypt_password_fernet(pwd, key)

        with get_db() as conn:
            conn.execute("INSERT INTO passwords (user_id, username, label, token, category) VALUES (?, ?, ?, ?, ?)",
                         (current_user.id, username, label, token, category))
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
    alphabet = string.ascii_letters + string.digits + string.punctuation
    pwd = ''.join(secrets.choice(alphabet) for _ in range(16))
    return {"password": pwd}

@app.route("/share/<int:id>", methods=["GET", "POST"])
@login_required
def share(id):
    if request.method == "POST":
        expires = int(request.form.get("expires", 300))
        key = session.get("key")

        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT token, username, label FROM passwords WHERE id = ? AND user_id = ?",
                      (id, current_user.id))
            row = c.fetchone()
            if not row:
                abort(404)

            decrypted_password = decrypt_password_fernet(row[0], key)
            if not decrypted_password:
                flash("Erreur lors du déchiffrement du mot de passe.")
                return redirect(url_for("vault"))

            share_data = {
                "password": decrypted_password,
                "username": row[1],
                "label": row[2],
                "category": row[3]
            }

            temp_key = base64.urlsafe_b64encode(os.urandom(32))
            f = Fernet(temp_key)

            encrypted_data = f.encrypt(json.dumps(share_data).encode())
            link_id = base64.urlsafe_b64encode(os.urandom(9)).decode().rstrip("=")
            c.execute("INSERT INTO shares (link_id, token, expires_at) VALUES (?, ?, ?)",
                      (link_id, encrypted_data, int(time.time()) + expires))
            conn.commit()

        share_url = f"/shared/{link_id}?key={temp_key.decode()}"
        return render_template("share.html", link_id=link_id, share_url=share_url)
    return render_template("share.html", link_id=None)

@app.route("/share_multiple", methods=["POST"])
@login_required
def share_multiple():
    ids = request.form.getlist("selected_ids")
    if not ids:
        flash("Aucune ligne sélectionnée.")
        return redirect(url_for("vault"))

    key = session.get("key")
    shared_items = []

    with get_db() as conn:
        c = conn.cursor()
        placeholders = ",".join("?" for _ in ids)
        query = f"SELECT id, token, username, label FROM passwords WHERE id IN ({placeholders}) AND user_id = ?"
        c.execute(query, (*ids, current_user.id))
        rows = c.fetchall()

        for row in rows:
            password = re.search(r"b'([^']*)'", str(row[1]))
            decrypted_password = decrypt_password_fernet(password.group(1), key)
            if decrypted_password:
                shared_items.append({
                    "id": row[0],
                    "password": decrypted_password,
                    "username": row[2],
                    "label": row[3]
                })

    if not shared_items:
        flash("Erreur lors du déchiffrement des mots de passe.")
        return redirect(url_for("vault"))

    temp_key = base64.urlsafe_b64encode(os.urandom(32))
    f = Fernet(temp_key)
    encrypted_data = f.encrypt(json.dumps(shared_items).encode())
    link_id = base64.urlsafe_b64encode(os.urandom(9)).decode().rstrip("=")
    expires = 300
    print(shared_items)

    with get_db() as conn:
        c = conn.cursor()
        c.execute("INSERT INTO shares (link_id, token, expires_at) VALUES (?, ?, ?)",
                  (link_id, encrypted_data, int(time.time()) + expires))
        conn.commit()

    share_url = f"/shared/{link_id}?key={temp_key.decode()}"
    return render_template("share.html", link_id=link_id, share_url=share_url)

@app.route("/shared/<link_id>")
def shared(link_id):
    temp_key = request.args.get('key')

    if not temp_key:
        flash("Clé de déchiffrement manquante")
        abort(404)

    try:
        temp_key_bytes = temp_key.encode('utf-8') if isinstance(temp_key, str) else temp_key
        decoded_key = base64.urlsafe_b64decode(temp_key_bytes)
        if len(decoded_key) != 32:
            raise ValueError("Clé invalide")
    except Exception:
        flash("Clé de déchiffrement invalide")
        abort(404)

    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT token, expires_at FROM shares WHERE link_id = ?", (link_id,))
        row = c.fetchone()
        if not row or row[1] < int(time.time()):
            flash("Lien expiré ou introuvable")
            abort(404)

        encrypted_data = row[0]
        if isinstance(encrypted_data, str):
            encrypted_data = encrypted_data.encode('utf-8')

    try:
        f = Fernet(temp_key_bytes)
        decrypted_data = f.decrypt(encrypted_data).decode('utf-8')
        share_data = json.loads(decrypted_data)

        with get_db() as conn:
            c = conn.cursor()
            c.execute("DELETE FROM shares WHERE link_id = ?", (link_id,))
            conn.commit()

        if isinstance(share_data, list):
            return render_template("shared.html", items=share_data)
        return render_template("shared.html",
                               password=share_data.get("password"),
                               username=share_data.get("username"),
                               label=share_data.get("label"),
                               items=None)
    except Exception as e:
        print(f"Erreur de déchiffrement: {e}")
        flash("Impossible de déchiffrer le lien partagé")
        abort(404)


if __name__ == "__main__":
    app.run(debug=True)