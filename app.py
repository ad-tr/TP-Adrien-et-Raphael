import hashlib
import os
import base64
import sqlite3
import time
import json
from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from cryptography.fernet import Fernet
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
            id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY, user_id INTEGER, username TEXT, label TEXT,
            token BLOB, FOREIGN KEY(user_id) REFERENCES users(id))''')
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
        c.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
        return c.fetchone()


def create_fernet_key(password):
    """Crée une clé Fernet directement à partir du mot de passe utilisateur"""
    key_bytes = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(key_bytes)


def encrypt_password_fernet(password, user_password):
    """Chiffrement avec Fernet"""
    key = create_fernet_key(user_password)
    f = Fernet(key)
    return f.encrypt(password.encode())


def decrypt_password_fernet(encrypted_data, user_password):
    """Déchiffrement avec Fernet"""
    try:
        key = create_fernet_key(user_password)
        f = Fernet(key)
        return f.decrypt(encrypted_data).decode()
    except Exception:
        return None


@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username, password = request.form["username"], request.form["password"]
        user = get_user(username)
        if user and user[2] == password:
            login_user(User(user[0], user[1]))
            session["user_password"] = password
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
                conn.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                             (username, password))
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
    user_password = session.get("user_password")

    for item in items:
        decrypted = decrypt_password_fernet(item[1], user_password)
        if decrypted:
            passwords.append({"id": item[0], "username": item[2], "label": item[3], "password": decrypted})
        else:
            passwords.append({"id": item[0], "username": item[2], "label": item[3], "password": "***"})

    return render_template("vault.html", passwords=passwords)


@app.route("/add", methods=["GET", "POST"])
@login_required
def add():
    if request.method == "POST":
        label, pwd, username = request.form["label"], request.form["password"], request.form["username"]
        user_password = session.get("user_password")
        token = encrypt_password_fernet(pwd, user_password)

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
    alphabet = string.ascii_letters + string.digits + string.punctuation
    pwd = ''.join(secrets.choice(alphabet) for _ in range(16))
    return {"password": pwd}


@app.route("/share/<int:id>", methods=["GET", "POST"])
@login_required
def share(id):
    if request.method == "POST":
        expires = int(request.form.get("expires", 300))
        user_password = session.get("user_password")

        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT token, username, label FROM passwords WHERE id = ? AND user_id = ?",
                      (id, current_user.id))
            row = c.fetchone()
            if not row:
                abort(404)

            decrypted_password = decrypt_password_fernet(row[0], user_password)
            if not decrypted_password:
                flash("Erreur lors du déchiffrement du mot de passe.")
                return redirect(url_for("vault"))

            share_data = {
                "password": decrypted_password,
                "username": row[1],
                "label": row[2]
            }

            # Génération d'une clé temporaire pour ce partage
            temp_key = base64.urlsafe_b64encode(os.urandom(32))
            f = Fernet(temp_key)

            # Chiffrement des données avec JSON au lieu de str()
            encrypted_data = f.encrypt(json.dumps(share_data).encode())

            # Génération du hash temporaire pour l'URL
            link_id = base64.urlsafe_b64encode(os.urandom(9)).decode().rstrip("=")

            # Stockage uniquement des données chiffrées en base
            c.execute("INSERT INTO shares (link_id, token, expires_at) VALUES (?, ?, ?)",
                      (link_id, encrypted_data, int(time.time()) + expires))
            conn.commit()

        # URL avec la clé en paramètre GET
        share_url = f"/shared/{link_id}?key={temp_key.decode()}"

        return render_template("share.html", link_id=link_id, share_url=share_url)
    return render_template("share.html", link_id=None)


@app.route("/shared/<link_id>")
def shared(link_id):
    # Récupération et validation de la clé depuis les paramètres GET
    temp_key = request.args.get('key')

    if not temp_key:
        flash("Clé de déchiffrement manquante")
        abort(404)

    # Validation de la clé base64
    try:
        temp_key_bytes = temp_key.encode()
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

        # Récupération des données chiffrées
        encrypted_data = row[0]

    try:
        # Déchiffrement avec la clé récupérée des paramètres GET
        f = Fernet(temp_key_bytes)
        decrypted_data = f.decrypt(encrypted_data).decode()

        # Utilisation de JSON au lieu d'ast.literal_eval()
        share_data = json.loads(decrypted_data)

        # Suppression seulement après succès du déchiffrement
        with get_db() as conn:
            c = conn.cursor()
            c.execute("DELETE FROM shares WHERE link_id = ?", (link_id,))
            conn.commit()

        return render_template("shared.html",
                               password=share_data["password"],
                               username=share_data["username"],
                               label=share_data["label"])

    except Exception as e:
        print(f"Erreur de déchiffrement: {e}")
        flash("Impossible de déchiffrer le lien partagé")
        abort(404)


if __name__ == "__main__":
    app.run(debug=True)