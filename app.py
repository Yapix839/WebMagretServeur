#!/usr/bin/env python3
import os
from pathlib import Path
from functools import wraps
from flask import Flask, session, redirect, url_for, render_template_string, request, flash, send_from_directory, jsonify
import pyotp
import csv

# ---------------- CONFIG ----------------
APP_SECRET_KEY = os.environ.get("APP_SECRET_KEY", "change_this_secret")
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
PAGES_DIR = BASE_DIR / "Pages"
DATA_DIR.mkdir(exist_ok=True)

USERS_PATH = DATA_DIR / "users.txt"         # format: username:password:totp_secret
UNLOCK_PATH = DATA_DIR / "unlock_secret.txt"  # clé base32 pour le débridage

app = Flask(__name__, static_folder=str(PAGES_DIR))
app.secret_key = APP_SECRET_KEY

# ------------- UTIL ----------------
def load_users():
    users = {}
    if not USERS_PATH.exists():
        USERS_PATH.write_text("", encoding="utf-8")
        return users
    for line in USERS_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":", 2)
        if len(parts) >= 3:
            users[parts[0]] = {"password": parts[1], "totp": parts[2]}
    return users

def get_unlock_totp():
    if UNLOCK_PATH.exists():
        return pyotp.TOTP(UNLOCK_PATH.read_text().strip())
    return None

# ------------- DÉCORATEUR -------------
def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if session.get("authed"):
            return fn(*args, **kwargs)
        return redirect(url_for("login"))
    return wrapped

# ------------- ROUTES D'AUTH -------------
@app.route("/login", methods=["GET","POST"])
def login():
    users = load_users()
    if request.method == "POST":
        u = request.form.get("username","").strip()
        p = request.form.get("password","").strip()
        profile = users.get(u)
        if not profile:
            flash("Utilisateur inconnu.", "error")
            return redirect(url_for("login"))
        if p == profile["password"]:
            session.clear()
            session["username"] = u
            session["pass_ok"] = True
            return redirect(url_for("two_factor"))
        flash("Mot de passe incorrect.", "error")
    return render_template_string("""
    <!doctype html>
    <html lang="fr">
    <head>
      <meta charset="utf-8">
      <title>Connexion</title>
      <style>
      body{font-family:Arial,Helvetica,sans-serif;background:#f3f4f6;margin:0;padding:20px}
      .card{max-width:400px;margin:40px auto;background:white;padding:24px 24px 20px 24px;border-radius:10px;box-shadow:0 8px 30px rgba(0,0,0,0.06)}
      input{padding:10px;border-radius:8px;border:1px solid #ccc;width:70%;margin-bottom:10px}
      button{padding:10px 14px;border-radius:8px;border:none;background:#ff7a00;color:white;cursor:pointer;width:100%}
      .small{font-size:0.9em;color:#555}
      </style>
    </head>
    <body>
      <div class="card">
        <h2>Connexion</h2>
        {% for cat,msg in get_flashed_messages(with_categories=true) %}
          <p style="color:{{ 'green' if cat=='success' else 'red' }}">{{msg}}</p>
        {% endfor %}
        <form method="post" style="display: flex; flex-direction: column; align-items: center;">
          <input name="username" placeholder="Nom d'utilisateur" autofocus required>
          <input name="password" type="password" placeholder="Mot de passe" required>
          <button type="submit">Se connecter</button>
        </form>
      </div>
    </body>
    </html>
    """)

@app.route("/2fa", methods=["GET","POST"])
def two_factor():
    if not session.get("pass_ok") or not session.get("username"):
        return redirect(url_for("login"))
    users = load_users()
    username = session["username"]
    profile = users.get(username)
    if not profile:
        flash("Profil introuvable.", "error")
        return redirect(url_for("login"))
    error = None
    if request.method == "POST":
        code = request.form.get("code","").strip()
        totp_secret = profile.get("totp")
        if not totp_secret:
            error = "Aucun secret TOTP configuré pour ce compte."
        else:
            totp = pyotp.TOTP(totp_secret)
            if totp.verify(code, valid_window=1):
                session.clear()
                session["authed"] = True
                session["username"] = username
                session["just_authed"] = True
                return redirect(url_for("app_page"))
            else:
                error = "Code TOTP invalide."
    return render_template_string("""
    <!doctype html>
    <html lang="fr">
    <head>
      <meta charset="utf-8">
      <title>2FA</title>
      <style>
      body{font-family:Arial,Helvetica,sans-serif;background:#f3f4f6;margin:0;padding:20px}
      .card{max-width:400px;margin:40px auto;background:white;padding:24px 24px 20px 24px;border-radius:10px;box-shadow:0 8px 30px rgba(0,0,0,0.06)}
      input{padding:10px;border-radius:8px;border:1px solid #ccc;width:70%;margin-bottom:10px}
      button{padding:10px 14px;border-radius:8px;border:none;background:#ff7a00;color:white;cursor:pointer;width:100%}
      .small{font-size:0.9em;color:#555}
      </style>
    </head>
    <body>
      <div class="card">
        <h2>Code TOTP</h2>
        {% if error %}<p style="color:red">{{error}}</p>{% endif %}
        <form method="post" style="display: flex; flex-direction: column; align-items: center;">
          <input name="code" placeholder="Code à 6 chiffres" autofocus required>
          <button type="submit">Valider</button>
        </form>
      </div>
    </body>
    </html>
    """, error=error)

# Serve la page principale (fichier statique)
@app.route("/app")
@login_required
def app_page():
    return send_from_directory(str(PAGES_DIR), "search_csv_web.html")

# ------------- ROUTE DE RECHERCHE -------------
@app.route("/search", methods=["POST"])
@login_required
def search():
    q_raw = request.form.get("q", "").strip()
    if q_raw == "":
        return jsonify({"status":"ok","q":"", "matches":0, "rows":[]})

    try:
        unlock = get_unlock_totp()
        if unlock and unlock.verify(q_raw.replace(" ", ""), valid_window=1):
            session["debride"] = True
            return jsonify({"status":"unlocked", "message":"mode debridé activé"})
    except Exception:
        pass

    csv_path = PAGES_DIR / "all.csv"
    results = []

    # --- MODE DEBRIDE ---
    if request.form.get("debride", "").lower() in ("1","true","yes") and session.get("debride"):
        headers = ["Classe", "Nom Prénom", "ID", "Password"]
        if csv_path.exists():
            q_low = q_raw.lower()
            with open(csv_path, newline='', encoding='utf-8') as cf:
                reader = csv.reader(cf)
                _ = next(reader, None)  # skip header in file
                for row in reader:
                    if any(q_low in (str(c) or "").lower() for c in row):
                        out = [row[0] if len(row)>0 else "",
                               row[1] if len(row)>1 else "",
                               row[4] if len(row)>4 else "",
                               row[5] if len(row)>5 else ""]
                        results.append(out)
        return jsonify({"status":"ok","mode":"debride","q":q_raw,"matches":len(results),"rows":results[:500], "headers": headers})

    # --- MODE NORMAL ---
    if csv_path.exists():
        with open(csv_path, newline='', encoding='utf-8') as cf:
            reader = csv.reader(cf)
            headers = next(reader, None)
            for row in reader:
                if not row:
                    continue
                # ID exact check (5th column -> index 4) - CASE SENSITIVE exact equality
                if len(row) > 4 and row[4] == q_raw:
                    out = [ row[0] if len(row)>0 else "",
                            row[1] if len(row)>1 else "",
                            row[4] if len(row)>4 else "",
                            row[5] if len(row)>5 else "" ]
                    results.append(out)
                    continue
                # else search CASE SENSITIVE in any column, return selected columns
                found = False
                for cell in row:
                    if q_raw in (str(cell) or ""):
                        found = True
                        break
                if found:
                    out = [ row[0] if len(row)>0 else "",
                            row[1] if len(row)>1 else "",
                            row[4] if len(row)>4 else "",
                            row[5] if len(row)>5 else "" ]
                    results.append(out)

    return jsonify({"status":"ok","q":q_raw,"matches":len(results),"rows":results[:500]})

@app.route("/status")
@login_required
def status():
    return jsonify({"username": session.get("username"), "debride": bool(session.get("debride"))})

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    if not UNLOCK_PATH.exists():
        UNLOCK_PATH.write_text("NB2WY3DPEHPK3PXPJBSWY3DP", encoding="utf-8")
    print("Serveur: http://178.32.119.184:5000/login")
    app.run(host="178.32.119.184", port=5000, debug=True)