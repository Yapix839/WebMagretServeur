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

# ------------- MIDDLEWARE : déconnexion au refresh -------------
@app.before_request
def auto_logout_on_refresh():
    # On autorise POST, fichiers statiques et logout sans vider
    if request.method != "GET":
        return
    if request.endpoint in ("static", "logout"):
        return
    # Autoriser la GET immédiatement suivant auth
    if session.get("just_authed"):
        session.pop("just_authed", None)
        return
    if session.get("authed"):
        session.clear()
        return redirect(url_for("login"))

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
        # support : mot de passe 'OTP' (rare) treated previously omitted
        flash("Mot de passe incorrect.", "error")
    return render_template_string("""
    <!doctype html><html lang="fr"><head><meta charset="utf-8"><title>Login</title>
    <style>body{font-family:Arial;padding:20px} .card{max-width:420px;margin:30px auto;padding:16px;border-radius:8px;background:#fff;box-shadow:0 6px 18px rgba(0,0,0,0.06)}</style>
    </head><body>
    <div class="card">
      <h2>Connexion</h2>
      {% for cat,msg in get_flashed_messages(with_categories=true) %}
        <p style="color:{{ 'green' if cat=='success' else 'red' }}">{{msg}}</p>
      {% endfor %}
      <form method="post">
        <input name="username" placeholder="Nom d'utilisateur" autofocus style="width:100%;padding:10px;margin:6px 0"><br>
        <input name="password" type="password" placeholder="Mot de passe" style="width:100%;padding:10px;margin:6px 0"><br>
        <button type="submit" style="padding:10px 14px">Se connecter</button>
      </form>
    </div>
    </body></html>
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
    <!doctype html><html lang="fr"><head><meta charset="utf-8"><title>2FA</title></head><body>
    <div style="max-width:420px;margin:40px auto;padding:16px;background:#fff;border-radius:8px">
      <h2>Code TOTP</h2>
      {% if error %}<p style="color:red">{{error}}</p>{% endif %}
      <form method="post">
        <input name="code" placeholder="Code à 6 chiffres" autofocus style="width:100%;padding:10px"><br>
        <button type="submit">Valider</button>
      </form>
    </div>
    </body></html>
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
    """
    - Si q est le code OTP de débridage -> active session['debride'] et renvoie status 'unlocked' + message
    - Sinon :
       * Si on trouve un ID EXACT (5e colonne, index 4) -> renvoyer uniquement les colonnes demandées :
         - col 1 (index 0) = classe
         - col 2 (index 1) = nom prenom
         - col 5 (index 4) = id
         - col 6 (index 5) = password
       * Sinon -> recherche (par sous-chaîne, case-insensitive) sur toutes les colonnes ET retourne les mêmes colonnes sélectionnées
    - Si la requête contient 'debride'==true et que session['debride'] est True -> recherche insensible à la casse sur TOUTES les colonnes et renvoie LIGNE COMPLÈTE.
    """
    q_raw = request.form.get("q", "").strip()
    if q_raw == "":
        return jsonify({"status":"ok","q":"", "matches":0, "rows":[]})

    # 1) Test OTP débridage (exact match — on accepte espaces enlevés)
    try:
        unlock = get_unlock_totp()
        if unlock and unlock.verify(q_raw.replace(" ", ""), valid_window=1):
            session["debride"] = True
            return jsonify({"status":"unlocked", "message":"mode debridé activé"})
    except Exception:
        # ne pas bloquer la recherche si unlock key corrompue
        pass

    csv_path = PAGES_DIR / "all.csv"
    results = []

    # Mode debridé : recherche insensible à la casse sur toutes colonnes -> renvoie lignes complètes
    if request.form.get("debride", "").lower() in ("1","true","yes") and session.get("debride"):
        if csv_path.exists():
            q_low = q_raw.lower()
            with open(csv_path, newline='', encoding='utf-8') as cf:
                reader = csv.reader(cf)
                headers = next(reader, None)
                for row in reader:
                    if any(q_low in (str(c) or "").lower() for c in row):
                        results.append(row)
        return jsonify({"status":"ok","mode":"debride","q":q_raw,"matches":len(results),"rows":results[:500]})

    # Recherche normale :
    #  - priorité ID exact (5e colonne index 4) - comparaison SENSIBLE à la casse
    #  - sinon recherche insensible à la casse sur toutes les colonnes but returns selected columns
    if csv_path.exists():
        with open(csv_path, newline='', encoding='utf-8') as cf:
            reader = csv.reader(cf)
            headers = next(reader, None)
            q_low = q_raw.lower()
            for row in reader:
                if not row:
                    continue
                # ID exact check (5th column -> index 4) - CASE SENSITIVE exact equality
                if len(row) > 4 and row[4] == q_raw:
                    # pick columns: index 0,1,4,5
                    out = [ row[0] if len(row)>0 else "",
                            row[1] if len(row)>1 else "",
                            row[4] if len(row)>4 else "",
                            row[5] if len(row)>5 else "" ]
                    results.append(out)
                    continue
                # else search case-insensitive in any column, return selected columns
                found = False
                for cell in row:
                    if q_low in (str(cell) or "").lower():
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

# ------------- MAIN -------------
if __name__ == "__main__":
    # (optionnel) créer un unlock_secret par défaut si absent (tu peux remplacer)
    if not UNLOCK_PATH.exists():
        UNLOCK_PATH.write_text("NB2WY3DPEHPK3PXPJBSWY3DP", encoding="utf-8")
    print("Serveur: http://127.0.0.1:5000/login")
    app.run(host="127.0.0.1", port=5000, debug=True)
