#!/usr/bin/env python3
import os
import csv
from pathlib import Path
from functools import wraps
from flask import Flask, session, redirect, url_for, render_template, render_template_string, request, flash, jsonify
import pyotp
from file.variables_reader import read_variables

# ---------------- CONFIG ----------------
APP_SECRET_KEY = os.environ.get("APP_SECRET_KEY", "change_this_secret")
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
PAGES_DIR = BASE_DIR / "csv"
DATA_DIR.mkdir(exist_ok=True)

USERS_PATH = DATA_DIR / "users.txt"         # format: username:password:totp_secret[:optional_fourth_field]
UNLOCK_PATH = DATA_DIR / "unlock_secret.txt"  # clé base32 pour le débridage
VERSION_PATH = DATA_DIR / "version.txt"

app = Flask(__name__, static_folder=str(PAGES_DIR))
app.secret_key = APP_SECRET_KEY

vars = read_variables()
csv_emplacement_def = int(vars.get("csv_emplacement_def", "0"))
if csv_emplacement_def == 1:
    csv_emplacement = "all.csv"
else:
    csv_emplacement = "all_vrai.csv"

# ------------- UTIL ----------------
def load_users():
    """
    Charge data/users.txt en tolérant un 4ème champ optionnel.
    Format attendu : username:password:totp_secret[:optional]
    - Si totp_secret est vide ou 'none' (insensible à la casse) -> 2FA désactivée (totp == None).
    - Si totp_secret existe mais n'est pas une clé base32 décodable -> on le remplace automatiquement
      par 'none' (2FA désactivée) dans users.txt.
    Retourne dict users: { username: {"password": ..., "totp": <secret or None>} }
    """
    import base64
    import binascii

    users = {}
    if not USERS_PATH.exists():
        USERS_PATH.write_text("", encoding="utf-8")
        return users

    text = USERS_PATH.read_text(encoding="utf-8")
    lines = text.splitlines(keepends=True)  # préserve les fins de lignes pour réécriture fidèle
    out_lines = []
    changed = False

    for original_line in lines:
        line = original_line.rstrip("\r\n")
        stripped = line.strip()
        # conservez les lignes vides / commentaires telles quelles
        if not stripped or stripped.startswith("#"):
            out_lines.append(original_line)
            continue

        parts = line.split(":", 3)  # up to 4 parts
        if len(parts) < 3:
            # ligne malformée : conservez telle quelle pour ne pas perdre de données
            out_lines.append(original_line)
            continue

        username = parts[0].strip()
        password = parts[1].strip()
        totp_raw = parts[2].strip()
        extra = parts[3] if len(parts) == 4 else None

        # Normalisation : empty or "none" => disabled (None)
        if totp_raw == "" or totp_raw.lower() == "none":
            totp_val = None
            normalized_field = "none"
        else:
            # Essayer de décoder en base32 pour valider la clé
            try:
                # remove spaces and uppercase for base32 decode
                s = totp_raw.replace(" ", "").upper()
                # base64.b32decode lève binascii.Error si invalide
                _ = base64.b32decode(s, casefold=True)
                totp_val = totp_raw
                normalized_field = totp_raw
            except (binascii.Error, Exception):
                # invalide -> désactiver la 2FA et normaliser à "none"
                totp_val = None
                normalized_field = "none"

        users[username] = {"password": password, "totp": totp_val}

        # reconstruire la ligne normalisée ; on inclut l'éventuel 4ème champ tel quel
        if extra is not None:
            new_line = f"{username}:{password}:{normalized_field}:{extra}"
        else:
            new_line = f"{username}:{password}:{normalized_field}"

        # Comparer avec le champ original pour détecter changement
        if totp_raw != normalized_field:
            changed = True

        out_lines.append(new_line + ("\n" if original_line.endswith("\n") else ""))

    # Réécrire le fichier seulement si on a normalisé quelque chose
    if changed:
        USERS_PATH.write_text("".join(out_lines), encoding="utf-8")

    return users

def get_unlock_totp():
    if UNLOCK_PATH.exists():
        return pyotp.TOTP(UNLOCK_PATH.read_text().strip())
    return None

def get_version():
    try:
        with open(VERSION_PATH, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception:
        return "inconnue"

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
    version = get_version()
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
      <footer style="position:fixed; left:0; bottom:0; width:100%; background-color:#f0f0f0; color:gray; text-align:center; padding:8px 0; font-size:14px;">
        Vous utilisez la version v{{ version }}
      </footer>
    </body>
    </html>
    """, version=version)

@app.route("/2fa", methods=["GET","POST"])
def two_factor():
    if not session.get("pass_ok") or not session.get("username"):
        return redirect(url_for("login"))
    users = load_users()
    username = session["username"]
    profile = users.get(username)
    version = get_version()
    if not profile:
        flash("Profil introuvable.", "error")
        return redirect(url_for("login"))

    # Récupère le secret TOTP et considère que la 2FA est désactivée
    # si le champ est None, vide, ou la chaîne "none" (insensible à la casse).
    totp_secret = profile.get("totp")
    if totp_secret is None or str(totp_secret).strip().lower() in ("", "none"):
        # 2FA désactivée pour ce compte : on termine l'authentification
        session.clear()
        session["authed"] = True
        session["username"] = username
        session["just_authed"] = True
        return redirect(url_for("app_page"))

    error = None
    if request.method == "POST":
        code = request.form.get("code","").strip()
        try:
            totp = pyotp.TOTP(totp_secret)
            if totp.verify(code, valid_window=1):
                session.clear()
                session["authed"] = True
                session["username"] = username
                session["just_authed"] = True
                return redirect(url_for("app_page"))
            else:
                error = "Code TOTP invalide."
        except Exception:
            # protège contre un secret malformé
            error = "Erreur lors de la vérification du TOTP."

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
      <footer style="position:fixed; left:0; bottom:0; width:100%; background-color:#f0f0f0; color:gray; text-align:center; padding:8px 0; font-size:14px;">
        Vous utilisez la version v{{ version }}
      </footer>
    </body>
    </html>
    """, error=error, version=version)

# Serve la page principale (rendu dynamique pour le footer)
@app.route("/app")
@login_required
def app_page():
    version = get_version()
    return render_template("search_csv_web.html", version=version)

# ------------- ROUTE DE RECHERCHE -------------
@app.route("/search", methods=["POST"])
@login_required
def search():
    version = get_version()
    q_raw = (request.form.get("q") or "").strip()
    results = []
    csv_path = PAGES_DIR / csv_emplacement

    # --- VERIFICATION DU CODE DEVERROUILLAGE (unlock) ---
    try:
        unlock_totp = get_unlock_totp()
        if unlock_totp and q_raw:
            # si le code soumis correspond au TOTP d'unlock -> active la session debride
            if unlock_totp.verify(q_raw, valid_window=1):
                session["debride"] = True
                return jsonify({"status": "unlocked"})
    except Exception:
        app.logger.exception("Erreur lors de la vérification du TOTP d'unlock")

    # --- MODE DEBRIDE ---
    try:
        if request.form.get("debride", "").lower() in ("1", "true", "yes") and session.get("debride"):
            headers = ["Classe", "Nom Prénom", "ID", "Password"]
            if csv_path.exists():
                q_low = q_raw.lower()
                with open(csv_path, newline="", encoding="utf-8") as cf:
                    reader = csv.reader(cf)
                    # Skip header if present
                    _ = next(reader, None)
                    for row in reader:
                        if not row:
                            continue
                        try:
                            if any(q_low in (str(c) or "").lower() for c in row):
                                out = [
                                    row[0] if len(row) > 0 else "",
                                    row[1] if len(row) > 1 else "",
                                    row[4] if len(row) > 4 else "",
                                    row[5] if len(row) > 5 else "",
                                ]
                                results.append(out)
                        except Exception:
                            # protège contre lignes malformées
                            app.logger.exception("Erreur lors du traitement d'une ligne CSV (debride)")
            return jsonify({"status": "ok", "mode": "debride", "q": q_raw, "matches": len(results), "rows": results[:500], "headers": headers})
    except Exception:
        app.logger.exception("Erreur pendant la recherche en mode débridé")
        return jsonify({"status": "error", "error": "erreur lors de la recherche (debride)"}), 500

    # --- MODE NORMAL ---
    try:
        if csv_path.exists():
            with open(csv_path, newline="", encoding="utf-8") as cf:
                reader = csv.reader(cf)
                headers = next(reader, None)
                for row in reader:
                    if not row:
                        continue
                    # recherche exact sur la colonne id (index 4)
                    if len(row) > 4 and row[4] == q_raw:
                        out = [
                            row[0] if len(row) > 0 else "",
                            row[1] if len(row) > 1 else "",
                            row[4] if len(row) > 4 else "",
                            row[5] if len(row) > 5 else "",
                        ]
                        results.append(out)
                        continue
                    # recherche partielle sur toute la ligne (sensible à la casse)
                    try:
                        found = any(q_raw in (str(cell) or "") for cell in row)
                    except Exception:
                        found = False
                        app.logger.exception("Erreur lors de la comparaison d'une cellule CSV (normal)")
                    if found:
                        out = [
                            row[0] if len(row) > 0 else "",
                            row[1] if len(row) > 1 else "",
                            row[4] if len(row) > 4 else "",
                            row[5] if len(row) > 5 else "",
                        ]
                        results.append(out)
    except Exception:
        app.logger.exception("Erreur pendant la recherche en mode normal")
        return jsonify({"status": "error", "error": "erreur lors de la recherche (normal)"}), 500

    # Toujours retourner un JSON valide
    return jsonify({"status": "ok", "q": q_raw, "matches": len(results), "rows": results[:500]})
@app.route("/status")
@login_required
def status():
    return jsonify({"username": session.get("username"), "debride": bool(session.get("debride"))})

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

serveur = int(vars.get("serveur", "0"))
if serveur == 1:
    hote = "178.32.119.184"
    port = 52025
else:
    hote = "127.0.0.1"
    port = 5000

if __name__ == "__main__":
    if not UNLOCK_PATH.exists():
        UNLOCK_PATH.write_text("NB2WY3DPEHPK3PXPJBSWY3DP", encoding="utf-8")
    print(f"Serveur: http://{hote}:{port}/login")
    app.run(host=hote, port=port, debug=True)