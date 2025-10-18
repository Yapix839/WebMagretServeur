import os
import tempfile
from flask import (
    Flask, request, redirect, url_for, session, flash,
    render_template_string
)
from file.variables_reader import read_variables
vars = read_variables()

try:
    import pyotp
except Exception:
    pyotp = None

BASE_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(BASE_DIR, "data")
USERS_FILE = os.path.join(DATA_DIR, "users.txt")
VARIABLES_FILE = os.path.join(DATA_DIR, "variables.txt")

ALLOWED_VARIABLES = ("serveur", "csv_réel")


# ---------- fichiers & atomic write ----------
def ensure_data_dir():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR, exist_ok=True)


def atomic_write(path, content):
    dirn = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(dir=dirn)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp_path, path)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass


# ---------- users handling ----------
def parse_user_line(line):
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    parts = s.split(":")
    # normalize to 4 fields
    while len(parts) < 4:
        parts.append("")
    uid = parts[0].strip()
    pwd = parts[1]
    totp = parts[2]
    mode = parts[3].strip().lower() or "user"
    if mode not in ("admin", "user"):
        mode = "user"
    if not uid:
        return None
    return {"id": uid, "pwd": pwd, "totp": totp, "mode": mode}


def read_users():
    ensure_data_dir()
    if not os.path.exists(USERS_FILE):
        atomic_write(USERS_FILE, "")
        return []
    users = []
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            u = parse_user_line(line)
            if u:
                users.append(u)
    return users


def write_users(users):
    lines = []
    for u in users:
        lines.append(f"{u['id']}:{u.get('pwd','')}:{u.get('totp','')}:{u.get('mode','user')}")
    atomic_write(USERS_FILE, "\n".join(lines) + ("\n" if lines else ""))


def find_user(uid):
    for u in read_users():
        if u["id"] == uid:
            return u
    return None


def add_user(uid, pwd, totp="", mode="user"):
    uid = uid.strip()
    if not uid:
        return False, "Identifiant vide."
    if mode not in ("admin", "user"):
        return False, "Mode invalide."
    users = read_users()
    if any(u["id"] == uid for u in users):
        return False, "Utilisateur déjà existant."
    users.append({"id": uid, "pwd": pwd, "totp": totp, "mode": mode})
    write_users(users)
    return True, "Utilisateur ajouté."


def remove_user(uid):
    users = read_users()
    new_users = [u for u in users if u["id"] != uid]
    if len(new_users) == len(users):
        return False, "Utilisateur introuvable."
    write_users(new_users)
    return True, "Utilisateur supprimé."


def set_role(uid, mode):
    if mode not in ("admin", "user"):
        return False, "Mode invalide."
    users = read_users()
    found = False
    for u in users:
        if u["id"] == uid:
            u["mode"] = mode
            found = True
            break
    if not found:
        return False, "Utilisateur introuvable."
    write_users(users)
    return True, "Rôle mis à jour."


def verify_password(uid, pwd):
    u = find_user(uid)
    if not u:
        return False
    return u.get("pwd", "") == pwd


def verify_totp(uid, token):
    if pyotp is None:
        return False
    u = find_user(uid)
    if not u:
        return False
    secret = (u.get("totp") or "").strip()
    if not secret:
        return False
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)
    except Exception:
        return False


def is_admin(uid):
    u = find_user(uid)
    return bool(u and u.get("mode") == "admin")


# ---------- variables handling (copié du app principal) ----------
def read_variables():
    ensure_data_dir()
    defaults = {k: "0" for k in ALLOWED_VARIABLES}
    if not os.path.exists(VARIABLES_FILE):
        content = "\n".join(f"{k}={v}" for k, v in defaults.items()) + "\n"
        atomic_write(VARIABLES_FILE, content)
        return defaults.copy()
    vars = {}
    with open(VARIABLES_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip()
            if k in ALLOWED_VARIABLES:
                vars[k] = "1" if v.lower() in ("1", "true", "yes", "on") else "0"
    for k in ALLOWED_VARIABLES:
        vars.setdefault(k, defaults[k])
    return vars


def set_variable(key, value):
    ensure_data_dir()
    key = key.strip()
    if key not in ALLOWED_VARIABLES:
        return False, "Variable non autorisée."
    v = str(value).strip().lower()
    if v in ("1", "true", "yes", "on"):
        v_norm = "1"
    elif v in ("0", "false", "no", "off"):
        v_norm = "0"
    else:
        return False, "Valeur invalide."
    vars = read_variables()
    vars[key] = v_norm
    content = "\n".join(f"{k}={vars[k]}" for k in ALLOWED_VARIABLES) + "\n"
    try:
        atomic_write(VARIABLES_FILE, content)
    except Exception as e:
        return False, f"Erreur écriture fichier: {e}"
    return True, "Variable mise à jour."


# ---------- Flask app ----------
def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", None) or os.urandom(24)

    # Votre style copié directement dans l'en-tête, adapté pour centrer les éléments de connexion
    inline_style = """
    body{font-family:Arial,Helvetica,sans-serif;background:#f3f4f6;margin:0;padding:20px}
    .card{max-width:600px;margin:24px auto;background:white;padding:20px;border-radius:10px;box-shadow:0 8px 30px rgba(0,0,0,0.06)}
    .card-center { text-align: center; }
    .title { margin: 0 0 16px 0; font-size: 1.4rem; text-align:center; }
    .form-container { text-align: center; }
    .form { display:inline-block; width:100%; max-width:420px; text-align:left; }
    .form-row { margin-bottom: 12px; }
    .input { padding:10px; border-radius:8px; border:1px solid #ccc; width:100%; box-sizing: border-box; }
    .btn { padding:10px 14px; border-radius:8px; border:none; background:#ff7a00; color:white; cursor:pointer; display:inline-block; }
    .login-button-row { text-align:center; }
    .small{font-size:0.9em;color:#555}
    .table{width:100%;border-collapse:collapse;margin-top:12px}
    .table th,.table td{padding:8px;border-bottom:1px solid #eee;text-align:left}
    .badge{display:inline-block;padding:6px 10px;border-radius:8px;background:#eef}
    #debrideForm { display: flex; align-items: center; }
    #debrideForm button { margin-left: 12px; }
    .help { color:#666; font-size:0.95em; text-align:center; }
    """

    base_head = f"""
    <!doctype html>
    <html lang="fr">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <title>Admin Panel</title>
      <style>{inline_style}</style>
    </head>
    <body>
    <div class="card card-center">
    """

    base_footer = """
    </div>
    </body>
    </html>
    """

    # Login template: placeholders inside inputs, centered title and form
    login_tpl = base_head + """
    <h1 class="title">Admin Panel - Connexion</h1>
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <div class="small">
          {% for m in messages %}
            <div>{{ m }}</div>
          {% endfor %}
        </div>
      {% endif %}
    {% endwith %}
    <div class="form-container">
      <form method="post" action="{{ url_for('admin_login') }}" class="form" autocomplete="off">
        <div class="form-row">
          <input name="id" class="input" placeholder="Identifiant" autofocus>
        </div>
        <div class="form-row">
          <input name="pwd" type="password" class="input" placeholder="Mot de passe">
        </div>
        <div class="form-row login-button-row">
          <button class="btn" type="submit">Suivant (2FA)</button>
        </div>
      </form>
    </div>
    """ + base_footer

    # Two-factor template: show "Connecté en tant que <user>"
    twofa_tpl = base_head + """
    <h1 class="title">Admin Panel - 2FA</h1>
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <div class="small">
          {% for m in messages %}
            <div>{{ m }}</div>
          {% endfor %}
        </div>
      {% endif %}
    {% endwith %}
    <p class="small">Connecté en tant que <strong>{{ auth_user }}</strong></p>
    <div class="form-container">
      <form method="post" action="{{ url_for('admin_2fa') }}" class="form" autocomplete="off">
        <div class="form-row">
          <input name="token" class="input" placeholder="TOTP">
        </div>
        <div class="form-row login-button-row">
          <button class="btn" type="submit">Valider 2FA</button>
        </div>
      </form>
    </div>
    """ + base_footer

    # Template principal du panel : show "Connecté en tant que <user> — Déconnexion"
    panel_tpl = base_head + """
    <h1 class="title">Admin Panel</h1>
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        <div class="small">
          {% for m in messages %}
            <div>{{ m }}</div>
          {% endfor %}
        </div>
      {% endif %}
    {% endwith %}
    <p class="small">Connecté en tant que <strong>{{ admin_user }}</strong> — <a href="{{ url_for('admin_logout') }}">Déconnexion</a></p>

    <h2 class="small">Variables :</h2>
    {% for k in ALLOWED_VARIABLES %}
      {% set v = variables.get(k, '0') %}
      <div style="margin-bottom:8px;">
        <strong>{{ k }}</strong> : <span class="badge">{{ 'ON' if v=='1' else 'OFF' }}</span>
        <form method="post" action="{{ url_for('admin_toggle_variable') }}" style="display:inline;margin-left:12px;">
          <input type="hidden" name="var" value="{{ k }}">
          <input type="hidden" name="value" value="{{ '0' if v=='1' else '1' }}">
          <button class="btn" type="submit">{{ 'Turn OFF' if v=='1' else 'Turn ON' }}</button>
        </form>
      </div>
    {% endfor %}

    <h2 class="small">Utilisateurs :</h2>
    <div>
      <h3 class="small">Ajouter</h3>
      <form method="post" action="{{ url_for('admin_add_user') }}">
        <div class="form-row"><input name="id" class="input" placeholder="id" required></div>
        <div class="form-row"><input name="pwd" class="input" placeholder="pwd" required></div>
        <div class="form-row"><input name="totp" class="input" placeholder="totp (base32)"></div>
        <div class="form-row">
          <label>mode:
            <select name="mode" class="input" style="width:auto; display:inline-block; padding:8px; margin-left:8px;">
              <option value="user">user</option><option value="admin">admin</option>
            </select>
          </label>
        </div>
        <div class="form-row"><button class="btn" type="submit">Ajouter</button></div>
      </form>
    </div>

    <h3 class="small">Ajouter :</h3>
    <table class="table" role="table" aria-label="users">
      <thead><tr><th>id</th><th>mode</th><th>actions</th></tr></thead>
      <tbody>
      {% for u in users %}
        <tr>
          <td>{{ u.id }}</td>
          <td>{{ u.mode }}</td>
          <td>
            <form style="display:inline" method="post" action="{{ url_for('admin_set_role') }}">
              <input type="hidden" name="id" value="{{u.id}}">
              {% if u.mode == 'admin' %}
                <input type="hidden" name="mode" value="user">
                <button class="btn" type="submit">Retirer admin</button>
              {% else %}
                <input type="hidden" name="mode" value="admin">
                <button class="btn" type="submit">Donner admin</button>
              {% endif %}
            </form>
            <form style="display:inline" method="post" action="{{ url_for('admin_remove_user') }}">
              <input type="hidden" name="id" value="{{ u.id }}">
              <button class="btn" type="submit" onclick="return confirm('Supprimer {{u.id}} ?')">Supprimer</button>
            </form>
          </td>
        </tr>
      {% endfor %}
      </tbody>
    </table>
    """ + base_footer

    @app.route("/adminpanel/login", methods=["GET", "POST"])
    def admin_login():
        if request.method == "POST":
            uid = request.form.get("id", "").strip()
            pwd = request.form.get("pwd", "")
            if not uid or not pwd:
                flash("Identifiant et mot de passe requis.")
                return redirect(url_for("admin_login"))
            if not verify_password(uid, pwd):
                flash("Identifiants invalides.")
                return redirect(url_for("admin_login"))
            # stage1 passed: store auth_user and go to 2FA
            session["auth_user"] = uid
            return redirect(url_for("admin_2fa"))
        return render_template_string(login_tpl)

    @app.route("/adminpanel/2FA", methods=["GET", "POST"])
    def admin_2fa():
        auth_user = session.get("auth_user")
        if not auth_user:
            flash("Commencez par vous identifier.")
            return redirect(url_for("admin_login"))
        if request.method == "POST":
            token = request.form.get("token", "").strip()
            if not token:
                flash("Code TOTP requis.")
                return redirect(url_for("admin_2fa"))
            if pyotp is None:
                flash("pyotp non installé : impossible de vérifier le code TOTP.")
                return redirect(url_for("admin_login"))
            if not verify_totp(auth_user, token):
                flash("Code TOTP invalide.")
                return redirect(url_for("admin_2fa"))
            # TOTP ok -> check if admin
            if not is_admin(auth_user):
                flash("Accès refusé : utilisateur non-admin.")
                session.pop("auth_user", None)
                return redirect(url_for("admin_login"))
            # full auth: set admin_user in session (no flash here per your removal)
            session.pop("auth_user", None)
            session["admin_user"] = auth_user
            return redirect(url_for("admin_panel"))
        return render_template_string(twofa_tpl, auth_user=auth_user)

    @app.route("/adminpanel/logout")
    def admin_logout():
        session.pop("admin_user", None)
        flash("Déconnecté.")
        return redirect(url_for("admin_login"))

    @app.route("/adminpanel/panel", methods=["GET"])
    def admin_panel():
        if "admin_user" not in session:
            flash("Veuillez vous connecter.")
            return redirect(url_for("admin_login"))
        if not is_admin(session.get("admin_user")):
            flash("Accès refusé : non-admin.")
            return redirect(url_for("admin_login"))
        users = read_users()
        variables = read_variables()
        # Passer ALLOWED_VARIABLES au template pour forcer l'ordre et garantir les boutons correspondent
        return render_template_string(panel_tpl, admin_user=session.get("admin_user"), users=users, variables=variables, ALLOWED_VARIABLES=ALLOWED_VARIABLES)

    @app.route("/adminpanel/add_user", methods=["POST"])
    def admin_add_user():
        if "admin_user" not in session or not is_admin(session.get("admin_user")):
            flash("Accès refusé.")
            return redirect(url_for("admin_login"))
        uid = request.form.get("id", "").strip()
        pwd = request.form.get("pwd", "")
        totp = request.form.get("totp", "").strip()
        mode = request.form.get("mode", "user")
        ok, msg = add_user(uid, pwd, totp, mode)
        flash(msg)
        return redirect(url_for("admin_panel"))

    @app.route("/adminpanel/set_role", methods=["POST"])
    def admin_set_role():
        if "admin_user" not in session or not is_admin(session.get("admin_user")):
            flash("Accès refusé.")
            return redirect(url_for("admin_login"))
        uid = request.form.get("id", "").strip()
        mode = request.form.get("mode", "user")
        ok, msg = set_role(uid, mode)
        flash(msg)
        return redirect(url_for("admin_panel"))

    @app.route("/adminpanel/remove_user", methods=["POST"])
    def admin_remove_user():
        if "admin_user" not in session or not is_admin(session.get("admin_user")):
            flash("Accès refusé.")
            return redirect(url_for("admin_login"))
        uid = request.form.get("id", "").strip()
        ok, msg = remove_user(uid)
        flash(msg)
        return redirect(url_for("admin_panel"))

    @app.route("/adminpanel/toggle_variable", methods=["POST"])
    def admin_toggle_variable():
        if "admin_user" not in session or not is_admin(session.get("admin_user")):
            flash("Accès refusé.")
            return redirect(url_for("admin_login"))
        var = request.form.get("var")
        value = request.form.get("value")
        ok, msg = set_variable(var, value)
        flash(msg)
        return redirect(url_for("admin_panel"))

    return app

app = create_app()

serveur = int(vars.get("serveur", "0"))
if serveur == 1:
    hote = "178.32.119.184"
    port = 52025
else:
    hote = "127.0.0.1"
    port = 5000

if __name__ == "__main__":
    print(f"Serveur: http://{hote}:{port}/adminpanel/login")
    app.run(host=hote, port=port, debug=True)
