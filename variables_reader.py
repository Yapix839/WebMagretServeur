# Utilitaires pour data/variables.txt
# Copier ces fonctions dans app.py ou importer depuis un module séparé.

import os
import tempfile

BASE_DIR = os.path.dirname(__file__)
DATA_DIR = os.path.join(BASE_DIR, "data")
VARIABLES_FILE = os.path.join(DATA_DIR, "variables.txt")

# Liste des variables autorisées (ajustez selon vos besoins)
ALLOWED_VARIABLES = ("serveur", "csv_emplacement_def")

def ensure_data_dir():
    """Créer data/ si absent."""
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR, exist_ok=True)

def atomic_write(path, content):
    """Écriture atomique pour éviter la corruption de fichier."""
    dirn = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(dir=dirn)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
        os.replace(tmp_path, path)
    finally:
        # si une erreur survient et le tmp existe, essayer de le supprimer
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass

def read_variables():
    """
    Lire data/variables.txt (format key=value, une ligne par variable).
    Retourne un dict avec au moins toutes les ALLOWED_VARIABLES (valeurs '0' ou '1').
    Si le fichier n'existe pas, il est créé avec des valeurs par défaut '0'.
    """
    ensure_data_dir()
    # defaults
    defaults = {k: "0" for k in ALLOWED_VARIABLES}
    if not os.path.exists(VARIABLES_FILE):
        # créer fichier initial
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
                # normaliser à '0' ou '1' (tout autre -> '0')
                vars[k] = "1" if v in ("1", "true", "True", "yes", "on") else "0"
    # s'assurer que toutes les clés existent
    for k in ALLOWED_VARIABLES:
        vars.setdefault(k, defaults[k])
    return vars

def set_variable(key, value):
    """
    Mettre à jour une variable autorisée (value doit être '0' ou '1' ou équivalent).
    Écrit de façon atomique dans data/variables.txt et retourne (True,msg) ou (False,msg).
    """
    ensure_data_dir()
    key = key.strip()
    if key not in ALLOWED_VARIABLES:
        return False, "Variable non autorisée."
    v = str(value).strip()
    if v.lower() in ("1", "true", "yes", "on"):
        v_norm = "1"
    elif v.lower() in ("0", "false", "no", "off"):
        v_norm = "0"
    else:
        return False, "Valeur invalide (utiliser 0/1/on/off/true/false)."

    vars = read_variables()
    vars[key] = v_norm
    content = "\n".join(f"{k}={vars[k]}" for k in ALLOWED_VARIABLES) + "\n"
    try:
        atomic_write(VARIABLES_FILE, content)
    except Exception as e:
        return False, f"Erreur écriture fichier: {e}"
    return True, "Variable mise à jour."