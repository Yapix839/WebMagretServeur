"""
run_all.py - lancer les deux applications (site principal + panel) sur la même adresse

Comportement :
- Importera l'instance Flask exportée par app.py si elle existe (variable `app` / `application` / `flask_app` / `APP`).
- Pour le panneau admin (panel_admin.py) fera de même ; si seule une factory `create_app()` existe, l'app sera instanciée.
- Monte une application WSGI combinée qui dispatch :
    * /adminpanel/* -> admin app
    * tout le reste  -> main app
- Lance un serveur de développement via werkzeug.run_simple (pratique pour dev).

Usage :
    python run_all.py

Environnements :
    HOST (default 0.0.0.0)
    PORT (default 5000)
    FLASK_DEBUG=1 => active use_reloader et use_debugger

Remarques :
- Ce script tente d'accommoder plusieurs conventions d'export dans vos modules.
- En production, préférez gunicorn / uWSGI / waitress et montez correctement les apps.
"""
import os
import importlib
from werkzeug.serving import run_simple
from typing import Callable

serveur = int(vars.get("serveur", "0"))
if serveur == 1:
    hote = "178.32.119.184"
    port = 52025
else:
    hote = "127.0.0.1"
    port = 5000

vars = read_variables()
HOST = os.environ.get("HOST", hote)
PORT = int(os.environ.get("PORT", port))
DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"

def load_wsgi_from_module(module_name: str) -> Callable:
    """
    Importe le module et renvoie un objet WSGI callable (Flask app ou WSGI app).
    Priorité :
      1) variable 'app' / 'application' / 'flask_app' / 'APP' si elle est une instance Flask
         ou une callable factory.
      2) module.create_app() factory
    Lève RuntimeError si aucune app n'est trouvée.
    """
    mod = importlib.import_module(module_name)

    # 1) préférer une variable app/application/flask_app/APP
    for name in ("app", "application", "flask_app", "APP"):
        if hasattr(mod, name):
            obj = getattr(mod, name)
            # Si c'est une instance Flask (possède wsgi_app), renvoyer directement
            if hasattr(obj, "wsgi_app"):
                return obj
            # Si c'est callable, tenter d'appeler (factory). Si l'appel échoue par TypeError,
            # on suppose que l'objet est callable mais non-factory (ex: already-callable WSGI)
            if callable(obj):
                try:
                    candidate = obj()
                    return candidate
                except TypeError:
                    return obj

    # 2) fallback : create_app() factory
    if hasattr(mod, "create_app"):
        factory = getattr(mod, "create_app")
        if callable(factory):
            try:
                app = factory()
                return app
            except TypeError:
                raise RuntimeError(f"create_app() dans '{module_name}' nécessite des arguments et n'a pas pu être appelé sans ceux-ci.")
    raise RuntimeError(
        f"Aucune application WSGI trouvée dans le module '{module_name}'. "
        "Exportez une variable 'app' (instance Flask) ou une factory create_app()."
    )

def create_combined_app():
    # Charger les deux modules : 'app' (site principal) et 'panel_admin' (panneau)
    main_app = load_wsgi_from_module("app")
    admin_app = load_wsgi_from_module("panel_admin")

    # Les objets retournés doivent être des WSGI callables (Flask instance ou wsgi app)
    if not callable(main_app):
        raise RuntimeError("L'application principale chargée n'est pas callable (WSGI).")
    if not callable(admin_app):
        raise RuntimeError("Le panneau admin chargé n'est pas callable (WSGI).")

    def application(environ, start_response):
        path = environ.get("PATH_INFO", "") or ""
        # Rediriger tout ce qui commence par /adminpanel vers admin_app
        if path.startswith("/adminpanel"):
            return admin_app(environ, start_response)
        return main_app(environ, start_response)

    return application

if __name__ == "__main__":
    app = create_combined_app()
    print(f"Serving combined apps on http://{HOST}:{PORT}  (admin panel at /adminpanel)")
    run_simple(HOST, PORT, app, use_reloader=DEBUG, use_debugger=DEBUG)