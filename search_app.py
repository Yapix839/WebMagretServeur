#!/usr/bin/env python3
# search_app.py
# Petit utilitaire pour chercher dans CSV de classes.
# Placez un dossier "CSV" (ou modifiez csv_folder) à côté de l'exécutable / du script.

import csv
import sys
from pathlib import Path

# Si l'app est empaquetée par PyInstaller, les fichiers bundlés (s'il y en a) sont extraits dans _MEIPASS
def get_base_path():
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path.cwd()

BASE = get_base_path()
csv_folder = BASE / "CSV"  # dossier contenant les fichiers <classe>.csv

def charger_classe(classe_num):
    """Charge le fichier CSV d'une classe donnée"""
    file_path = csv_folder / f"{classe_num}.csv"
    if not file_path.exists():
        print(f"❌ Fichier {file_path} introuvable.")
        return []
    with open(file_path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        return list(reader)

def rechercher(classe_num, mot_cle):
    """Recherche un élève, utilisateur ou mot de passe dans le CSV"""
    data = charger_classe(classe_num)
    if not data:
        return
    print(f"\n🔎 Résultats pour '{mot_cle}' dans la classe {classe_num}:")
    found = 0
    for row in data:
        if any(mot_cle.lower() in str(v).lower() for v in row.values()):
            # n'affiche que les colonnes non vides
            parts = [f"{k}: {v}" for k, v in row.items() if str(v).strip()]
            print(" - " + " | ".join(parts))
            found += 1
    if found == 0:
        print(" ❗ Aucun résultat.")
    print("✅ Recherche terminée.\n")

def main():
    print("Bienvenue dans la base de données Berthelot")
    # boucle principale
    try:
        while True:
            search = input("Chercher (ou 'quit' pour quitter) : ").strip()
            if not search:
                continue
            if search.lower() in ("quit", "exit", "q"):
                print("Au revoir 👋")
                break
            # on cherche dans le fichier all.csv si présent, sinon on cherche dans "all" classe
            # (vous pouvez appeler par numéro de classe: ex '55' => charge 55.csv)
            # si vous voulez toujours rechercher toutes les classes, appelez rechercher("all", search)
            # Par défaut on cherchera dans 'all' (si all.csv existe) sinon demande de classe
            all_path = csv_folder / "all.csv"
            if all_path.exists():
                # charger all.csv comme classe "all"
                data = charger_classe("all")
                if data:
                    # on simule la recherche sur ce dataset
                    print(f"\n🔎 Recherche dans all.csv pour '{search}':")
                    found = 0
                    for row in data:
                        if any(search.lower() in str(v).lower() for v in row.values()):
                            parts = [f"{k}: {v}" for k, v in row.items() if str(v).strip()]
                            print(" - " + " | ".join(parts))
                            found += 1
                    if found == 0:
                        print(" ❗ Aucun résultat.")
                    print("✅ Recherche terminée.\n")
                    continue
            # sinon demander classe
            classe_num = input("Indiquez la classe (ou 'all' si vous avez all.csv) : ").strip() or "all"
            rechercher(classe_num, search)
    except KeyboardInterrupt:
        print("\nInterrompu. Au revoir.")

if __name__ == "__main__":
    main()
