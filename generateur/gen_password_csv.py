import csv
import random
import string

fichier_csv = "./pages/all.csv"

def generer_mdp(existants):
    caracteres = string.ascii_uppercase + string.digits
    while True:
        mdp = ''.join(random.choice(caracteres) for _ in range(6))
        if mdp not in existants:
            existants.add(mdp)
            return mdp

# Lire le CSV
with open(fichier_csv, newline='', encoding='utf-8') as csvfile:
    reader = list(csv.reader(csvfile))

# Ensemble pour garder les mots de passe uniques
mdp_utilises = set()

# Remplacer la 6ème colonne en sautant la première ligne
for row in reader[1:]:
    if len(row) >= 6:
        row[5] = generer_mdp(mdp_utilises)

# Écrire directement dans le même fichier
with open(fichier_csv, 'w', newline='', encoding='utf-8') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerows(reader)

print("Un nouvelle ensemble de mot de passe a été generé")
