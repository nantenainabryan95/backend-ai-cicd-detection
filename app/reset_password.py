# -----------------------------------------------------------------------------
# Petit utilitaire pour (re)définir le mot de passe d'un utilisateur existant,
# en le hachant correctement. Utile pour les comptes créés avant l'ajout de
# l'authentification, dont le mot de passe était stocké en clair.
#
# Usage (depuis la racine du projet, venv activé) :
#     python -m app.reset_password analyste1 MonNouveauMotDePasse
# -----------------------------------------------------------------------------

import sys

from app.database import SessionLocal
from app import models
from app.auth import hash_password


def main():
    if len(sys.argv) != 3:
        print("Usage : python -m app.reset_password <username> <nouveau_mot_de_passe>")
        sys.exit(1)

    username, new_password = sys.argv[1], sys.argv[2]

    with SessionLocal() as db:
        user = db.query(models.User).filter(models.User.username == username).first()
        if user is None:
            print(f"Aucun utilisateur nommé '{username}'.")
            sys.exit(1)

        user.password_hash = hash_password(new_password)
        db.commit()
        print(f"Mot de passe de '{username}' mis à jour (haché).")


if __name__ == "__main__":
    main()
