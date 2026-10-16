# -----------------------------------------------------------------------------
# Crée un utilisateur (ou met à jour son mot de passe et son rôle s'il existe).
# Sert à créer le premier administrateur et le compte de service de Jenkins.
#
# Usage (depuis la racine du projet, venv activé) :
#     python -m app.create_user <nom> <mot_de_passe> <rôle> [email]
#
# Rôles : developer, appsec, tech_lead, admin
# Exemples :
#     python -m app.create_user admin MotDePasseSolide admin
#     python -m app.create_user jenkins AutreMotDePasse developer
# -----------------------------------------------------------------------------

import sys

from app.database import SessionLocal
from app import models
from app.auth import hash_password


def main():
    if len(sys.argv) not in (4, 5):
        print("Usage : python -m app.create_user <nom> <mot_de_passe> <rôle> [email]")
        print("Rôles : " + ", ".join(r.value for r in models.UserRole))
        sys.exit(1)

    username, password, role = sys.argv[1], sys.argv[2], sys.argv[3]
    email = sys.argv[4] if len(sys.argv) == 5 else f"{username}@vulnscan.local"

    try:
        role_enum = models.UserRole(role)
    except ValueError:
        print(f"Rôle inconnu : '{role}'. Rôles : " + ", ".join(r.value for r in models.UserRole))
        sys.exit(1)

    with SessionLocal() as db:
        user = db.query(models.User).filter(models.User.username == username).first()

        if user is None:
            db.add(
                models.User(
                    username=username,
                    email=email,
                    password_hash=hash_password(password),
                    role=role_enum,
                )
            )
            action = "créé"
        else:
            user.password_hash = hash_password(password)
            user.role = role_enum
            action = "mis à jour"

        db.commit()
        print(f"Utilisateur '{username}' {action} (rôle : {role}).")


if __name__ == "__main__":
    main()
