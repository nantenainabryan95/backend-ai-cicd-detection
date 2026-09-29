# -----------------------------------------------------------------------------
# Petit script qu'on exécute UNE FOIS pour créer réellement les tables dans
# PostgreSQL, à partir des classes définies dans app/models.py.
#
# Plus tard, pour un vrai projet en production, on utiliserait un outil comme
# "Alembic" pour gérer les évolutions du schéma proprement (ajouter une colonne
# sans perdre les données, etc.). Pour l'instant, on reste simple.
# -----------------------------------------------------------------------------

from app.database import Base, engine

# Cette ligne est très importante : même si on n'utilise pas directement
# "models" dans ce fichier, il FAUT l'importer pour que Python "découvre"
# les classes User, Project, Finding, et sache qu'elles doivent devenir
# des tables. Sans cet import, Base ne les connaît pas encore.
from app import models  # noqa: F401  (ce commentaire dit à l'outil de vérification de ne pas se plaindre d'un import "inutilisé")


def init_db():
    print("Création des tables dans la base de données...")
    Base.metadata.create_all(bind=engine)
    print("Terminé. Tables créées : users, projects, findings, analyses_ia.")


# Ce "if" est une convention Python très courante : le code à l'intérieur ne
# s'exécute que si on lance CE fichier directement (python -m app.init_db),
# pas si on l'importe depuis un autre fichier.
if __name__ == "__main__":
    init_db()
