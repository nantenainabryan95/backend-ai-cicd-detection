# -----------------------------------------------------------------------------
# SQLAlchemy est la bibliothèque Python qui permet de parler à PostgreSQL sans
# écrire de SQL brut partout : on définira nos tables comme des classes Python
# (on appelle ça un "ORM" - Object Relational Mapper).
# -----------------------------------------------------------------------------

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

from app.config import settings

# "engine" représente la connexion réelle vers PostgreSQL.
# On le crée une seule fois au démarrage de l'application.
engine = create_engine(settings.database_url)

# "SessionLocal" est une fabrique de sessions : une session, c'est une
# conversation temporaire avec la base (le temps d'une requête HTTP, en général).
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# Toutes nos futures tables (Finding, Project, User...) hériteront de cette
# classe "Base". C'est une convention SQLAlchemy : hériter d'une classe pour
# dire "cette classe Python correspond à une table en base".
class Base(DeclarativeBase):
    pass


def get_db():
    """
    Cette fonction fournit une session de base de données à chaque requête,
    puis la referme automatiquement à la fin, même en cas d'erreur.

    Le mot-clé "yield" (au lieu de "return") en fait un générateur : FastAPI
    sait s'en servir pour ouvrir la session avant la requête et la fermer
    juste après, sans qu'on ait à écrire ce code à chaque endpoint.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
