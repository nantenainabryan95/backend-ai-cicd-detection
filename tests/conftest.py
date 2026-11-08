"""
Outils partagés par les tests de l'API (accès par rôle, Quality Gate, décisions).

Principe : aucun serveur et aucun PostgreSQL. Chaque test reçoit une base SQLite
vide, créée en mémoire, et un client qui appelle l'API directement en Python.

Lancer :  python -m pytest -v
"""

import os

# Ces deux lignes DOIVENT précéder tout import de "app" : elles empêchent les
# tests de toucher à la vraie base PostgreSQL et fournissent un secret JWT valide.
os.environ["DATABASE_URL"] = "sqlite://"
os.environ["JWT_SECRET"] = "secret-de-test-" + "x" * 40

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import models
from app.auth import create_access_token, hash_password
from app.database import Base, get_db
from app.main import app  # importe aussi les tables des builds et des décisions


@pytest.fixture()
def db_session():
    """Base SQLite en mémoire, vide, recréée pour chaque test."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, autoflush=False)()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture()
def client(db_session):
    """Client HTTP de test, branché sur la base en mémoire."""

    def _get_test_db():
        yield db_session

    app.dependency_overrides[get_db] = _get_test_db
    yield TestClient(app)  # sans "with" : le démarrage (lifespan) n'est pas exécuté
    app.dependency_overrides.clear()


@pytest.fixture()
def make_user(db_session):
    """Crée (une seule fois par test) l'utilisateur du rôle demandé et le renvoie."""
    deja_crees = {}

    def _make(role: str):
        if role in deja_crees:
            return deja_crees[role]
        utilisateur = models.User(
            username=f"user_{role}",
            email=f"{role}@test.local",
            password_hash=hash_password("motdepasse123"),
            role=models.UserRole(role),
        )
        db_session.add(utilisateur)
        db_session.commit()
        deja_crees[role] = utilisateur
        return utilisateur

    return _make


@pytest.fixture()
def auth(make_user):
    """En-tête d'authentification pour un utilisateur du rôle demandé."""

    def _auth(role: str) -> dict:
        utilisateur = make_user(role)
        return {"Authorization": f"Bearer {create_access_token(utilisateur.id)}"}

    return _auth


@pytest.fixture()
def project(db_session):
    projet = models.Project(name="projet-test", repository_url="https://exemple.local/depot")
    db_session.add(projet)
    db_session.commit()
    return projet


@pytest.fixture()
def make_finding(db_session, project):
    """Crée une vulnérabilité d'une sévérité, d'un statut et d'un build donnés."""
    compteur = {"n": 0}

    def _make(severity="critical", status="new", build=1):
        compteur["n"] += 1
        finding = models.Finding(
            project_id=project.id,
            title=f"vuln-{compteur['n']}",
            scanner_name="trivy",
            severity=models.FindingSeverity(severity),
            status=models.FindingStatus(status),
            jenkins_build_number=build,
        )
        db_session.add(finding)
        db_session.commit()
        return finding

    return _make
