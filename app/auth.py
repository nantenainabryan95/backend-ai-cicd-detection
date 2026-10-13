# -----------------------------------------------------------------------------
# Ce fichier gère deux choses séparées mais liées :
#  1) Le hachage des mots de passe (jamais stockés en clair en base).
#  2) La création et la vérification des jetons JWT, utilisés pour prouver
#     qu'une personne est bien connectée, sans renvoyer son mot de passe à
#     chaque requête.
# -----------------------------------------------------------------------------

from datetime import datetime, timedelta, timezone

import jwt
from passlib.context import CryptContext

from app.config import settings

# "CryptContext" sait comment hacher un mot de passe avec bcrypt, un
# algorithme pensé spécifiquement pour ça (lent exprès, pour rendre les
# attaques par force brute beaucoup plus coûteuses).
_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8  # un jeton reste valide 8 heures


def hash_password(plain_password: str) -> str:
    """Transforme un mot de passe en clair en une empreinte à stocker en base."""
    return _pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Vérifie qu'un mot de passe en clair correspond bien à une empreinte donnée.

    Si l'empreinte stockée n'est pas un vrai hash bcrypt (cas d'un ancien
    utilisateur créé avant l'ajout du hachage, dont le mot de passe était
    en clair), passlib lève une ValueError : on répond simplement "non"
    plutôt que de faire planter la connexion avec une erreur 500.
    """
    try:
        return _pwd_context.verify(plain_password, hashed_password)
    except ValueError:
        return False


def create_access_token(user_id: int) -> str:
    """
    Crée un jeton JWT contenant l'id de l'utilisateur et une date d'expiration.
    "sub" (subject) est le nom conventionnel du champ qui identifie à QUI
    appartient ce jeton.
    """
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {"sub": str(user_id), "exp": expire}
    return jwt.encode(payload, settings.jwt_secret, algorithm=ALGORITHM)


def decode_access_token(token: str) -> int:
    """
    Vérifie un jeton JWT et renvoie l'id de l'utilisateur qu'il contient.
    Lève une erreur si le jeton est invalide, modifié, ou expiré.
    """
    payload = jwt.decode(token, settings.jwt_secret, algorithms=[ALGORITHM])
    return int(payload["sub"])
