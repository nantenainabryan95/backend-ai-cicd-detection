# -----------------------------------------------------------------------------
# Les "schémas" Pydantic décrivent la forme des données qui entrent et
# sortent de l'API (différent des modèles SQLAlchemy, qui décrivent la
# base de données). FastAPI s'en sert pour valider automatiquement ce que
# les gens envoient, et pour générer la documentation sur /docs.
# -----------------------------------------------------------------------------

from pydantic import BaseModel


class ProjectCreate(BaseModel):
    name: str
    repository_url: str = ""


class ProjectOut(BaseModel):
    id: int
    name: str
    repository_url: str

    # Ça dit à Pydantic : "tu peux lire ces champs directement depuis un
    # objet SQLAlchemy (Project), pas seulement depuis un dictionnaire".
    model_config = {"from_attributes": True}


class ScanRequest(BaseModel):
    target_path: str  # chemin, DANS le conteneur Docker, vers le code à scanner


class FindingOut(BaseModel):
    id: int
    title: str
    scanner_name: str
    vulnerability_id: str | None
    file_path: str | None
    severity: str
    cvss_score: float | None
    epss_score: float | None
    in_kev: bool
    is_exposed: bool
    priority_score: float | None
    fix_available: bool

    model_config = {"from_attributes": True}


class AIAnalysisOut(BaseModel):
    id: int
    finding_id: int
    llm_provider: str
    ai_model_name: str
    ai_verdict: str
    ai_adjusted_priority: str | None
    ai_reasoning: str
    ai_suggested_fix: str | None
    human_status: str
    reviewed_by: int | None

    model_config = {"from_attributes": True}


class UserCreate(BaseModel):
    username: str
    email: str
    # NOTE : en clair pour l'instant, sans hachage. Ce n'est PAS sécurisé
    # tel quel : on corrigera ça à l'étape "authentification", où on
    # utilisera une vraie bibliothèque de hachage (passlib/bcrypt) pour ne
    # jamais stocker un mot de passe lisible en base.
    password: str
    role: str = "developer"


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: str

    model_config = {"from_attributes": True}


class AnalysisReview(BaseModel):
    human_status: str  # "approuve" ou "rejete"
    reviewed_by: int    # id de l'utilisateur qui valide