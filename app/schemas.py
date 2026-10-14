from datetime import datetime

from pydantic import BaseModel


# =============================================================================
# PROJETS
# =============================================================================

class ProjectCreate(BaseModel):
    name: str
    repository_url: str = ""


class ProjectOut(BaseModel):
    id: int
    name: str
    repository_url: str

    model_config = {
        "from_attributes": True
    }


# =============================================================================
# SCANS
# =============================================================================

class ScanRequest(BaseModel):
    """
    Paramètres envoyés lors d'un scan.

    target_path :
        Chemin du projet à analyser.

    jenkins_build_number :
        Numéro du build Jenkins ayant déclenché le scan.

    git_commit_sha :
        SHA du commit Git analysé par Jenkins.
    """

    target_path: str

    jenkins_build_number: int | None = None

    git_commit_sha: str | None = None


# =============================================================================
# FINDINGS / VULNERABILITES
# =============================================================================

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

    # -------------------------------------------------------------------------
    # Détail (page "fiche d'une vulnérabilité")
    # -------------------------------------------------------------------------

    description: str | None = None

    code_snippet: str | None = None

    line_number: int | None = None

    status: str = "new"

    # -------------------------------------------------------------------------
    # Informations CI/CD Jenkins
    # -------------------------------------------------------------------------

    jenkins_build_number: int | None

    git_commit_sha: str | None

    model_config = {
        "from_attributes": True
    }


# =============================================================================
# QUALITY GATE
# =============================================================================

class QualityGateOut(BaseModel):
    """
    Résultat du Quality Gate Jenkins.
    """

    passed: bool

    message: str

    blocking_findings: int

    model_config = {
        "from_attributes": True
    }


# =============================================================================
# HISTORIQUE DES BUILDS
# =============================================================================

class BuildRunOut(BaseModel):
    build_number: int

    git_commit_sha: str | None

    created_at: datetime | None

    critical: int

    high: int

    medium: int

    low: int

    blocking: int

    passed: bool

    model_config = {
        "from_attributes": True
    }


# =============================================================================
# ANALYSES IA
# =============================================================================

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

    created_at: datetime | None = None

    model_config = {
        "from_attributes": True
    }


class AnalysisDetailOut(AIAnalysisOut):
    """Une analyse + les informations de la vulnérabilité concernée."""

    finding_title: str

    finding_severity: str

    scanner_name: str


# =============================================================================
# UTILISATEURS
# =============================================================================

class UserCreate(BaseModel):
    username: str

    email: str

    password: str

    role: str = "developer"


class UserOut(BaseModel):
    id: int

    username: str

    email: str

    role: str

    model_config = {
        "from_attributes": True
    }


# =============================================================================
# VALIDATION HUMAINE
# =============================================================================

class AnalysisReview(BaseModel):
    """
    "reviewed_by" n'est plus envoyé ici : on le déduit automatiquement de
    la personne connectée (via son jeton), pour éviter qu'un utilisateur
    puisse valider une analyse "au nom" de quelqu'un d'autre simplement en
    changeant un nombre dans la requête.
    """
    human_status: str


# =============================================================================
# AUTHENTIFICATION
# =============================================================================

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"