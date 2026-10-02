# -----------------------------------------------------------------------------
# C'est le fichier qu'on lance pour démarrer le serveur.
# FastAPI transforme les fonctions Python en routes HTTP grâce aux décorateurs
# @app.get(), @app.post(), @app.patch(), etc.
# -----------------------------------------------------------------------------

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import requests

from app.database import get_db
from app import models, schemas

from app.scanners.trivy import (
    run_trivy_scan,
    parse_trivy_results,
)

from app.scanners.semgrep import (
    run_semgrep_scan,
    parse_semgrep_results,
)

from app.scanners.gitleaks import (
    run_gitleaks_scan,
    parse_gitleaks_results,
)

from app.enrichment.epss import fetch_epss_score
from app.enrichment.kev import is_in_kev

from app.scoring import compute_priority_score

from app.config import settings

from app.llm.groq import analyze_finding_with_groq


# -----------------------------------------------------------------------------
# Création de l'application FastAPI
# -----------------------------------------------------------------------------

app = FastAPI(
    title="VulnScan API",
    description="Détection et priorisation des vulnérabilités par IA",
    version="0.1.0",
)


# -----------------------------------------------------------------------------
# CORS
# -----------------------------------------------------------------------------
#
# Le frontend React/Vite fonctionne généralement sur :
#
#     http://localhost:5173
#
# tandis que FastAPI fonctionne sur :
#
#     http://localhost:8000
#
# Le navigateur considère ces deux adresses comme des origines différentes.
# CORS permet donc au frontend de communiquer avec l'API.
# -----------------------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -----------------------------------------------------------------------------
# Health check
# -----------------------------------------------------------------------------

@app.get("/health")
def health_check():
    """
    Vérifie simplement que l'API fonctionne.
    """
    return {
        "status": "ok",
        "service": "vulnscan-api",
    }


# -----------------------------------------------------------------------------
# Route racine
# -----------------------------------------------------------------------------

@app.get("/")
def root():
    return {
        "message": (
            "Bienvenue sur l'API VulnScan. "
            "Voir /docs pour la documentation interactive."
        )
    }


# =============================================================================
# PROJETS
# =============================================================================

@app.post(
    "/projects",
    response_model=schemas.ProjectOut,
)
def create_project(
    payload: schemas.ProjectCreate,
    db: Session = Depends(get_db),
):
    """
    Crée un nouveau projet.
    """

    projet = models.Project(
        name=payload.name,
        repository_url=payload.repository_url,
    )

    db.add(projet)
    db.commit()
    db.refresh(projet)

    return projet


@app.get(
    "/projects",
    response_model=list[schemas.ProjectOut],
)
def list_projects(
    db: Session = Depends(get_db),
):
    """
    Retourne tous les projets.
    """

    return db.query(models.Project).all()


# =============================================================================
# FONCTIONS UTILITAIRES
# =============================================================================

def _get_project_or_error(
    db: Session,
    project_id: int,
) -> models.Project:
    """
    Recherche un projet par son ID.

    Si le projet n'existe pas, retourne une erreur HTTP 404.
    """

    projet = db.get(models.Project, project_id)

    if projet is None:
        raise HTTPException(
            status_code=404,
            detail=f"Aucun projet avec l'id {project_id}.",
        )

    return projet


def _get_finding_or_error(
    db: Session,
    finding_id: int,
) -> models.Finding:
    """
    Recherche une vulnérabilité par son ID.

    Si elle n'existe pas, retourne une erreur HTTP 404.
    """

    finding = db.get(models.Finding, finding_id)

    if finding is None:
        raise HTTPException(
            status_code=404,
            detail=f"Aucun finding avec l'id {finding_id}.",
        )

    return finding


def _save_findings(
    db: Session,
    project_id: int,
    parsed_items: list[dict],
) -> list[models.Finding]:
    """
    Fonction commune aux scanners.

    Transforme les dictionnaires retournés par les scanners
    en objets Finding, les sauvegarde dans PostgreSQL,
    puis retourne les findings créés.
    """

    nouveaux_findings = []

    for item in parsed_items:

        finding = models.Finding(
            project_id=project_id,
            **item,
        )

        db.add(finding)
        nouveaux_findings.append(finding)

    db.commit()

    for finding in nouveaux_findings:
        db.refresh(finding)

    return nouveaux_findings


# =============================================================================
# SCAN TRIVY
# =============================================================================

@app.post(
    "/projects/{project_id}/scan/trivy",
    response_model=list[schemas.FindingOut],
)
def scan_project_with_trivy(
    project_id: int,
    payload: schemas.ScanRequest,
    db: Session = Depends(get_db),
):
    """
    Lance Trivy sur le dossier indiqué.

    Trivy est utilisé principalement pour détecter
    les vulnérabilités dans les dépendances et images.
    """

    projet = _get_project_or_error(
        db,
        project_id,
    )

    try:
        raw_results = run_trivy_scan(
            payload.target_path
        )

        parsed = parse_trivy_results(
            raw_results
        )

        return _save_findings(
            db,
            projet.id,
            parsed,
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Erreur pendant le scan Trivy : {e}",
        )


# =============================================================================
# SCAN SEMGREP
# =============================================================================

@app.post(
    "/projects/{project_id}/scan/semgrep",
    response_model=list[schemas.FindingOut],
)
def scan_project_with_semgrep(
    project_id: int,
    payload: schemas.ScanRequest,
    db: Session = Depends(get_db),
):
    """
    Lance Semgrep pour analyser le code source.
    """

    projet = _get_project_or_error(
        db,
        project_id,
    )

    try:
        raw_results = run_semgrep_scan(
            payload.target_path
        )

        parsed = parse_semgrep_results(
            raw_results
        )

        return _save_findings(
            db,
            projet.id,
            parsed,
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Erreur pendant le scan Semgrep : {e}",
        )


# =============================================================================
# SCAN GITLEAKS
# =============================================================================

@app.post(
    "/projects/{project_id}/scan/gitleaks",
    response_model=list[schemas.FindingOut],
)
def scan_project_with_gitleaks(
    project_id: int,
    payload: schemas.ScanRequest,
    db: Session = Depends(get_db),
):
    """
    Lance Gitleaks pour détecter les secrets
    présents dans le projet.
    """

    projet = _get_project_or_error(
        db,
        project_id,
    )

    try:
        raw_results = run_gitleaks_scan(
            payload.target_path
        )

        parsed = parse_gitleaks_results(
            raw_results
        )

        return _save_findings(
            db,
            projet.id,
            parsed,
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Erreur pendant le scan Gitleaks : {e}",
        )


# =============================================================================
# FINDINGS
# =============================================================================

@app.get(
    "/projects/{project_id}/findings",
    response_model=list[schemas.FindingOut],
)
def list_findings(
    project_id: int,
    db: Session = Depends(get_db),
):
    """
    Retourne toutes les vulnérabilités d'un projet.
    """

    _get_project_or_error(
        db,
        project_id,
    )

    return (
        db.query(models.Finding)
        .filter(
            models.Finding.project_id == project_id
        )
        .all()
    )


# =============================================================================
# MOTEUR DE SCORING
# =============================================================================

@app.post(
    "/projects/{project_id}/score",
    response_model=list[schemas.FindingOut],
)
def score_project_findings(
    project_id: int,
    db: Session = Depends(get_db),
):
    """
    Recalcule le score de priorité de tous les findings
    d'un projet.

    Pour les vulnérabilités possédant un CVE :
        - récupération EPSS
        - vérification KEV
        - calcul du score final

    Les findings Gitleaks peuvent ne pas avoir de CVE.
    """

    projet = _get_project_or_error(
        db,
        project_id,
    )

    findings = (
        db.query(models.Finding)
        .filter(
            models.Finding.project_id == projet.id
        )
        .all()
    )

    for finding in findings:

        # ---------------------------------------------------------
        # Enrichissement CVE
        # ---------------------------------------------------------

        if (
            finding.vulnerability_id
            and finding.vulnerability_id.startswith("CVE-")
        ):

            finding.epss_score = fetch_epss_score(
                finding.vulnerability_id
            )

            finding.in_kev = is_in_kev(
                finding.vulnerability_id
            )

        # ---------------------------------------------------------
        # Calcul du score
        # ---------------------------------------------------------

        score, severity = compute_priority_score(
            cvss_score=finding.cvss_score,
            epss_score=finding.epss_score,
            in_kev=finding.in_kev,
            is_exposed=finding.is_exposed,
            fallback_severity=finding.severity.value,
        )

        finding.priority_score = score

        finding.severity = models.FindingSeverity(
            severity
        )

    db.commit()

    for finding in findings:
        db.refresh(finding)

    # Plus prioritaire en premier
    return sorted(
        findings,
        key=lambda finding: finding.priority_score or 0,
        reverse=True,
    )


# =============================================================================
# ANALYSE PAR IA / GROQ
# =============================================================================

@app.post(
    "/findings/{finding_id}/analyze",
    response_model=schemas.AIAnalysisOut,
)
def analyze_finding(
    finding_id: int,
    db: Session = Depends(get_db),
):
    """
    Analyse une vulnérabilité avec le modèle IA configuré
    via l'API Groq.

    Le modèle est récupéré depuis :

        settings.llm_model

    et la clé API depuis :

        settings.llm_api_key
    """

    # ---------------------------------------------------------
    # Recherche du finding
    # ---------------------------------------------------------

    finding = _get_finding_or_error(
        db,
        finding_id,
    )

    # ---------------------------------------------------------
    # Construction du contexte envoyé à l'IA
    # ---------------------------------------------------------

    context = {
        "title": finding.title,
        "scanner_name": finding.scanner_name,
        "vulnerability_id": finding.vulnerability_id,
        "description": finding.description,
        "file_path": finding.file_path,
        "cvss_score": finding.cvss_score,
        "epss_score": finding.epss_score,
        "in_kev": finding.in_kev,
        "code_snippet": finding.code_snippet,
    }

    # ---------------------------------------------------------
    # Vérification de la configuration Groq
    # ---------------------------------------------------------

    if not settings.llm_api_key:
        raise HTTPException(
            status_code=500,
            detail=(
                "La clé API Groq n'est pas configurée. "
                "Vérifiez LLM_API_KEY dans le fichier .env."
            ),
        )

    if not settings.llm_model:
        raise HTTPException(
            status_code=500,
            detail=(
                "Aucun modèle IA n'est configuré. "
                "Vérifiez LLM_MODEL dans le fichier .env."
            ),
        )

    # ---------------------------------------------------------
    # Appel de Groq
    # ---------------------------------------------------------

    try:

        result = analyze_finding_with_groq(
            finding_context=context,
            api_key=settings.llm_api_key,
            model=settings.llm_model,
        )

    except requests.exceptions.Timeout as e:

        raise HTTPException(
            status_code=504,
            detail=(
                "Le service Groq a mis trop de temps à répondre. "
                "Réessayez dans quelques instants."
            ),
        ) from e

    except requests.exceptions.HTTPError as e:

        raise HTTPException(
            status_code=502,
            detail=(
                "Le service Groq a retourné une erreur HTTP. "
                "Vérifiez la clé API et le modèle configuré. "
                f"Détail : {e}"
            ),
        ) from e

    except requests.exceptions.RequestException as e:

        raise HTTPException(
            status_code=503,
            detail=(
                "Le service Groq est actuellement indisponible "
                "ou inaccessible. Réessayez dans quelques instants. "
                f"Détail : {e}"
            ),
        ) from e

    except (ValueError, KeyError, TypeError) as e:

        raise HTTPException(
            status_code=502,
            detail=(
                "La réponse du modèle IA est invalide "
                "ou ne respecte pas le format attendu. "
                f"Détail : {e}"
            ),
        ) from e

    # ---------------------------------------------------------
    # Sauvegarde de l'analyse IA
    # ---------------------------------------------------------

    try:

        analyse = models.AIAnalysis(
            finding_id=finding.id,

            # Le fournisseur utilisé
            llm_provider="groq",

            # Modèle configuré dans .env
            ai_model_name=settings.llm_model,

            # Verdict retourné par l'IA
            ai_verdict=models.AIVerdict(
                result["verdict"]
            ),

            # Priorité ajustée par l'IA
            ai_adjusted_priority=models.AIAdjustedPriority(
                result["adjusted_priority"]
            ),

            # Explication de l'IA
            ai_reasoning=result["reasoning"],

            # Correction proposée
            ai_suggested_fix=result["suggested_fix"],

            # L'analyse doit être validée par un humain
            human_status=models.HumanReviewStatus.EN_ATTENTE,
        )

        db.add(analyse)
        db.commit()
        db.refresh(analyse)

    except Exception as e:

        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=(
                "L'analyse IA a bien été obtenue, "
                "mais son enregistrement en base de données "
                f"a échoué. Détail : {e}"
            ),
        ) from e

    return analyse


# =============================================================================
# HISTORIQUE DES ANALYSES IA
# =============================================================================

@app.get(
    "/findings/{finding_id}/analyses",
    response_model=list[schemas.AIAnalysisOut],
)
def list_finding_analyses(
    finding_id: int,
    db: Session = Depends(get_db),
):
    """
    Retourne toutes les analyses IA d'un finding.

    La plus récente est retournée en premier.
    """

    # Vérifie que le finding existe
    _get_finding_or_error(
        db,
        finding_id,
    )

    return (
        db.query(models.AIAnalysis)
        .filter(
            models.AIAnalysis.finding_id == finding_id
        )
        .order_by(
            models.AIAnalysis.created_at.desc()
        )
        .all()
    )


# =============================================================================
# UTILISATEURS
# =============================================================================

@app.post(
    "/users",
    response_model=schemas.UserOut,
)
def create_user(
    payload: schemas.UserCreate,
    db: Session = Depends(get_db),
):
    """
    Crée un utilisateur.

    ATTENTION :
    Le mot de passe est actuellement stocké directement.
    Pour une version de production, il faudra utiliser
    un véritable système de hashage.
    """

    utilisateur = models.User(
        username=payload.username,
        email=payload.email,
        password_hash=payload.password,
        role=models.UserRole(payload.role),
    )

    db.add(utilisateur)
    db.commit()
    db.refresh(utilisateur)

    return utilisateur


@app.get(
    "/users",
    response_model=list[schemas.UserOut],
)
def list_users(
    db: Session = Depends(get_db),
):
    """
    Retourne tous les utilisateurs.
    """

    return db.query(models.User).all()


# =============================================================================
# VALIDATION HUMAINE - HUMAN IN THE LOOP
# =============================================================================

@app.patch(
    "/analyses/{analysis_id}/review",
    response_model=schemas.AIAnalysisOut,
)
def review_analysis(
    analysis_id: int,
    payload: schemas.AnalysisReview,
    db: Session = Depends(get_db),
):
    """
    Permet à un utilisateur de valider ou rejeter
    une analyse produite par l'IA.

    Principe :

        IA propose
             ↓
        Humain vérifie
             ↓
        Humain approuve/rejette
             ↓
        Décision enregistrée
    """

    # ---------------------------------------------------------
    # Recherche de l'analyse
    # ---------------------------------------------------------

    analyse = db.get(
        models.AIAnalysis,
        analysis_id,
    )

    if analyse is None:
        raise HTTPException(
            status_code=404,
            detail=f"Aucune analyse avec l'id {analysis_id}.",
        )

    # ---------------------------------------------------------
    # Recherche de l'utilisateur
    # ---------------------------------------------------------

    utilisateur = db.get(
        models.User,
        payload.reviewed_by,
    )

    if utilisateur is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Aucun utilisateur avec l'id "
                f"{payload.reviewed_by}."
            ),
        )

    # ---------------------------------------------------------
    # Validation du statut
    # ---------------------------------------------------------

    try:

        nouveau_statut = models.HumanReviewStatus(
            payload.human_status
        )

    except ValueError as e:

        raise HTTPException(
            status_code=400,
            detail=(
                "Statut de validation humaine invalide. "
                "Utilisez une valeur autorisée par "
                "HumanReviewStatus."
            ),
        ) from e

    # ---------------------------------------------------------
    # Mise à jour
    # ---------------------------------------------------------

    analyse.human_status = nouveau_statut
    analyse.reviewed_by = utilisateur.id

    db.commit()
    db.refresh(analyse)

    return analyse