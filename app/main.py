# -----------------------------------------------------------------------------
# C'est le fichier qu'on lance pour démarrer le serveur.
# FastAPI transforme les fonctions Python en routes HTTP grâce aux décorateurs
# @app.get(), @app.post(), @app.patch(), etc.
#
# Correctifs de cette version (pipeline Jenkins) :
#   1. _save_findings : un finding déjà connu est MIS À JOUR (pas dupliqué).
#   2. ?build=N sur /findings et /score : on travaille sur UN build précis.
#   3. quality-gate : filtre par build + seuils (critical / high).
#   4. review_analysis : la décision humaine met à jour le statut du Finding.
# -----------------------------------------------------------------------------

from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
import requests
import jwt

from app.database import get_db, engine
from app import models, schemas
from app.models_builds import BuildRun
from app.auth import hash_password, verify_password, create_access_token, decode_access_token

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

@asynccontextmanager
async def lifespan(_: FastAPI):
    """
    Au démarrage : crée la table de l'historique des builds si elle n'existe pas
    encore (les autres tables restent gérées par app/init_db.py).
    """
    BuildRun.__table__.create(bind=engine, checkfirst=True)
    yield


app = FastAPI(
    title="VulnScan API",
    description="Détection et priorisation des vulnérabilités par IA",
    version="0.1.0",
    lifespan=lifespan,
)


# -----------------------------------------------------------------------------
# CORS
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
# Authentification
# -----------------------------------------------------------------------------

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")


def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> models.User:
    """
    Extrait l'utilisateur connecté à partir du jeton JWT. Toute route qui
    ajoute "Depends(get_current_user)" devient protégée.
    """
    try:
        user_id = decode_access_token(token)
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=401,
            detail="Jeton invalide ou expiré. Reconnectez-vous.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    utilisateur = db.get(models.User, user_id)
    if utilisateur is None:
        raise HTTPException(
            status_code=401,
            detail="Utilisateur introuvable.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return utilisateur


@app.post("/auth/login", response_model=schemas.TokenOut)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    """
    Vérifie le nom d'utilisateur et le mot de passe, et renvoie un jeton
    JWT valable 8 heures si tout est correct.
    """
    utilisateur = db.query(models.User).filter(models.User.username == form_data.username).first()

    # Même message pour "utilisateur inconnu" et "mauvais mot de passe" :
    # on ne révèle pas quels noms d'utilisateur existent.
    if utilisateur is None or not verify_password(form_data.password, utilisateur.password_hash):
        raise HTTPException(
            status_code=401,
            detail="Nom d'utilisateur ou mot de passe incorrect.",
        )

    token = create_access_token(utilisateur.id)
    return schemas.TokenOut(access_token=token)


@app.get("/auth/me", response_model=schemas.UserOut)
def read_current_user(current_user: models.User = Depends(get_current_user)):
    """Renvoie les infos de la personne actuellement connectée."""
    return current_user


# -----------------------------------------------------------------------------
# Health check
# -----------------------------------------------------------------------------

@app.get("/health")
def health_check():
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
    return db.query(models.Project).all()


# =============================================================================
# FONCTIONS UTILITAIRES
# =============================================================================

def _get_project_or_error(
    db: Session,
    project_id: int,
) -> models.Project:
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
    jenkins_build_number: int | None = None,
    git_commit_sha: str | None = None,
) -> list[models.Finding]:
    """
    CORRECTIF 1 : dédoublonnage.

    Avant : chaque scan créait de NOUVELLES lignes, même pour une vulnérabilité
    déjà connue. Une faille corrigée au build 5 restait "ouverte" à jamais
    (ligne du build 1), et bloquait le Quality Gate.

    Maintenant, un finding est identifié par :
        (projet, scanner, titre, fichier, ligne)

      - déjà connu  -> on met à jour "vu pour la dernière fois au build N" et
                       on CONSERVE son statut (donc la décision humaine).
      - nouveau     -> on le crée.
      - était FIXED mais réapparaît -> on le rouvre (NEW).

    Limite connue : si le code est décalé (la ligne change), le finding est
    considéré comme nouveau.
    """
    resultat = []

    for item in parsed_items:
        existant = (
            db.query(models.Finding)
            .filter(
                models.Finding.project_id == project_id,
                models.Finding.scanner_name == item.get("scanner_name"),
                models.Finding.title == item.get("title"),
                models.Finding.file_path == item.get("file_path"),
                models.Finding.line_number == item.get("line_number"),
            )
            .first()
        )

        if existant is not None:
            # Un scan lancé à la main (interface web) n'a pas de numéro de build :
            # on ne doit pas effacer le dernier build connu de ce finding.
            if jenkins_build_number is not None:
                existant.jenkins_build_number = jenkins_build_number
                existant.git_commit_sha = git_commit_sha
            if existant.status == models.FindingStatus.FIXED:
                existant.status = models.FindingStatus.NEW
            resultat.append(existant)
        else:
            finding = models.Finding(
                project_id=project_id,
                jenkins_build_number=jenkins_build_number,
                git_commit_sha=git_commit_sha,
                **item,
            )
            db.add(finding)
            # autoflush est désactivé : sans flush, deux éléments identiques
            # d'un même lot ne se verraient pas et seraient dupliqués.
            db.flush()
            resultat.append(finding)

    db.commit()

    for finding in resultat:
        db.refresh(finding)

    return resultat


def _sync_finding_status(
    db: Session,
    analyse: models.AIAnalysis,
) -> None:
    """
    CORRECTIF 4 : la décision humaine doit atteindre le Finding.

    Le Quality Gate lit Finding.status. Or la validation humaine ne modifiait
    que AIAnalysis.human_status : approuver un "faux positif" ne débloquait
    donc jamais le build.

      - humain APPROUVE le verdict IA "faux_positif"  -> FALSE_POSITIVE (ne bloque plus)
      - humain APPROUVE le verdict IA "vraie_menace"  -> CONFIRMED (bloque toujours)
      - humain REJETTE / remet en attente             -> on annule : retour à NEW
    """
    finding = db.get(models.Finding, analyse.finding_id)
    if finding is None:
        return

    if analyse.human_status == models.HumanReviewStatus.APPROUVE:
        if analyse.ai_verdict == models.AIVerdict.FAUX_POSITIF:
            finding.status = models.FindingStatus.FALSE_POSITIVE
        elif analyse.ai_verdict == models.AIVerdict.VRAIE_MENACE:
            finding.status = models.FindingStatus.CONFIRMED
    elif finding.status in (
        models.FindingStatus.FALSE_POSITIVE,
        models.FindingStatus.CONFIRMED,
    ):
        finding.status = models.FindingStatus.NEW


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
            jenkins_build_number=payload.jenkins_build_number,
            git_commit_sha=payload.git_commit_sha,
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
            jenkins_build_number=payload.jenkins_build_number,
            git_commit_sha=payload.git_commit_sha,
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
            jenkins_build_number=payload.jenkins_build_number,
            git_commit_sha=payload.git_commit_sha,
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
    build: int | None = None,   # CORRECTIF 2 : ?build=N
    db: Session = Depends(get_db),
):
    _get_project_or_error(
        db,
        project_id,
    )

    query = db.query(models.Finding).filter(
        models.Finding.project_id == project_id
    )

    if build is not None:
        query = query.filter(
            models.Finding.jenkins_build_number == build
        )

    return query.all()


# =============================================================================
# MOTEUR DE SCORING
# =============================================================================

@app.post(
    "/projects/{project_id}/score",
    response_model=list[schemas.FindingOut],
)
def score_project_findings(
    project_id: int,
    build: int | None = None,   # CORRECTIF 2 : ?build=N
    db: Session = Depends(get_db),
):
    projet = _get_project_or_error(
        db,
        project_id,
    )

    query = db.query(models.Finding).filter(
        models.Finding.project_id == projet.id
    )

    # En CI : on ne rescore que les findings vus lors de CE build
    # (sinon on refait des appels EPSS/KEV pour tout l'historique).
    if build is not None:
        query = query.filter(
            models.Finding.jenkins_build_number == build
        )

    findings = query.all()

    for finding in findings:
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

    return sorted(
        findings,
        key=lambda finding: finding.priority_score or 0,
        reverse=True,
    )


def _record_build(
    db: Session,
    project_id: int,
    build_number: int,
    all_findings: list[models.Finding],
    open_findings: list[models.Finding],
    passed: bool,
    blocking: int,
) -> None:
    """
    Enregistre (ou met à jour) l'instantané d'un build : combien de
    vulnérabilités ouvertes par sévérité, et le verdict du Quality Gate.
    Appeler deux fois pour le même build met simplement la ligne à jour.
    """
    run = (
        db.query(BuildRun)
        .filter(
            BuildRun.project_id == project_id,
            BuildRun.build_number == build_number,
        )
        .first()
    )

    if run is None:
        run = BuildRun(project_id=project_id, build_number=build_number)
        db.add(run)

    run.git_commit_sha = next(
        (f.git_commit_sha for f in all_findings if f.git_commit_sha),
        None,
    )

    def count(severity: models.FindingSeverity) -> int:
        return sum(1 for f in open_findings if f.severity == severity)

    run.critical = count(models.FindingSeverity.CRITICAL)
    run.high = count(models.FindingSeverity.HIGH)
    run.medium = count(models.FindingSeverity.MEDIUM)
    run.low = count(models.FindingSeverity.LOW)
    run.blocking = blocking
    run.passed = passed

    db.commit()


# =============================================================================
# QUALITY GATE CI/CD
# =============================================================================

@app.get(
    "/projects/{project_id}/quality-gate",
    response_model=schemas.QualityGateOut,
)
def quality_gate(
    project_id: int,
    build: int | None = None,        # ?build=N : seulement ce qui a été vu au build N
    max_critical: int = 0,           # nombre de critiques tolérés
    max_high: int | None = None,     # nombre de "high" tolérés (None = non vérifié)
    record: bool = False,            # True (Jenkins) : enregistre un instantané du build
    db: Session = Depends(get_db),
):
    """
    CORRECTIF 3 : le gate regarde un build précis et applique des seuils.

    Les secrets (Gitleaks) et le code (Semgrep) n'ont pas de CVSS : ils
    n'atteignent jamais "critical", seulement "high". Sans seuil sur "high",
    une clé API exposée ne bloquerait jamais le build.

    Statuts qui ne bloquent plus : FIXED, FALSE_POSITIVE, ACCEPTED_RISK.
    """
    projet = _get_project_or_error(
        db,
        project_id,
    )

    non_blocking_statuses = [
        models.FindingStatus.FIXED,
        models.FindingStatus.FALSE_POSITIVE,
        models.FindingStatus.ACCEPTED_RISK,
    ]

    query = db.query(models.Finding).filter(
        models.Finding.project_id == projet.id,
    )

    if build is not None:
        query = query.filter(
            models.Finding.jenkins_build_number == build
        )

    tous_ce_build = query.all()

    ouverts = [
        f for f in tous_ce_build
        if f.status not in non_blocking_statuses
    ]

    critiques = [
        f for f in ouverts
        if f.severity == models.FindingSeverity.CRITICAL
    ]
    hauts = [
        f for f in ouverts
        if f.severity == models.FindingSeverity.HIGH
    ]

    raisons = []
    bloquants = []

    if len(critiques) > max_critical:
        raisons.append(f"{len(critiques)} critique(s) (max {max_critical})")
        bloquants += critiques

    if max_high is not None and len(hauts) > max_high:
        raisons.append(f"{len(hauts)} haute(s) (max {max_high})")
        bloquants += hauts

    # Historique : Jenkins demande d'enregistrer le résultat de CE build.
    if record and build is not None:
        _record_build(
            db,
            projet.id,
            build,
            tous_ce_build,
            ouverts,
            passed=not raisons,
            blocking=len(bloquants),
        )

    if raisons:
        raise HTTPException(
            status_code=422,
            detail={
                "passed": False,
                "message": "Quality Gate échoué : " + " ; ".join(raisons) + ".",
                "blocking_findings": len(bloquants),
                "finding_ids": [f.id for f in bloquants],
            },
        )

    return schemas.QualityGateOut(
        passed=True,
        message="Quality Gate réussi : seuils respectés.",
        blocking_findings=0,
    )


# =============================================================================
# HISTORIQUE DES BUILDS
# =============================================================================

@app.get(
    "/projects/{project_id}/builds",
    response_model=list[schemas.BuildRunOut],
)
def list_builds(
    project_id: int,
    db: Session = Depends(get_db),
):
    """
    Historique des builds Jenkins enregistrés (le plus récent d'abord).
    Alimenté par l'appel du Jenkinsfile à /quality-gate?...&record=true.
    """
    _get_project_or_error(
        db,
        project_id,
    )

    return (
        db.query(BuildRun)
        .filter(BuildRun.project_id == project_id)
        .order_by(BuildRun.build_number.desc())
        .all()
    )


# =============================================================================
# ANALYSES IA D'UN PROJET (une seule requête pour toutes les vulnérabilités)
# =============================================================================

@app.get(
    "/projects/{project_id}/analyses",
    response_model=list[schemas.AnalysisDetailOut],
)
def list_project_analyses(
    project_id: int,
    db: Session = Depends(get_db),
):
    """
    Toutes les analyses IA du projet, la plus récente d'abord, avec le titre
    et la sévérité de la vulnérabilité concernée.
    """
    _get_project_or_error(
        db,
        project_id,
    )

    rows = (
        db.query(models.AIAnalysis, models.Finding)
        .join(
            models.Finding,
            models.AIAnalysis.finding_id == models.Finding.id,
        )
        .filter(models.Finding.project_id == project_id)
        .order_by(
            models.AIAnalysis.created_at.desc(),
            models.AIAnalysis.id.desc(),
        )
        .all()
    )

    return [
        schemas.AnalysisDetailOut(
            **schemas.AIAnalysisOut.model_validate(analysis).model_dump(),
            finding_title=finding.title,
            finding_severity=finding.severity.value,
            scanner_name=finding.scanner_name,
        )
        for analysis, finding in rows
    ]


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
    finding = _get_finding_or_error(
        db,
        finding_id,
    )

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

    try:
        analyse = models.AIAnalysis(
            finding_id=finding.id,
            llm_provider="groq",
            ai_model_name=settings.llm_model,
            ai_verdict=models.AIVerdict(
                result["verdict"]
            ),
            ai_adjusted_priority=models.AIAdjustedPriority(
                result["adjusted_priority"]
            ),
            ai_reasoning=result["reasoning"],
            ai_suggested_fix=result["suggested_fix"],
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
    utilisateur = models.User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
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
    current_user: models.User = Depends(get_current_user),
):
    analyse = db.get(
        models.AIAnalysis,
        analysis_id,
    )

    if analyse is None:
        raise HTTPException(
            status_code=404,
            detail=f"Aucune analyse avec l'id {analysis_id}.",
        )

    # "current_user" vient du jeton, déjà vérifié par get_current_user.
    utilisateur = current_user

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

    analyse.human_status = nouveau_statut
    analyse.reviewed_by = utilisateur.id

    # CORRECTIF 4 : propager la décision humaine au Finding (lu par le gate).
    _sync_finding_status(db, analyse)

    db.commit()
    db.refresh(analyse)

    return analyse