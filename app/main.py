# -----------------------------------------------------------------------------
# C'est le fichier qu'on lance pour démarrer le serveur. FastAPI transforme
# des fonctions Python normales en routes HTTP grâce à des "décorateurs"
# (les lignes qui commencent par @, juste au-dessus d'une fonction).
# -----------------------------------------------------------------------------

from fastapi import FastAPI, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app import models, schemas
from app.scanners.trivy import run_trivy_scan, parse_trivy_results
from app.scanners.semgrep import run_semgrep_scan, parse_semgrep_results
from app.scanners.gitleaks import run_gitleaks_scan, parse_gitleaks_results
from app.enrichment.epss import fetch_epss_score
from app.enrichment.kev import is_in_kev
from app.scoring import compute_priority_score
from app.config import settings
from app.llm.gemini import analyze_finding_with_gemini

# On crée l'application. C'est cet objet "app" qu'uvicorn (le serveur) va lancer.
app = FastAPI(
    title="VulnScan API",
    description="Détection et priorisation des vulnérabilités par IA",
    version="0.1.0",
)


# @app.get("/health") veut dire : "quand quelqu'un fait une requête GET sur
# l'URL /health, exécute la fonction juste en dessous".
@app.get("/health")
def health_check():
    """
    Endpoint très simple pour vérifier que le serveur tourne.
    """
    return {"status": "ok", "service": "vulnscan-api"}


@app.get("/")
def root():
    return {"message": "Bienvenue sur l'API VulnScan. Voir /docs pour la documentation interactive."}


# -----------------------------------------------------------------------------
# Projets
# -----------------------------------------------------------------------------

@app.post("/projects", response_model=schemas.ProjectOut)
def create_project(payload: schemas.ProjectCreate, db: Session = Depends(get_db)):
    """
    Crée un nouveau projet. "Depends(get_db)" est la façon dont FastAPI
    fournit automatiquement une session de base de données à cette fonction,
    en utilisant la fonction get_db() qu'on a définie dans database.py.
    """
    projet = models.Project(name=payload.name, repository_url=payload.repository_url)
    db.add(projet)
    db.commit()
    db.refresh(projet)  # récupère l'id généré par PostgreSQL
    return projet


@app.get("/projects", response_model=list[schemas.ProjectOut])
def list_projects(db: Session = Depends(get_db)):
    return db.query(models.Project).all()


# -----------------------------------------------------------------------------
# Scans
# -----------------------------------------------------------------------------

def _save_findings(db: Session, project_id: int, parsed_items: list[dict]) -> list[models.Finding]:
    """
    Petite fonction commune aux trois scanners : transforme une liste de
    dictionnaires en objets Finding, les enregistre, et les renvoie.
    On évite ainsi de répéter ce même code dans chaque endpoint de scan.
    """
    nouveaux_findings = []
    for item in parsed_items:
        finding = models.Finding(project_id=project_id, **item)
        db.add(finding)
        nouveaux_findings.append(finding)

    db.commit()
    for f in nouveaux_findings:
        db.refresh(f)

    return nouveaux_findings


def _get_project_or_error(db: Session, project_id: int) -> models.Project:
    projet = db.get(models.Project, project_id)
    if projet is None:
        raise ValueError(f"Aucun projet avec l'id {project_id}")
    return projet


@app.post("/projects/{project_id}/scan/trivy", response_model=list[schemas.FindingOut])
def scan_project_with_trivy(project_id: int, payload: schemas.ScanRequest, db: Session = Depends(get_db)):
    """
    Lance Trivy sur le dossier "target_path", puis enregistre chaque
    vulnérabilité trouvée comme une nouvelle ligne dans "vulnerabilites".
    """
    projet = _get_project_or_error(db, project_id)
    raw_results = run_trivy_scan(payload.target_path)
    parsed = parse_trivy_results(raw_results)
    return _save_findings(db, projet.id, parsed)


@app.post("/projects/{project_id}/scan/semgrep", response_model=list[schemas.FindingOut])
def scan_project_with_semgrep(project_id: int, payload: schemas.ScanRequest, db: Session = Depends(get_db)):
    """
    Lance Semgrep (analyse du code) sur le dossier "target_path".
    """
    projet = _get_project_or_error(db, project_id)
    raw_results = run_semgrep_scan(payload.target_path)
    parsed = parse_semgrep_results(raw_results)
    return _save_findings(db, projet.id, parsed)


@app.post("/projects/{project_id}/scan/gitleaks", response_model=list[schemas.FindingOut])
def scan_project_with_gitleaks(project_id: int, payload: schemas.ScanRequest, db: Session = Depends(get_db)):
    """
    Lance Gitleaks (détection de secrets) sur le dossier "target_path".
    """
    projet = _get_project_or_error(db, project_id)
    raw_results = run_gitleaks_scan(payload.target_path)
    parsed = parse_gitleaks_results(raw_results)
    return _save_findings(db, projet.id, parsed)


@app.get("/projects/{project_id}/findings", response_model=list[schemas.FindingOut])
def list_findings(project_id: int, db: Session = Depends(get_db)):
    return db.query(models.Finding).filter(models.Finding.project_id == project_id).all()


# -----------------------------------------------------------------------------
# Moteur de scoring
# -----------------------------------------------------------------------------

@app.post("/projects/{project_id}/score", response_model=list[schemas.FindingOut])
def score_project_findings(project_id: int, db: Session = Depends(get_db)):
    """
    Recalcule le score de priorité de TOUS les findings d'un projet.

    Pour chaque finding qui a un vrai CVE (pas les secrets Gitleaks, qui
    n'en ont pas), on va d'abord chercher son score EPSS et vérifier s'il
    est dans le catalogue KEV, AVANT de calculer le score final.
    """
    projet = _get_project_or_error(db, project_id)

    findings = db.query(models.Finding).filter(models.Finding.project_id == projet.id).all()

    for finding in findings:
        # On n'enrichit que les findings avec un vrai identifiant CVE.
        # ".startswith" vérifie simplement que le texte commence par "CVE-".
        if finding.vulnerability_id and finding.vulnerability_id.startswith("CVE-"):
            finding.epss_score = fetch_epss_score(finding.vulnerability_id)
            finding.in_kev = is_in_kev(finding.vulnerability_id)

        score, severity = compute_priority_score(
            cvss_score=finding.cvss_score,
            epss_score=finding.epss_score,
            in_kev=finding.in_kev,
            is_exposed=finding.is_exposed,
            fallback_severity=finding.severity.value,
        )
        finding.priority_score = score
        finding.severity = models.FindingSeverity(severity)

    db.commit()
    for f in findings:
        db.refresh(f)

    # On renvoie la liste triée du plus prioritaire au moins prioritaire :
    # c'est exactement ce qu'un développeur ou un analyste veut voir en premier.
    return sorted(findings, key=lambda f: f.priority_score or 0, reverse=True)


# -----------------------------------------------------------------------------
# Analyse par le LLM
# -----------------------------------------------------------------------------

def _get_finding_or_error(db: Session, finding_id: int) -> models.Finding:
    finding = db.get(models.Finding, finding_id)
    if finding is None:
        raise ValueError(f"Aucun finding avec l'id {finding_id}")
    return finding


@app.post("/findings/{finding_id}/analyze", response_model=schemas.AIAnalysisOut)
def analyze_finding(finding_id: int, db: Session = Depends(get_db)):
    """
    Demande au LLM d'analyser CE finding précis, et enregistre le résultat
    comme une nouvelle ligne dans "analyses_ia" (on garde l'historique, on
    n'écrase jamais une analyse précédente).
    """
    finding = _get_finding_or_error(db, finding_id)

    # On rassemble tout ce que le LLM a besoin de savoir sur cette
    # vulnérabilité, dans un simple dictionnaire.
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

    result = analyze_finding_with_gemini(context, api_key=settings.llm_api_key, model=settings.llm_model)

    analyse = models.AIAnalysis(
        finding_id=finding.id,
        llm_provider="gemini",
        ai_model_name=settings.llm_model,
        ai_verdict=models.AIVerdict(result["verdict"]),
        ai_adjusted_priority=models.AIAdjustedPriority(result["adjusted_priority"]),
        ai_reasoning=result["reasoning"],
        ai_suggested_fix=result["suggested_fix"],
        human_status=models.HumanReviewStatus.EN_ATTENTE,
    )
    db.add(analyse)
    db.commit()
    db.refresh(analyse)

    return analyse


@app.get("/findings/{finding_id}/analyses", response_model=list[schemas.AIAnalysisOut])
def list_finding_analyses(finding_id: int, db: Session = Depends(get_db)):
    """Historique de toutes les analyses faites sur ce finding, la plus récente en premier."""
    return (
        db.query(models.AIAnalysis)
        .filter(models.AIAnalysis.finding_id == finding_id)
        .order_by(models.AIAnalysis.created_at.desc())
        .all()
    )