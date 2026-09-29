# -----------------------------------------------------------------------------
# Même principe que trivy.py : une fonction qui lance l'outil, une fonction
# qui transforme son résultat en dictionnaires compatibles avec "vulnerabilites".
#
# Contrairement à un usage classique de Semgrep ("--config auto"), on utilise
# ici NOS PROPRES règles, écrites dans semgrep-rules.yaml, à côté de ce
# fichier. Avantage : aucune connexion internet nécessaire pendant le scan.
# -----------------------------------------------------------------------------

import json
import subprocess
from pathlib import Path


def _get_rules_path_for_docker() -> str:
    """
    Renvoie le chemin, sur VOTRE machine, vers le fichier de règles, dans un
    format que Docker accepte pour le montage de volume (avec des "/", même
    sous Windows).

    "Path(__file__)" représente le chemin de CE fichier Python. ".parent"
    donne son dossier. C'est une façon fiable de retrouver un fichier voisin,
    qui fonctionne peu importe d'où le programme est lancé.
    """
    rules_file = Path(__file__).parent / "semgrep-rules.yaml"
    # "resolve()" transforme en chemin absolu, ".as_posix()" force les "/"
    # (même sous Windows), ce qui est le format attendu par Docker.
    return rules_file.resolve().as_posix()


def run_semgrep_scan(target_path: str) -> dict:
    """
    Lance Semgrep sur le dossier "target_path", via Docker, en utilisant nos
    propres règles (voir semgrep-rules.yaml), sans dépendre d'internet.
    """
    rules_path = _get_rules_path_for_docker()

    command = [
        "docker", "run", "--rm",
        "-v", f"{target_path}:/src",
        "-v", f"{rules_path}:/rules.yaml",  # on "monte" aussi notre fichier de règles
        "semgrep/semgrep",
        "semgrep", "scan",
        "--config", "/rules.yaml",
        "--json",
        "--quiet",
        "--exclude", "venv",
        "--exclude", "node_modules",
        "--exclude", "__pycache__",
        "/src",
    ]

    result = subprocess.run(command, capture_output=True, text=True, timeout=120)

    # Contrairement à Trivy, Semgrep renvoie un code différent de 0 quand il
    # TROUVE des problèmes de sécurité (ce n'est pas un échec de l'outil,
    # c'est le résultat attendu !). On ne vérifie donc pas returncode ici,
    # sauf si la sortie est franchement vide, signe d'un vrai plantage.
    if not result.stdout:
        raise RuntimeError(f"Semgrep n'a rien renvoyé : {result.stderr}")

    return json.loads(result.stdout)


# Semgrep utilise ses propres niveaux (ERROR, WARNING, INFO), différents de
# ceux de Trivy. On fait la correspondance vers nos niveaux à nous.
_SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


def parse_semgrep_results(raw_results: dict) -> list[dict]:
    """
    Transforme le JSON de Semgrep en une liste de dictionnaires, un par
    problème détecté dans le code.
    """
    findings: list[dict] = []

    for item in raw_results.get("results", []):
        extra = item.get("extra", {})
        severity_raw = extra.get("severity", "INFO")

        findings.append({
            "title": item.get("check_id", "Règle Semgrep inconnue"),
            "description": extra.get("message", "")[:2000],
            "scanner_name": "semgrep",
            "vulnerability_id": item.get("check_id"),
            "file_path": item.get("path"),
            "line_number": item.get("start", {}).get("line"),
            "code_snippet": (extra.get("lines") or "")[:1000],
            "raw_severity": severity_raw,
            "severity": _SEVERITY_MAP.get(severity_raw, "low"),
            "fix_available": False,
        })

    return findings# -----------------------------------------------------------------------------
# Même principe que trivy.py : une fonction qui lance l'outil, une fonction
# qui transforme son résultat en dictionnaires compatibles avec "vulnerabilites".
#
# Contrairement à un usage classique de Semgrep ("--config auto"), on utilise
# ici NOS PROPRES règles, écrites dans semgrep-rules.yaml, à côté de ce
# fichier. Avantage : aucune connexion internet nécessaire pendant le scan.
# -----------------------------------------------------------------------------

import json
import subprocess
from pathlib import Path


def _get_rules_path_for_docker() -> str:
    """
    Renvoie le chemin, sur VOTRE machine, vers le fichier de règles, dans un
    format que Docker accepte pour le montage de volume (avec des "/", même
    sous Windows).

    "Path(__file__)" représente le chemin de CE fichier Python. ".parent"
    donne son dossier. C'est une façon fiable de retrouver un fichier voisin,
    qui fonctionne peu importe d'où le programme est lancé.
    """
    rules_file = Path(__file__).parent / "semgrep-rules.yaml"
    # "resolve()" transforme en chemin absolu, ".as_posix()" force les "/"
    # (même sous Windows), ce qui est le format attendu par Docker.
    return rules_file.resolve().as_posix()


def run_semgrep_scan(target_path: str) -> dict:
    """
    Lance Semgrep sur le dossier "target_path", via Docker, en utilisant nos
    propres règles (voir semgrep-rules.yaml), sans dépendre d'internet.
    """
    rules_path = _get_rules_path_for_docker()

    command = [
        "docker", "run", "--rm",
        "-v", f"{target_path}:/src",
        "-v", f"{rules_path}:/rules.yaml",  # on "monte" aussi notre fichier de règles
        "semgrep/semgrep",
        "semgrep", "scan",
        "--config", "/rules.yaml",
        "--json",
        "--quiet",
        "--exclude", "venv",
        "--exclude", "node_modules",
        "--exclude", "__pycache__",
        "/src",
    ]

    result = subprocess.run(command, capture_output=True, text=True, timeout=120)

    # Contrairement à Trivy, Semgrep renvoie un code différent de 0 quand il
    # TROUVE des problèmes de sécurité (ce n'est pas un échec de l'outil,
    # c'est le résultat attendu !). On ne vérifie donc pas returncode ici,
    # sauf si la sortie est franchement vide, signe d'un vrai plantage.
    if not result.stdout:
        raise RuntimeError(f"Semgrep n'a rien renvoyé : {result.stderr}")

    return json.loads(result.stdout)


# Semgrep utilise ses propres niveaux (ERROR, WARNING, INFO), différents de
# ceux de Trivy. On fait la correspondance vers nos niveaux à nous.
_SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}


def parse_semgrep_results(raw_results: dict) -> list[dict]:
    """
    Transforme le JSON de Semgrep en une liste de dictionnaires, un par
    problème détecté dans le code.
    """
    findings: list[dict] = []

    for item in raw_results.get("results", []):
        extra = item.get("extra", {})
        severity_raw = extra.get("severity", "INFO")

        findings.append({
            "title": item.get("check_id", "Règle Semgrep inconnue"),
            "description": extra.get("message", "")[:2000],
            "scanner_name": "semgrep",
            "vulnerability_id": item.get("check_id"),
            "file_path": item.get("path"),
            "line_number": item.get("start", {}).get("line"),
            "code_snippet": (extra.get("lines") or "")[:1000],
            "raw_severity": severity_raw,
            "severity": _SEVERITY_MAP.get(severity_raw, "low"),
            "fix_available": False,
        })

    return findings
