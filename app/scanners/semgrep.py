# -----------------------------------------------------------------------------
# Même principe que trivy.py : une fonction qui lance l'outil, une fonction
# qui transforme son résultat en dictionnaires compatibles avec "vulnerabilites".
#
# Contrairement à un usage classique de Semgrep ("--config auto"), on utilise
# ici NOS PROPRES règles, écrites dans semgrep-rules.yaml, à côté de ce
# fichier. Avantage : aucune connexion internet nécessaire pendant le scan.
# -----------------------------------------------------------------------------

import json
import os
import shutil
import subprocess
from pathlib import Path


# Nom du fichier de règles copié temporairement dans le dossier scanné.
_RULES_FILENAME = ".vulnscan-semgrep-rules.yaml"


def run_semgrep_scan(target_path: str) -> dict:
    """
    Lance Semgrep sur le dossier "target_path", via Docker, en utilisant nos
    propres règles (voir semgrep-rules.yaml), sans dépendre d'internet.

    Le fichier de règles est copié dans le dossier scanné (comme le rapport de
    Gitleaks), puis supprimé. Ainsi un seul montage suffit, et cela fonctionne
    aussi quand l'API tourne dans un conteneur Docker : le chemin du fichier de
    règles vu par l'API n'existerait pas sur la machine qui exécute Docker.
    """
    rules_in_target = os.path.join(target_path, _RULES_FILENAME)
    shutil.copyfile(Path(__file__).parent / "semgrep-rules.yaml", rules_in_target)

    command = [
        "docker", "run", "--rm",
        "-v", f"{target_path}:/src",
        "semgrep/semgrep",
        "semgrep", "scan",
        "--config", f"/src/{_RULES_FILENAME}",
        "--json",
        "--quiet",
        "--exclude", _RULES_FILENAME,
        "--exclude", "venv",
        "--exclude", "node_modules",
        "--exclude", "__pycache__",
        "/src",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
        )
    finally:
        if os.path.exists(rules_in_target):
            os.remove(rules_in_target)

    if not result.stdout:
        raise RuntimeError(f"Semgrep n'a rien renvoyé : {result.stderr}")

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "Semgrep a terminé mais son résultat n'est pas un JSON valide. "
            f"Détail : {result.stderr}"
        ) from exc


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