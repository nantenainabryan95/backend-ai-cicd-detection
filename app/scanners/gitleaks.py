# -----------------------------------------------------------------------------
# Gitleaks fonctionne différemment des deux autres : il n'affiche pas son
# résultat directement dans le terminal, il l'écrit dans un FICHIER JSON.
# On lui demande donc d'écrire ce fichier dans le dossier scanné (qui est
# "partagé" avec Docker), puis on le relit depuis Python, et on le supprime
# une fois lu, pour ne pas laisser de fichier temporaire trainer.
# -----------------------------------------------------------------------------

import json
import os
import subprocess

# Nom du fichier de rapport temporaire. Le point au début le rend "caché"
# sous Linux/Mac (convention), ça évite qu'il traine visuellement.
_REPORT_FILENAME = ".vulnscan-gitleaks-report.json"


def run_gitleaks_scan(target_path: str) -> list[dict]:
    """
    Lance Gitleaks sur le dossier "target_path", via Docker, et retourne
    directement la liste des secrets trouvés (déjà chargée depuis le JSON).
    """
    container_report_path = f"/target/{_REPORT_FILENAME}"
    # "os.path.join" construit un chemin de fichier de façon fiable, en
    # gérant automatiquement les différences entre Windows et Linux/Mac.
    host_report_path = os.path.join(target_path, _REPORT_FILENAME)

    command = [
        "docker", "run", "--rm",
        "-v", f"{target_path}:/target",
        "zricethezav/gitleaks",
        "detect",
        "--no-git",                 # scanne les fichiers tels quels, pas l'historique Git
        "--source", "/target",
        "--report-format", "json",
        "--report-path", container_report_path,
        "--exit-code", "0",         # sans ça, Gitleaks arrêterait le programme "en erreur" dès qu'il trouve un secret
    ]

    subprocess.run(command, capture_output=True, text=True, timeout=300)

    # Si aucun secret n'est trouvé, Gitleaks ne crée parfois aucun fichier.
    # Ce n'est pas une erreur, ça veut juste dire "rien à signaler".
    if not os.path.exists(host_report_path):
        return []

    with open(host_report_path, "r", encoding="utf-8") as f:
        raw_results = json.load(f)

    os.remove(host_report_path)  # on nettoie le fichier temporaire
    return raw_results


def _redact(secret: str) -> str:
    """
    Ne garde que les tout premiers et derniers caractères d'un secret, pour
    éviter de stocker le secret complet en clair dans notre propre base de
    données. Bonne pratique de sécurité, même dans un outil qui sert
    justement à repérer ce genre de fuite.
    """
    if not secret or len(secret) <= 8:
        return "****"
    return f"{secret[:3]}...{secret[-3:]}"


def parse_gitleaks_results(raw_results: list[dict]) -> list[dict]:
    """
    Transforme la liste brute de Gitleaks en dictionnaires compatibles avec
    la table "vulnerabilites".
    """
    findings: list[dict] = []

    for item in raw_results:
        findings.append({
            "title": f"Secret exposé — {item.get('RuleID', 'inconnu')}",
            "description": item.get("Description", ""),
            "scanner_name": "gitleaks",
            "vulnerability_id": None,   # pas de CVE pour un secret : ce n'est pas une faille connue, c'est une fuite
            "file_path": item.get("File"),
            "line_number": item.get("StartLine"),
            "code_snippet": _redact(item.get("Match", "")),
            "raw_severity": "HIGH",     # un secret exposé est presque toujours traité comme grave
            "severity": "high",
            "fix_available": False,
        })

    return findings
