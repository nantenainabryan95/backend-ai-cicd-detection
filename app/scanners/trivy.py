# -----------------------------------------------------------------------------
# Ce fichier fait deux choses :
#  1) run_trivy_scan(...)   -> lance Trivy (via Docker) sur un dossier de code,
#                              récupère son résultat brut au format JSON.
#  2) parse_trivy_results(...) -> transforme ce JSON brut en une liste de
#                              dictionnaires Python, au format attendu par
#                              notre table "vulnerabilites".
#
# On sépare volontairement "lancer l'outil" et "comprendre son résultat" :
# ça permet de tester la fonction parse() toute seule, avec un exemple de
# JSON, sans avoir besoin de relancer un vrai scan à chaque fois.
# -----------------------------------------------------------------------------

import json
import subprocess


# -----------------------------------------------------------------------------
# Mise à jour de la base de vulnérabilités de Trivy.
#
#   False (par défaut) : Trivy vérifie et télécharge une base plus récente si
#                        besoin. Il faut alors un accès Internet correct.
#   True               : Trivy utilise UNIQUEMENT la base déjà présente dans le
#                        volume "trivy-cache". Les scans sont rapides et ne
#                        dépendent plus du réseau, mais la base vieillit.
#                        À n'activer que si la base est déjà en cache
#                        (sinon Trivy échoue au premier scan).
# -----------------------------------------------------------------------------
SKIP_DB_UPDATE = False


def run_trivy_scan(target_path: str) -> dict:
    """
    Lance Trivy sur le dossier "target_path", via Docker.

    Docker doit être installé et démarré sur la machine.

    Retourne le résultat brut de Trivy sous forme de dictionnaire Python.
    """

    command = [
        "docker",
        "run",
        "--rm",

        # Monte le dossier à analyser dans le conteneur Trivy.
        "-v",
        f"{target_path}:/target",

        # Volume nommé pour conserver le cache de Trivy entre les scans.
        "-v",
        "trivy-cache:/root/.cache/trivy",

        "aquasec/trivy",

        # Scan d'un système de fichiers.
        "fs",

        # Format JSON pour pouvoir traiter le résultat en Python.
        "--format",
        "json",

        "--quiet",

        # Seules les vulnérabilités nous intéressent ici : les secrets sont
        # déjà détectés par Gitleaks. Ça accélère aussi le scan.
        "--scanners",
        "vuln",

        # Dépôt utilisé pour la base de vulnérabilités.
        "--db-repository",
        "ghcr.io/aquasecurity/trivy-db",

        # Timeout interne de Trivy.
        "--timeout",
        "9m",

        # Dossiers à ignorer.
        "--skip-dirs",
        "venv",

        "--skip-dirs",
        "node_modules",

        "--skip-dirs",
        "frontend",

        "--skip-dirs",
        "__pycache__",

        "--skip-dirs",
        ".git",
    ]

    # Option : ne pas retélécharger la base (voir SKIP_DB_UPDATE plus haut).
    if SKIP_DB_UPDATE:
        command += ["--skip-db-update", "--skip-java-db-update"]

    # Dossier monté dans le conteneur (doit rester le DERNIER argument).
    command.append("/target")

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,

        # CORRECTIF : Trivy écrit sa sortie en UTF-8. Sans ces deux lignes,
        # Python décode avec l'encodage de Windows (cp1252) : un guillemet
        # typographique dans la description d'une vulnérabilité fait échouer
        # la lecture, et result.stdout vaut None
        # ("the JSON object must be str, bytes or bytearray, not NoneType").
        encoding="utf-8",
        errors="replace",   # un caractère illisible devient "?" au lieu de planter

        timeout=600,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Trivy a échoué : {result.stderr}"
        )

    if not result.stdout:
        raise RuntimeError(
            "Trivy n'a rien renvoyé sur sa sortie standard. "
            f"Détail : {result.stderr}"
        )

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            "Trivy a terminé correctement mais son résultat "
            "n'est pas un JSON valide."
        ) from exc


# -----------------------------------------------------------------------------
# Correspondance entre les niveaux Trivy et les valeurs de notre base.
# -----------------------------------------------------------------------------

_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "low",
}


def parse_trivy_results(raw_results: dict) -> list[dict]:
    """
    Transforme le JSON brut de Trivy en une liste de dictionnaires.

    Chaque dictionnaire correspond à une vulnérabilité et contient les
    informations nécessaires pour créer un objet Finding en base de données.

    Exemple de structure Trivy :

    {
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-12345",
                        "PkgName": "example",
                        "Severity": "HIGH",
                        ...
                    }
                ]
            }
        ]
    }
    """

    findings: list[dict] = []

    # Parcours des résultats retournés par Trivy.
    for result in raw_results.get("Results", []):

        # Fichier ou cible analysée.
        file_path = result.get("Target", "")

        # Parcours des vulnérabilités trouvées dans cette cible.
        # ("or []" : Trivy peut renvoyer null quand il n'y a rien.)
        for vuln in result.get("Vulnerabilities") or []:

            # Niveau de sévérité brut fourni par Trivy.
            severity_raw = vuln.get("Severity", "UNKNOWN")

            # -----------------------------------------------------------------
            # Récupération du score CVSS.
            # -----------------------------------------------------------------

            cvss_score = None

            cvss_data = vuln.get("CVSS", {})

            # Les données CVSS peuvent provenir de différentes sources.
            for source in ("nvd", "redhat", "ghsa"):

                source_data = cvss_data.get(source, {})

                score = source_data.get("V3Score")

                if score is not None:
                    cvss_score = score
                    break

            # -----------------------------------------------------------------
            # Construction du finding.
            # -----------------------------------------------------------------

            findings.append(
                {
                    "title": (
                        f"{vuln.get('VulnerabilityID')} "
                        f"— {vuln.get('PkgName')}"
                    ),

                    "description": (
                        vuln.get("Description", "")[:2000]
                    ),

                    "scanner_name": "trivy",

                    "vulnerability_id": (
                        vuln.get("VulnerabilityID")
                    ),

                    "file_path": file_path,

                    "raw_severity": severity_raw,

                    "cvss_score": cvss_score,

                    "fix_available": bool(
                        vuln.get("FixedVersion")
                    ),

                    "severity": _SEVERITY_MAP.get(
                        severity_raw,
                        "low",
                    ),
                }
            )

    return findings