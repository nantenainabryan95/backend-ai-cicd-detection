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
import subprocess  # module Python standard pour lancer une commande externe (ici, docker)


def run_trivy_scan(target_path: str) -> dict:
    """
    Lance Trivy sur le dossier "target_path", via Docker (pas besoin d'installer
    Trivy directement sur votre PC, seulement Docker, que vous avez déjà).

    Retourne le résultat de Trivy déjà transformé en dictionnaire Python
    (json.loads a fait la conversion depuis le texte JSON).
    """
    # "subprocess.run" exécute une commande comme si vous la tapiez vous-même
    # dans un terminal. On lui donne la commande sous forme de LISTE de mots
    # (plutôt qu'une seule chaîne de texte) : c'est la façon recommandée en
    # Python, ça évite des soucis d'espaces ou de guillemets mal interprétés.
    command = [
        "docker", "run", "--rm",
        "-v", f"{target_path}:/target",   # on "monte" votre dossier dans le conteneur
        "aquasec/trivy",
        "fs",                              # "fs" = scanner un système de fichiers (par opposition à une image)
        "--format", "json",
        "--quiet",
        # On exclut les dossiers qui ne contiennent pas VOTRE code, mais du
        # code tiers déjà installé (environnement virtuel, dépendances...).
        # Sans ça, Trivy essaie d'analyser des milliers de fichiers inutiles
        # et peut devenir très lent, voire planter.
        "--skip-dirs", "venv",
        "--skip-dirs", "node_modules",
        "--skip-dirs", "__pycache__",
        "--skip-dirs", ".git",
        "/target",
    ]

    result = subprocess.run(
        command,
        capture_output=True,  # récupère ce que la commande affiche, au lieu de l'afficher directement
        text=True,             # récupère le résultat comme du texte, pas des octets bruts
        timeout=300,           # abandonne si ça prend plus de 5 minutes (sécurité)
    )

    if result.returncode != 0:
        # "raise" déclenche une erreur volontairement, avec un message clair,
        # au lieu de laisser le programme planter sans explication.
        raise RuntimeError(f"Trivy a échoué : {result.stderr}")

    return json.loads(result.stdout)


# Trivy utilise des majuscules (CRITICAL, HIGH...), notre base utilise des
# minuscules (voir FindingSeverity dans models.py). Ce dictionnaire fait la
# correspondance entre les deux.
_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "UNKNOWN": "low",
}


def parse_trivy_results(raw_results: dict) -> list[dict]:
    """
    Transforme le JSON brut de Trivy en une liste de dictionnaires simples,
    un par vulnérabilité trouvée, avec des clés qui correspondent directement
    aux colonnes de la table "vulnerabilites".

    On ne crée pas encore d'objets Finding ici : on reste sur de simples
    dictionnaires, pour que cette fonction reste indépendante de la base de
    données (plus facile à tester, réutilisable ailleurs si besoin).
    """
    findings: list[dict] = []

    # Le JSON de Trivy a la forme :
    # { "Results": [ { "Target": "package-lock.json", "Vulnerabilities": [...] }, ... ] }
    # ".get(..., [])" évite une erreur si la clé n'existe pas (ex: aucune
    # vulnérabilité trouvée dans ce fichier).
    for result in raw_results.get("Results", []):
        file_path = result.get("Target", "")

        for vuln in result.get("Vulnerabilities", []):
            severity_raw = vuln.get("Severity", "UNKNOWN")

            # On essaie de récupérer un score CVSS numérique si Trivy en fournit un.
            # La structure exacte varie selon la source (nvd, redhat...), donc on
            # essaie plusieurs chemins possibles, dans l'ordre de préférence.
            cvss_score = None
            cvss_data = vuln.get("CVSS", {})
            for source in ("nvd", "redhat", "ghsa"):
                score = cvss_data.get(source, {}).get("V3Score")
                if score is not None:
                    cvss_score = score
                    break

            findings.append({
                "title": f"{vuln.get('VulnerabilityID')} — {vuln.get('PkgName')}",
                "description": vuln.get("Description", "")[:2000],  # on limite la longueur, par sécurité
                "scanner_name": "trivy",
                "vulnerability_id": vuln.get("VulnerabilityID"),
                "file_path": file_path,
                "raw_severity": severity_raw,
                "cvss_score": cvss_score,
                "fix_available": bool(vuln.get("FixedVersion")),
                "severity": _SEVERITY_MAP.get(severity_raw, "low"),
            })

    return findings