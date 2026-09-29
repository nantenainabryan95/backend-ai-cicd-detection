# -----------------------------------------------------------------------------
# EPSS (Exploit Prediction Scoring System) est un service public, maintenu
# par FIRST.org, qui donne, pour un CVE donné, la PROBABILITÉ qu'il soit
# réellement exploité dans les 30 prochains jours (entre 0 et 1). C'est très
# différent du CVSS, qui ne mesure que la gravité technique théorique.
# -----------------------------------------------------------------------------

import requests  # bibliothèque standard pour faire des requêtes HTTP en Python

EPSS_API_URL = "https://api.first.org/data/v1/epss"


def fetch_epss_score(cve_id: str) -> float | None:
    """
    Interroge l'API EPSS pour un CVE précis (ex: "CVE-2024-3094").
    Renvoie un nombre entre 0 et 1, ou None si le CVE est inconnu d'EPSS,
    ou si la requête échoue (pas d'internet, service indisponible...).

    On ne fait JAMAIS planter tout le programme si cet appel échoue : une
    vulnérabilité reste consultable et scorable même sans info EPSS, juste
    avec un score un peu moins précis.
    """
    try:
        response = requests.get(
            EPSS_API_URL,
            params={"cve": cve_id},
            timeout=10,  # on n'attend pas indéfiniment une API externe
        )
        response.raise_for_status()  # déclenche une erreur si le code HTTP n'est pas 200
        data = response.json()

        results = data.get("data", [])
        if not results:
            # Le CVE existe peut-être, mais EPSS n'a pas encore de score pour lui
            # (cas fréquent pour les CVE très récents).
            return None

        # L'API renvoie le score sous forme de texte (ex: "0.94013"), on le
        # convertit en nombre décimal Python.
        return float(results[0]["epss"])

    except (requests.RequestException, KeyError, ValueError, IndexError) as e:
        # On attrape plusieurs types d'erreurs possibles en une fois :
        # - RequestException : pas d'internet, timeout, service en panne...
        # - KeyError/IndexError : réponse reçue mais pas dans le format attendu
        # - ValueError : le texte reçu n'est pas convertible en nombre
        print(f"[EPSS] Impossible de récupérer le score pour {cve_id} : {e}")
        return None
