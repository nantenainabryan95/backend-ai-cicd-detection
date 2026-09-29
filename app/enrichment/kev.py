# -----------------------------------------------------------------------------
# KEV (Known Exploited Vulnerabilities) est un catalogue public tenu par la
# CISA (l'agence de cybersécurité américaine) : il liste les CVE dont on SAIT,
# avec certitude, qu'ils sont activement exploités dans de vraies attaques.
# Être dans cette liste doit faire monter la priorité en flèche, quel que
# soit le CVSS.
# -----------------------------------------------------------------------------

import requests

KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

# On garde le catalogue en mémoire une fois téléchargé, pour ne pas le
# re-télécharger à chaque vulnérabilité (le fichier fait plusieurs Mo).
# "_kev_cache" commence à None : ça veut dire "pas encore chargé".
_kev_cache: set[str] | None = None


def _load_kev_catalog() -> set[str]:
    """
    Télécharge le catalogue KEV une seule fois, et le transforme en un
    "set" (ensemble) des identifiants CVE qu'il contient. Un "set" permet
    de vérifier très rapidement si un CVE y figure, sans parcourir toute
    la liste à chaque fois.
    """
    global _kev_cache  # nécessaire pour MODIFIER une variable définie en dehors de la fonction

    if _kev_cache is not None:
        return _kev_cache

    try:
        response = requests.get(KEV_CATALOG_URL, timeout=15)
        response.raise_for_status()
        data = response.json()

        # Le catalogue a la forme { "vulnerabilities": [ {"cveID": "CVE-..."}, ... ] }
        _kev_cache = {item["cveID"] for item in data.get("vulnerabilities", [])}

    except (requests.RequestException, KeyError, ValueError) as e:
        print(f"[KEV] Impossible de télécharger le catalogue : {e}")
        _kev_cache = set()  # on retombe sur un ensemble vide plutôt que de planter

    return _kev_cache


def is_in_kev(cve_id: str) -> bool:
    """Renvoie True si ce CVE est activement exploité, selon la CISA."""
    if not cve_id:
        return False
    catalog = _load_kev_catalog()
    return cve_id in catalog
