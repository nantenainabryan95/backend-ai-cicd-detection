# -----------------------------------------------------------------------------
# Ce fichier appelle l'API Gemini pour qu'elle analyse UNE vulnérabilité et
# nous renvoie un verdict structuré, au format JSON, qu'on peut directement
# enregistrer dans la table "analyses_ia".
# -----------------------------------------------------------------------------

import json
import requests

GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

# On décrit à Gemini EXACTEMENT la forme de réponse qu'on attend. On lui
# demande de répondre uniquement en JSON (voir "response_mime_type" plus
# bas) : ça évite d'avoir à extraire du texte au milieu d'une phrase.
_PROMPT_TEMPLATE = """Tu es un analyste en cybersécurité. Analyse la vulnérabilité suivante,
détectée par un scanner automatique, et réponds UNIQUEMENT avec un objet JSON
respectant exactement cette forme, sans aucun texte autour :

{{
  "verdict": "vraie_menace" ou "faux_positif" ou "incertain",
  "adjusted_priority": "basse" ou "moyenne" ou "elevee" ou "critique_confirmee",
  "reasoning": "explication claire en français, 2 à 4 phrases",
  "suggested_fix": "correctif concret proposé, ou null si non applicable"
}}

Informations sur la vulnérabilité :
- Titre : {title}
- Scanner : {scanner_name}
- Identifiant : {vulnerability_id}
- Description : {description}
- Fichier concerné : {file_path}
- Score CVSS : {cvss_score}
- Score EPSS (probabilité d'exploitation) : {epss_score}
- Présente dans le catalogue CISA KEV (exploitation active confirmée) : {in_kev}
- Extrait de code, si disponible : {code_snippet}
"""


def analyze_finding_with_gemini(finding_context: dict, api_key: str, model: str = "gemini-2.5-flash") -> dict:
    """
    Envoie les informations d'un finding à Gemini, et renvoie un dictionnaire
    avec les clés : verdict, adjusted_priority, reasoning, suggested_fix.

    "finding_context" est un simple dictionnaire (pas un objet Finding
    directement) : ça garde cette fonction indépendante de SQLAlchemy, plus
    facile à tester toute seule.
    """
    prompt = _PROMPT_TEMPLATE.format(
        title=finding_context.get("title", ""),
        scanner_name=finding_context.get("scanner_name", ""),
        vulnerability_id=finding_context.get("vulnerability_id") or "aucun",
        description=finding_context.get("description") or "aucune description",
        file_path=finding_context.get("file_path") or "inconnu",
        cvss_score=finding_context.get("cvss_score") or "non disponible",
        epss_score=finding_context.get("epss_score") or "non disponible",
        in_kev=finding_context.get("in_kev", False),
        code_snippet=finding_context.get("code_snippet") or "non disponible",
    )

    url = GEMINI_API_URL.format(model=model)

    response = requests.post(
        url,
        params={"key": api_key},
        json={
            "contents": [{"parts": [{"text": prompt}]}],
            # On force Gemini à répondre en JSON pur : plus besoin de
            # "nettoyer" du texte autour de la réponse.
            "generationConfig": {"response_mime_type": "application/json"},
        },
        timeout=60,
    )
    response.raise_for_status()  # déclenche une erreur si la clé est invalide, quota dépassé, etc.

    raw = response.json()

    # La vraie réponse du modèle est "cachée" à cet endroit précis de la
    # structure que Gemini renvoie toujours.
    text_content = raw["candidates"][0]["content"]["parts"][0]["text"]
    result = json.loads(text_content)

    return _validate_result(result)


# Valeurs autorisées, pour se protéger si jamais le modèle répond avec une
# valeur légèrement différente de ce qu'on attend (ex: "VRAIE_MENACE" en
# majuscules, ou une faute de frappe).
_VALID_VERDICTS = {"vraie_menace", "faux_positif", "incertain"}
_VALID_PRIORITIES = {"basse", "moyenne", "elevee", "critique_confirmee"}


def _validate_result(result: dict) -> dict:
    """
    Vérifie que la réponse du LLM contient bien les bonnes clés, avec des
    valeurs acceptées. Si quelque chose ne va pas, on retombe sur des
    valeurs par défaut prudentes plutôt que de planter tout le programme.
    """
    verdict = str(result.get("verdict", "")).lower()
    if verdict not in _VALID_VERDICTS:
        verdict = "incertain"

    priority = str(result.get("adjusted_priority", "")).lower()
    if priority not in _VALID_PRIORITIES:
        priority = "moyenne"

    return {
        "verdict": verdict,
        "adjusted_priority": priority,
        "reasoning": result.get("reasoning") or "Aucune explication fournie par le modèle.",
        "suggested_fix": result.get("suggested_fix"),
    }