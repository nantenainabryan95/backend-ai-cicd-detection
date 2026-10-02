# -----------------------------------------------------------------------------
# Ce fichier contient ce qui est IDENTIQUE peu importe le fournisseur de LLM
# utilisé (Gemini, Groq, demain Claude ou Ollama) : la question qu'on pose,
# et la façon de vérifier que la réponse est bien formée. Seule la manière
# d'ENVOYER cette question change d'un fournisseur à l'autre (fichiers
# gemini.py, groq.py...).
# -----------------------------------------------------------------------------

PROMPT_TEMPLATE = """Tu es un analyste en cybersécurité. Analyse la vulnérabilité suivante,
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

VALID_VERDICTS = {"vraie_menace", "faux_positif", "incertain"}
VALID_PRIORITIES = {"basse", "moyenne", "elevee", "critique_confirmee"}


def build_prompt(finding_context: dict) -> str:
    """Construit le texte envoyé au LLM à partir des infos d'un finding."""
    return PROMPT_TEMPLATE.format(
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


def validate_result(result: dict) -> dict:
    """
    Vérifie que la réponse du LLM contient bien les bonnes clés, avec des
    valeurs acceptées. Si quelque chose ne va pas, on retombe sur des
    valeurs par défaut prudentes plutôt que de planter tout le programme.
    """
    verdict = str(result.get("verdict", "")).lower()
    if verdict not in VALID_VERDICTS:
        verdict = "incertain"

    priority = str(result.get("adjusted_priority", "")).lower()
    if priority not in VALID_PRIORITIES:
        priority = "moyenne"

    return {
        "verdict": verdict,
        "adjusted_priority": priority,
        "reasoning": result.get("reasoning") or "Aucune explication fournie par le modèle.",
        "suggested_fix": result.get("suggested_fix"),
    }
