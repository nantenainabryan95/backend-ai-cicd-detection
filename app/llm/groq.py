import json
import requests

from app.llm.common import build_prompt, validate_result


GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"


def analyze_finding_with_groq(
    finding_context: dict,
    api_key: str,
    model: str,
) -> dict:
    """
    Analyse une vulnérabilité avec un modèle disponible via l'API Groq.

    Args:
        finding_context: Informations concernant la vulnérabilité.
        api_key: Clé API Groq.
        model: Nom du modèle Groq à utiliser.

    Returns:
        Résultat JSON validé par validate_result().

    Raises:
        requests.exceptions.RequestException:
            Si l'API Groq retourne une erreur HTTP ou devient inaccessible.
        ValueError:
            Si la réponse de Groq ne contient pas les données attendues.
        json.JSONDecodeError:
            Si le modèle retourne un contenu qui n'est pas un JSON valide.
    """

    # Construction du prompt à partir des informations
    # de la vulnérabilité.
    prompt = build_prompt(finding_context)

    # Appel de l'API Groq
    response = requests.post(
        GROQ_API_URL,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        json={
            "model": model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            "response_format": {
                "type": "json_object"
            },
        },
        timeout=60,
    )

    # Si Groq retourne une erreur, on affiche les détails
    # dans le terminal pour faciliter le diagnostic.
    if not response.ok:
        print("========== ERREUR GROQ ==========")
        print("Status code :", response.status_code)
        print("Response :", response.text)
        print("=================================")

    # Déclenche une exception si le statut HTTP n'est pas 2xx.
    response.raise_for_status()

    # Conversion de la réponse Groq en dictionnaire Python.
    raw = response.json()

    # Vérification de la structure de la réponse.
    try:
        text_content = raw["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise ValueError(
            "Réponse Groq invalide : le contenu de l'analyse "
            "est introuvable dans la réponse API."
        ) from exc

    # Conversion du JSON retourné par le modèle en dictionnaire Python.
    try:
        result = json.loads(text_content)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "Le modèle Groq a retourné un contenu qui n'est pas "
            "un JSON valide."
        ) from exc

    # Validation du résultat selon le format attendu
    # par ton application.
    return validate_result(result)