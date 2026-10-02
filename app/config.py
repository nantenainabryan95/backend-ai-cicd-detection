# -----------------------------------------------------------------------------
# Ce fichier centralise la configuration de l'application : tout ce qui peut
# changer selon l'environnement (mot de passe de la base, clé API, etc.)
# se règle dans le fichier ".env", jamais écrit "en dur" dans le code.
# -----------------------------------------------------------------------------

# "BaseSettings" est une classe fournie par pydantic-settings : elle sait lire
# automatiquement les variables du fichier .env et les valider (types corrects,
# valeurs obligatoires présentes, etc.)
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # En Python, on déclare une variable de classe avec juste "nom: type".
    # Ici, chaque attribut correspond à une variable attendue dans le .env.
    database_url: str = "postgresql://vulnscan:vulnscan@localhost:5432/vulnscan"
    llm_provider: str = "groq"
    llm_api_key: str = ""
    llm_model: str = "llama-3.3-70b-versatile"
    jwt_secret: str = "change-me"

    # Cette classe interne dit à pydantic où aller chercher le fichier .env
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


# On crée UNE SEULE instance de Settings, réutilisée partout dans le projet.
# C'est un pattern courant en Python : au lieu de relire le .env à chaque fois,
# on le lit une fois au démarrage et on réutilise cet objet.
settings = Settings()