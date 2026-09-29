# VulnScan — étape 1 : le projet démarre

## Structure

```
vulnscan/
├── app/
│   ├── __init__.py     -> dit à Python que "app" est un module
│   ├── config.py        -> lit les variables du fichier .env
│   ├── database.py      -> connexion à PostgreSQL
│   └── main.py           -> l'application FastAPI, le point de départ
├── requirements.txt      -> liste des bibliothèques Python nécessaires
└── .env.example           -> à copier en .env
```

## Pour lancer le projet chez vous

1. Créez un environnement virtuel (une "boîte" isolée pour les bibliothèques
   Python de ce projet, pour ne pas mélanger avec d'autres projets) :
   ```
   python3 -m venv venv
   source venv/bin/activate        # sur Windows : venv\Scripts\activate
   ```

2. Installez les dépendances :
   ```
   pip install -r requirements.txt
   ```

3. Copiez le fichier d'environnement :
   ```
   cp .env.example .env
   ```

4. Lancez le serveur :
   ```
   uvicorn app.main:app --reload
   ```
   `--reload` redémarre automatiquement le serveur à chaque fois que vous
   modifiez un fichier — très utile pendant le développement.

5. Ouvrez votre navigateur sur :
   - http://localhost:8000/health → doit afficher `{"status":"ok",...}`
   - http://localhost:8000/docs → documentation interactive générée
     automatiquement par FastAPI (vous pouvez tester chaque route ici,
     sans écrire de code)

## Quelques bases Python utiles pour lire ce code

- **L'indentation fait partie du langage.** Contrairement à d'autres langages
  qui utilisent des accolades `{ }`, en Python c'est l'espacement (4 espaces
  par niveau, en général) qui délimite un bloc de code (le contenu d'une
  fonction, d'un `if`, etc.). Une mauvaise indentation provoque une erreur.

- **`def nom_de_fonction():`** définit une fonction. Le code qui lui
  appartient est indenté juste en dessous.

- **`@quelque_chose`** juste au-dessus d'une fonction est un "décorateur" :
  ça enrichit la fonction avec un comportement supplémentaire, sans changer
  son code. Dans FastAPI, `@app.get("/health")` transforme une fonction
  normale en route HTTP.

- **`from app.config import settings`** importe un objet précis (`settings`)
  depuis un autre fichier (`app/config.py`). C'est l'équivalent d'un `import`
  ou d'un `require` dans d'autres langages.

- **`class MaClasse:`** définit une classe, comme dans la plupart des
  langages orientés objet.

## Prochaine étape

À l'étape 2, on va définir le modèle de données : les tables `Project`,
`Finding`, `User`, en Python avec SQLAlchemy, et les créer réellement dans
PostgreSQL.
