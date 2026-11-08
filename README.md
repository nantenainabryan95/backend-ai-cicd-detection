# VulnScan — Détection automatisée des vulnérabilités dans une chaîne CI/CD avec IA

VulnScan intègre trois scanners de sécurité dans un pipeline Jenkins, priorise les vulnérabilités avec des données de risque réel (CVSS, EPSS, CISA KEV), les fait analyser par une IA, puis exige une **validation humaine** avant que la décision n'influence le **Quality Gate** qui autorise ou bloque le build.

## Fonctionnalités

- **3 scanners** exécutés via Docker : Trivy (dépendances), Semgrep (code, règles personnalisées), Gitleaks (secrets).
- **Priorisation** : score de 0 à 100 combinant CVSS, probabilité d'exploitation EPSS, présence dans le catalogue CISA KEV et exposition.
- **Analyse IA** (Groq) : verdict (vraie menace, faux positif, incertain), raisonnement, correctif suggéré.
- **Humain dans la boucle** : un analyste approuve ou rejette le verdict de l'IA ; seule cette décision modifie le statut du finding.
- **Quality Gate** : seuils configurables (critiques, hauts), décision enregistrée à chaque build.
- **Interface web** : tableau de bord, findings, analyses, historique des builds, gestion des utilisateurs.
- **API sécurisée** : authentification JWT, rôles, compte de service dédié pour Jenkins.

## Architecture

```mermaid
flowchart LR
    Dev[Développeur] -->|push| GH[(GitHub)]
    GH -->|Jenkinsfile + code du commit| J[Jenkins]
    J -->|1. login compte jenkins| API[API FastAPI]
    J -->|2. scans, scoring, analyse IA, quality-gate| API
    API --> S1[Trivy]
    API --> S2[Semgrep]
    API --> S3[Gitleaks]
    S1 & S2 & S3 -->|lisent le dossier de travail Jenkins| WS[(Workspace du commit)]
    API --> EN[EPSS / CISA KEV]
    API --> LLM[LLM Groq]
    API <--> DB[(PostgreSQL)]
    UI[Interface React] <-->|JWT| API
    Analyste[Analyste / Tech lead] --> UI
```

Le dossier de travail de Jenkins est partagé avec la machine hôte : les scanners lisent exactement le code récupéré à ce build, pas un dossier fixe.

## Pipeline Jenkins

| Étape | Rôle |
|---|---|
| Checkout | Récupère le commit et nettoie le dossier (`git clean`) |
| API disponible ? | Vérifie `/health` |
| Connexion API | Se connecte avec le compte `jenkins` (Credentials `vulnscan-api`) |
| Scan Trivy / Semgrep / Gitleaks | Scanne le code du commit |
| Calcul des scores | Priorise les findings de ce build |
| Analyse IA | Analyse les plus prioritaires (déjà analysés ignorés, quota préservé) |
| Quality Gate | 200 = passé, 422 = build bloqué |

Paramètres du job : `VULNSCAN_API`, `PROJECT_ID`, `TARGET_PATH`, `MAX_AI_ANALYSES`, `MAX_CRITICAL` et `MAX_HIGH` (vides par défaut : les seuils du projet s'appliquent).

## Priorisation et Quality Gate

- **Score** : CVSS × 10 (ou base selon la sévérité pour Semgrep/Gitleaks), ajusté par l'EPSS, porté à 95 minimum si la faille est dans CISA KEV, +10 si exposée.
- **Sévérité** : ≥ 90 critique, ≥ 70 haute, ≥ 40 moyenne, sinon basse.
- **Gate** : le build échoue si le nombre de findings ouverts de ce build dépasse les seuils du projet (réglés dans l'interface, page Projets) ; les paramètres `MAX_CRITICAL` et `MAX_HIGH` du job, s'ils sont renseignés, sont prioritaires. Les statuts `fixed`, `false_positive` et `accepted_risk` ne bloquent pas.
- **Décision humaine** : approuver un verdict « faux positif » débloque le finding ; approuver une « vraie menace » le garde bloquant.
- **Décision de l'analyste** : l'analyste peut aussi fixer lui-même le statut (faux positif, risque accepté, menace confirmée, remis à l'étude) avec une justification obligatoire ; chaque décision est conservée dans un journal (qui, quand, pourquoi).

## Rôles et sécurité

| Action | developer | appsec / tech_lead | admin |
|---|:---:|:---:|:---:|
| Consulter, lancer scans et analyses | ✔ | ✔ | ✔ |
| Valider une analyse IA | ✘ | ✔ | ✔ |
| Décider du statut d'une vulnérabilité (avec justification) | ✘ | ✔ | ✔ |
| Régler les seuils du Quality Gate d'un projet | ✘ | tech_lead ✔, appsec ✘ | ✔ |
| Créer, modifier, supprimer des utilisateurs | ✘ | ✘ | ✔ |

- Toutes les routes exigent un jeton, sauf `/health`, `/` et `/auth/login`.
- Mots de passe hachés (bcrypt) ; l'API refuse de démarrer sans `JWT_SECRET` d'au moins 32 caractères.
- Un administrateur ne peut ni supprimer son compte ni changer son propre rôle.
- Jenkins utilise un compte de service `developer` ; son mot de passe est stocké dans les Credentials Jenkins et n'apparaît pas dans les logs.
- Le fichier `.env` ne doit jamais être versionné.

## Installation

Prérequis : Python 3, Node.js, Docker Desktop, Jenkins.

1. **Base de données**
   ```bash
   docker compose up -d postgres
   ```
2. **Backend**
   ```bash
   python -m venv venv
   source venv/Scripts/activate        # Git Bash sous Windows
   pip install -r requirements.txt
   ```
3. **Fichier `.env`** à la racine :
   ```
   DATABASE_URL=postgresql://vulnscan:vulnscan@localhost:5432/vulnscan
   LLM_PROVIDER=groq
   LLM_API_KEY=<votre clé Groq>
   LLM_MODEL=<modèle Groq choisi>
   JWT_SECRET=<généré ci-dessous>
   ```
   ```bash
   python -c "import secrets; print(secrets.token_hex(32))"
   ```
4. **Tables et comptes**
   ```bash
   python -m app.init_db
   python -m app.create_user <nom> <mot_de_passe> admin
   python -m app.create_user jenkins <mot_de_passe> developer
   ```
5. **Lancement**
   ```bash
   uvicorn app.main:app --reload       # API sur http://localhost:8000 (docs sur /docs)
   cd frontend && npm install && npm run dev   # interface sur http://localhost:5173
   ```
6. **Jenkins**
   - Credentials : type *Username with password*, ID `vulnscan-api`, compte `jenkins`.
   - Job : *Pipeline script from SCM*, Git, branche `*/master`, Script Path `Jenkinsfile`.
   - Le dossier `jenkins_home` du conteneur doit être monté sur un dossier de la machine ; renseigner `TARGET_PATH` avec le chemin Windows de `workspace/<job>` (avec des `/`).

## Structure du projet

```
app/            API FastAPI (routes, modèles, scoring, auth)
app/scanners/   Trivy, Semgrep (règles personnalisées), Gitleaks
app/enrichment/ EPSS et CISA KEV
app/llm/        Analyse IA
frontend/       Interface React + TypeScript (Vite)
Jenkinsfile     Pipeline CI/CD
docker-compose.yml   PostgreSQL
```

## Captures d'écran

*(à compléter : tableau de bord, détail d'un finding avec analyse IA, validation humaine, build Jenkins bloqué puis réussi)*

## Limites connues

- Chemins d'exécution propres à une machine Windows avec Docker Desktop ; `TARGET_PATH` est à adapter ailleurs.
- Un finding est identifié par scanner, titre, fichier et ligne : un décalage de ligne le fait considérer comme nouveau.
- Les scans durent plusieurs minutes (exécution des scanners dans Docker).
- Pas de limitation des tentatives de connexion.