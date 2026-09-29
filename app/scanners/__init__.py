# Ce dossier regroupera un fichier par scanner (trivy.py, semgrep.py,
# gitleaks.py...). Chacun aura la même forme : une fonction "run(...)" qui
# lance l'outil, et une fonction "parse(...)" qui transforme son résultat
# brut en objets Finding compréhensibles par le reste de l'application.
