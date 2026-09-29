# Ce dossier contient un fichier par fournisseur de LLM (gemini.py, puis
# plus tard ollama.py, claude.py...). Chacun expose UNE fonction avec la
# même signature : analyser un finding et renvoyer un dictionnaire avec les
# mêmes clés. Ça permet de changer de fournisseur en changeant une seule
# ligne d'import dans main.py, sans toucher au reste de l'application.
