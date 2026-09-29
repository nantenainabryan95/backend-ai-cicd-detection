# -----------------------------------------------------------------------------
# C'est ICI que se joue l'idée centrale de votre projet : au lieu de trier
# les vulnérabilités par le seul CVSS (ce que font la plupart des outils),
# on combine plusieurs facteurs pour obtenir un score de priorité plus
# proche du risque RÉEL.
#
# On écrit cette fonction de façon "pure" : elle prend des valeurs simples
# en entrée (pas un objet Finding directement), et renvoie un résultat,
# sans toucher à la base de données. Ça la rend facile à tester et à
# comprendre indépendamment du reste de l'application.
# -----------------------------------------------------------------------------


# Score de départ selon la sévérité brute, utilisé UNIQUEMENT quand on n'a
# aucun score CVSS numérique (le cas de Semgrep et Gitleaks, qui ne donnent
# pas de CVSS, seulement un niveau textuel).
_BASELINE_BY_SEVERITY = {
    "critical": 90,
    "high": 70,
    "medium": 45,
    "low": 20,
}


def _epss_adjustment(epss_score: float) -> float:
    """
    Traduit une probabilité EPSS (0 à 1) en un nombre de points à ajouter
    (ou retirer) au score. Le signe "-" veut dire qu'on fait BAISSER le score.
    """
    if epss_score < 0.01:      # moins de 1 % : très improbable
        return -20
    if epss_score < 0.05:      # 1 % à 5 % : improbable
        return -10
    if epss_score < 0.20:      # 5 % à 20 % : neutre, on ne touche pas au score
        return 0
    if epss_score < 0.50:      # 20 % à 50 % : probable
        return 10
    return 20                  # 50 % et plus : très probable


def compute_priority_score(
    cvss_score: float | None,
    epss_score: float | None,
    in_kev: bool,
    is_exposed: bool,
    fallback_severity: str = "low",
) -> tuple[float, str]:
    """
    Calcule le score de priorité (0 à 100) et le niveau de sévérité qui en
    découle, à partir des facteurs disponibles pour un finding.

    Renvoie un TUPLE (score, sévérité) : c'est la façon en Python de
    renvoyer deux valeurs depuis une seule fonction.
    """

    # ---- 1) Score de départ ----
    if cvss_score is not None:
        # Le CVSS va de 0 à 10, on le ramène à une échelle de 0 à 100.
        score = cvss_score * 10
    else:
        # Pas de CVSS (cas Semgrep/Gitleaks) : on part d'une base selon la
        # sévérité déjà déterminée par le scanner lui-même.
        score = _BASELINE_BY_SEVERITY.get(fallback_severity, 20)

    # ---- 2) Le facteur qui change TOUT : exploitation active confirmée ----
    # Si la CISA confirme que cette vulnérabilité est activement exploitée
    # dans de vraies attaques, elle devient quasiment toujours prioritaire,
    # peu importe son score CVSS de départ.
    if in_kev:
        score = max(score, 95)

    # ---- 3) Sinon, on ajuste selon la probabilité d'exploitation (EPSS) ----
    # EPSS peut maintenant faire MONTER ou BAISSER le score. Une faille très
    # grave sur le papier mais quasiment jamais attaquée doit descendre dans
    # la liste, pour ne pas vous faire perdre de temps dessus.
    #
    # Les paliers sont bas volontairement : l'EPSS est très "étalé" (la grande
    # majorité des CVE sont sous 1 %), donc 10 % est déjà considéré comme élevé.
    elif epss_score is not None:
        score += _epss_adjustment(epss_score)

    # ---- 4) Exposition : un service accessible publiquement est plus risqué
    # qu'un service uniquement accessible en interne ----
    if is_exposed:
        score += 10

    # ---- 5) On garde le score dans les bornes 0-100 ----
    score = max(0, min(100, score))

    # ---- 6) On déduit un niveau de sévérité lisible à partir du score final ----
    if score >= 90:
        severity = "critical"
    elif score >= 70:
        severity = "high"
    elif score >= 40:
        severity = "medium"
    else:
        severity = "low"

    return round(score, 1), severity