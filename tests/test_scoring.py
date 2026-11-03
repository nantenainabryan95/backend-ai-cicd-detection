"""
Tests du score de priorité (app/scoring.py).

Ce module ne dépend ni de la base de données ni de l'API : on appelle la
fonction avec des valeurs et on vérifie le résultat. Chaque test vérifie une
règle de calcul précise.

Lancer :  python -m pytest -v
"""

from app.scoring import _epss_adjustment, compute_priority_score


# ---------------------------------------------------------------------------
# Ajustement lié à la probabilité d'exploitation (EPSS)
# ---------------------------------------------------------------------------

def test_epss_tres_improbable_fait_baisser_le_score():
    assert _epss_adjustment(0.0099) == -20


def test_epss_paliers_aux_limites():
    # Chaque palier commence exactement à sa borne basse.
    assert _epss_adjustment(0.01) == -10
    assert _epss_adjustment(0.05) == 0
    assert _epss_adjustment(0.20) == 10
    assert _epss_adjustment(0.50) == 20


# ---------------------------------------------------------------------------
# Score de départ
# ---------------------------------------------------------------------------

def test_cvss_est_ramene_sur_100():
    # CVSS 6.0, EPSS neutre (10 %) : 6.0 x 10 = 60, aucun ajustement.
    score, severity = compute_priority_score(6.0, 0.10, False, False)
    assert score == 60.0
    assert severity == "medium"


def test_sans_cvss_on_part_de_la_severite_du_scanner():
    # Cas de Semgrep et Gitleaks : pas de CVSS, seulement un niveau textuel.
    assert compute_priority_score(None, None, False, False, "high") == (70.0, "high")
    assert compute_priority_score(None, None, False, False, "low") == (20.0, "low")
    assert compute_priority_score(None, None, False, False, "critical") == (90.0, "critical")


# ---------------------------------------------------------------------------
# Les trois facteurs qui font bouger le score
# ---------------------------------------------------------------------------

def test_faille_grave_mais_jamais_attaquee_descend():
    # Le cas des deux CVE de PyJWT du projet : CVSS 9.1 mais EPSS très faible.
    # 91 - 20 = 71 : la faille reste "high" et ne passe plus en "critical".
    score, severity = compute_priority_score(9.1, 0.001, False, False)
    assert score == 71.0
    assert severity == "high"


def test_exploitation_probable_fait_monter_le_score():
    # 9.1 x 10 = 91, plus 20 points (EPSS de 60 %), plafonné à 100.
    score, severity = compute_priority_score(9.1, 0.60, False, False)
    assert score == 100.0
    assert severity == "critical"


def test_faille_du_catalogue_kev_devient_critique():
    # Un CVSS moyen (5.0) mais une exploitation confirmée par la CISA : 95 au minimum.
    score, severity = compute_priority_score(5.0, None, True, False)
    assert score == 95.0
    assert severity == "critical"


def test_kev_ignore_l_epss():
    # Quand la faille est dans le catalogue KEV, l'EPSS n'est pas utilisé,
    # même s'il est très faible.
    score, _ = compute_priority_score(5.0, 0.001, True, False)
    assert score == 95.0


def test_exposition_ajoute_dix_points():
    # 60 (CVSS 6.0, EPSS neutre) + 10 (composant exposé) = 70 : passe en "high".
    score, severity = compute_priority_score(6.0, 0.10, False, True)
    assert score == 70.0
    assert severity == "high"


# ---------------------------------------------------------------------------
# Bornes et seuils de sévérité
# ---------------------------------------------------------------------------

def test_le_score_ne_depasse_jamais_100():
    score, _ = compute_priority_score(10.0, None, True, True)
    assert score == 100.0


def test_le_score_ne_descend_jamais_sous_0():
    # 1.0 x 10 = 10, moins 20 (EPSS très faible) = -10, ramené à 0.
    score, severity = compute_priority_score(1.0, 0.001, False, False)
    assert score == 0.0
    assert severity == "low"


def test_seuils_de_severite():
    # 90 et plus : critical ; 70 à 89 : high ; 40 à 69 : medium ; en dessous : low.
    assert compute_priority_score(9.0, 0.10, False, False)[1] == "critical"
    assert compute_priority_score(8.9, 0.10, False, False)[1] == "high"
    assert compute_priority_score(7.0, 0.10, False, False)[1] == "high"
    assert compute_priority_score(6.9, 0.10, False, False)[1] == "medium"
    assert compute_priority_score(4.0, 0.10, False, False)[1] == "medium"
    assert compute_priority_score(3.9, 0.10, False, False)[1] == "low"
