"""
Tests du Quality Gate (GET /projects/{id}/quality-gate).

Règles vérifiées :
  - seuils par défaut : 0 critique, 5 hautes ;
  - le gate échoue (422) quand un nombre de vulnérabilités dépasse le seuil ;
  - les statuts FIXED, FALSE_POSITIVE et ACCEPTED_RISK ne bloquent plus ;
  - le paramètre ?build=N limite le calcul à un build ;
  - les seuils enregistrés pour le projet s'appliquent, et un seuil passé dans
    l'URL les remplace.
"""

import pytest


def gate(client, headers, project, **params):
    return client.get(
        f"/projects/{project.id}/quality-gate", params=params, headers=headers
    )


# ---------------------------------------------------------------------------
# Seuils par défaut
# ---------------------------------------------------------------------------

def test_seuils_par_defaut(client, auth, project):
    reponse = client.get(
        f"/projects/{project.id}/quality-gate/settings", headers=auth("developer")
    )
    corps = reponse.json()
    assert corps["max_critical"] == 0
    assert corps["max_high"] == 5
    assert corps["is_default"] is True


def test_projet_sans_vulnerabilite_passe(client, auth, project):
    reponse = gate(client, auth("developer"), project)
    assert reponse.status_code == 200
    assert reponse.json()["passed"] is True


def test_une_critique_bloque_avec_les_seuils_par_defaut(client, auth, project, make_finding):
    make_finding("critical")
    reponse = gate(client, auth("developer"), project)
    assert reponse.status_code == 422
    detail = reponse.json()["detail"]
    assert detail["passed"] is False
    assert detail["blocking_findings"] == 1


def test_cinq_hautes_passent_et_six_bloquent(client, auth, project, make_finding):
    for _ in range(5):
        make_finding("high")
    assert gate(client, auth("developer"), project).status_code == 200

    make_finding("high")
    assert gate(client, auth("developer"), project).status_code == 422


def test_les_severites_moyenne_et_basse_ne_bloquent_jamais(client, auth, project, make_finding):
    for _ in range(10):
        make_finding("medium")
        make_finding("low")
    assert gate(client, auth("developer"), project).status_code == 200


# ---------------------------------------------------------------------------
# Statuts qui ne bloquent plus
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("statut", ["fixed", "false_positive", "accepted_risk"])
def test_statuts_qui_ne_bloquent_plus(client, auth, project, make_finding, statut):
    make_finding("critical", status=statut)
    assert gate(client, auth("developer"), project).status_code == 200


@pytest.mark.parametrize("statut", ["new", "triaging", "confirmed", "in_progress"])
def test_statuts_qui_bloquent_encore(client, auth, project, make_finding, statut):
    make_finding("critical", status=statut)
    assert gate(client, auth("developer"), project).status_code == 422


# ---------------------------------------------------------------------------
# Filtre par build
# ---------------------------------------------------------------------------

def test_le_gate_ne_regarde_que_le_build_demande(client, auth, project, make_finding):
    make_finding("critical", build=1)   # vue seulement au build 1
    make_finding("low", build=2)

    assert gate(client, auth("developer"), project, build=1).status_code == 422
    assert gate(client, auth("developer"), project, build=2).status_code == 200


# ---------------------------------------------------------------------------
# Seuils réglés par le projet et seuils passés dans l'URL
# ---------------------------------------------------------------------------

def test_seuil_enregistre_pour_le_projet_est_applique(client, auth, project, make_finding):
    make_finding("critical")
    assert gate(client, auth("developer"), project).status_code == 422

    client.put(
        f"/projects/{project.id}/quality-gate/settings",
        json={"max_critical": 1, "max_high": 5},
        headers=auth("tech_lead"),
    )
    assert gate(client, auth("developer"), project).status_code == 200


def test_seuil_dans_l_url_remplace_celui_du_projet(client, auth, project, make_finding):
    make_finding("critical")
    reponse = gate(client, auth("developer"), project, max_critical=2)
    assert reponse.status_code == 200


def test_reglage_des_seuils_est_signe_par_son_auteur(client, auth, project):
    client.put(
        f"/projects/{project.id}/quality-gate/settings",
        json={"max_critical": 2, "max_high": 8},
        headers=auth("tech_lead"),
    )
    corps = client.get(
        f"/projects/{project.id}/quality-gate/settings", headers=auth("developer")
    ).json()
    assert corps["max_critical"] == 2
    assert corps["max_high"] == 8
    assert corps["is_default"] is False
    assert corps["updated_by"] == "user_tech_lead"


@pytest.mark.parametrize("valeur", [-1, 1001])
def test_seuils_hors_limites_sont_refuses(client, auth, project, valeur):
    reponse = client.put(
        f"/projects/{project.id}/quality-gate/settings",
        json={"max_critical": valeur, "max_high": 5},
        headers=auth("tech_lead"),
    )
    assert reponse.status_code == 422


def test_quality_gate_projet_inconnu(client, auth):
    reponse = client.get("/projects/9999/quality-gate", headers=auth("developer"))
    assert reponse.status_code == 404
