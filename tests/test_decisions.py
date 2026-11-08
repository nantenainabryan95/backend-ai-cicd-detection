"""
Tests des décisions de l'analyste.

Règles vérifiées :
  - PATCH /findings/{id}/decision change le statut et exige une justification
    d'au moins 5 caractères ;
  - faux_positif et risque_accepte débloquent le Quality Gate, confirme et rouvert
    continuent de le bloquer ;
  - chaque décision est journalisée (qui, quand, pourquoi, ancien statut) ;
  - la validation humaine d'une analyse IA (PATCH /analyses/{id}/review) se
    répercute sur le statut du finding.
"""

import pytest

from app import models


def decider(client, headers, finding, decision="faux_positif", reason="Justification de test"):
    return client.patch(
        f"/findings/{finding.id}/decision",
        json={"decision": decision, "reason": reason},
        headers=headers,
    )


# ---------------------------------------------------------------------------
# Effet de chaque décision sur le statut
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("decision,statut_attendu", [
    ("faux_positif", models.FindingStatus.FALSE_POSITIVE),
    ("risque_accepte", models.FindingStatus.ACCEPTED_RISK),
    ("confirme", models.FindingStatus.CONFIRMED),
    ("rouvert", models.FindingStatus.NEW),
])
def test_chaque_decision_donne_le_bon_statut(
    client, auth, db_session, make_finding, decision, statut_attendu
):
    finding = make_finding("critical", status="triaging")
    assert decider(client, auth("appsec"), finding, decision).status_code == 200
    db_session.refresh(finding)
    assert finding.status == statut_attendu


def test_faux_positif_debloque_le_quality_gate(client, auth, project, make_finding):
    finding = make_finding("critical")
    url = f"/projects/{project.id}/quality-gate"
    assert client.get(url, headers=auth("appsec")).status_code == 422

    decider(client, auth("appsec"), finding, "faux_positif")
    assert client.get(url, headers=auth("appsec")).status_code == 200


def test_confirme_continue_de_bloquer(client, auth, project, make_finding):
    finding = make_finding("critical")
    decider(client, auth("appsec"), finding, "confirme")
    assert client.get(f"/projects/{project.id}/quality-gate", headers=auth("appsec")).status_code == 422


def test_rouvrir_une_vulnerabilite_la_remet_dans_le_gate(client, auth, project, make_finding):
    finding = make_finding("critical", status="false_positive")
    url = f"/projects/{project.id}/quality-gate"
    assert client.get(url, headers=auth("appsec")).status_code == 200

    decider(client, auth("appsec"), finding, "rouvert")
    assert client.get(url, headers=auth("appsec")).status_code == 422


# ---------------------------------------------------------------------------
# Contrôles de saisie
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("justification", ["", "    ", "abc", "  ab  "])
def test_justification_trop_courte_est_refusee(client, auth, make_finding, justification):
    finding = make_finding()
    reponse = decider(client, auth("appsec"), finding, reason=justification)
    assert reponse.status_code == 422


def test_decision_inconnue_est_refusee(client, auth, make_finding):
    finding = make_finding()
    assert decider(client, auth("appsec"), finding, decision="n_importe_quoi").status_code == 400


def test_decision_sur_vulnerabilite_inexistante(client, auth):
    reponse = client.patch(
        "/findings/9999/decision",
        json={"decision": "faux_positif", "reason": "Justification de test"},
        headers=auth("appsec"),
    )
    assert reponse.status_code == 404


def test_decision_refusee_ne_modifie_pas_le_statut(client, auth, db_session, make_finding):
    finding = make_finding("critical", status="new")
    decider(client, auth("developer"), finding)          # 403 : rôle non autorisé
    decider(client, auth("appsec"), finding, reason="x") # 422 : justification trop courte
    db_session.refresh(finding)
    assert finding.status == models.FindingStatus.NEW


# ---------------------------------------------------------------------------
# Journal des décisions
# ---------------------------------------------------------------------------

def test_la_decision_est_journalisee(client, auth, make_finding):
    finding = make_finding("critical", status="triaging")
    decider(client, auth("appsec"), finding, "faux_positif", "Aucun appel depuis l'extérieur")

    journal = client.get(f"/findings/{finding.id}/decisions", headers=auth("developer")).json()
    assert len(journal) == 1
    assert journal[0]["decision"] == "faux_positif"
    assert journal[0]["reason"] == "Aucun appel depuis l'extérieur"
    assert journal[0]["previous_status"] == "triaging"
    assert journal[0]["decided_by_name"] == "user_appsec"


def test_le_journal_garde_toutes_les_decisions_la_plus_recente_en_premier(client, auth, make_finding):
    finding = make_finding("critical")
    decider(client, auth("appsec"), finding, "faux_positif", "Première décision")
    decider(client, auth("appsec"), finding, "rouvert", "Seconde décision")

    journal = client.get(f"/findings/{finding.id}/decisions", headers=auth("appsec")).json()
    assert [ligne["decision"] for ligne in journal] == ["rouvert", "faux_positif"]
    assert journal[0]["previous_status"] == "false_positive"


# ---------------------------------------------------------------------------
# Validation humaine d'un verdict de l'IA
# ---------------------------------------------------------------------------

def creer_analyse(db_session, finding, verdict):
    analyse = models.AIAnalysis(
        finding_id=finding.id,
        llm_provider="test",
        ai_model_name="modele-de-test",
        ai_verdict=verdict,
        ai_reasoning="Raisonnement de test",
    )
    db_session.add(analyse)
    db_session.commit()
    return analyse


def valider(client, headers, analyse, statut):
    return client.patch(
        f"/analyses/{analyse.id}/review", json={"human_status": statut}, headers=headers
    )


def test_approuver_un_faux_positif_de_l_ia_debloque_le_finding(client, auth, db_session, make_finding):
    finding = make_finding("critical")
    analyse = creer_analyse(db_session, finding, models.AIVerdict.FAUX_POSITIF)

    assert valider(client, auth("appsec"), analyse, "approuve").status_code == 200
    db_session.refresh(finding)
    assert finding.status == models.FindingStatus.FALSE_POSITIVE


def test_approuver_une_vraie_menace_confirme_le_finding(client, auth, db_session, make_finding):
    finding = make_finding("critical")
    analyse = creer_analyse(db_session, finding, models.AIVerdict.VRAIE_MENACE)

    valider(client, auth("appsec"), analyse, "approuve")
    db_session.refresh(finding)
    assert finding.status == models.FindingStatus.CONFIRMED


def test_rejeter_le_verdict_remet_le_finding_a_new(client, auth, db_session, make_finding):
    finding = make_finding("critical", status="false_positive")
    analyse = creer_analyse(db_session, finding, models.AIVerdict.FAUX_POSITIF)

    valider(client, auth("appsec"), analyse, "rejete")
    db_session.refresh(finding)
    assert finding.status == models.FindingStatus.NEW


def test_un_developpeur_ne_peut_pas_valider_une_analyse(client, auth, db_session, make_finding):
    finding = make_finding("critical")
    analyse = creer_analyse(db_session, finding, models.AIVerdict.FAUX_POSITIF)

    assert valider(client, auth("developer"), analyse, "approuve").status_code == 403
    db_session.refresh(finding)
    assert finding.status == models.FindingStatus.NEW


def test_statut_de_validation_invalide(client, auth, db_session, make_finding):
    finding = make_finding("critical")
    analyse = creer_analyse(db_session, finding, models.AIVerdict.FAUX_POSITIF)
    assert valider(client, auth("appsec"), analyse, "peut_etre").status_code == 400
