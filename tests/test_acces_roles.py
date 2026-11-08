"""
Tests de l'authentification et des droits par rôle.

Règles vérifiées (voir app/main.py) :
  - toute route protégée exige un jeton valide (401 sinon) ;
  - créer un utilisateur : admin seulement ;
  - décider du sort d'une vulnérabilité : admin, appsec, tech_lead ;
  - régler les seuils du Quality Gate : admin, tech_lead.
"""

import pytest

DECISION = {"decision": "faux_positif", "reason": "Cas de test justifié"}
SEUILS = {"max_critical": 1, "max_high": 3}
NOUVEAU_COMPTE = {
    "username": "nouveau",
    "email": "nouveau@test.local",
    "password": "motdepasse123",
    "role": "developer",
}
TOUS_LES_ROLES = ["developer", "appsec", "tech_lead", "admin"]


# ---------------------------------------------------------------------------
# Authentification
# ---------------------------------------------------------------------------

def test_route_protegee_sans_jeton_est_refusee(client):
    assert client.get("/projects").status_code == 401


def test_jeton_invalide_est_refuse(client):
    reponse = client.get("/projects", headers={"Authorization": "Bearer faux.jeton.ici"})
    assert reponse.status_code == 401


def test_connexion_avec_bon_mot_de_passe_donne_un_jeton(client, make_user):
    make_user("developer")
    reponse = client.post(
        "/auth/login", data={"username": "user_developer", "password": "motdepasse123"}
    )
    assert reponse.status_code == 200
    assert reponse.json()["access_token"]


def test_connexion_avec_mauvais_mot_de_passe_est_refusee(client, make_user):
    make_user("developer")
    reponse = client.post(
        "/auth/login", data={"username": "user_developer", "password": "mauvais"}
    )
    assert reponse.status_code == 401


def test_connexion_utilisateur_inconnu_meme_message_que_mauvais_mot_de_passe(client, make_user):
    # Le message ne doit pas révéler quels noms d'utilisateur existent.
    make_user("developer")
    inconnu = client.post("/auth/login", data={"username": "personne", "password": "x"})
    mauvais = client.post("/auth/login", data={"username": "user_developer", "password": "x"})
    assert inconnu.status_code == mauvais.status_code == 401
    assert inconnu.json() == mauvais.json()


# ---------------------------------------------------------------------------
# Création d'utilisateurs : admin seulement
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("role", ["developer", "appsec", "tech_lead"])
def test_seul_l_admin_cree_des_utilisateurs_refus(client, auth, role):
    reponse = client.post("/users", json=NOUVEAU_COMPTE, headers=auth(role))
    assert reponse.status_code == 403


def test_seul_l_admin_cree_des_utilisateurs_succes(client, auth):
    reponse = client.post("/users", json=NOUVEAU_COMPTE, headers=auth("admin"))
    assert reponse.status_code in (200, 201)
    assert reponse.json()["role"] == "developer"


# ---------------------------------------------------------------------------
# Décision sur une vulnérabilité : admin, appsec, tech_lead
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("role,attendu", [
    ("developer", 403),
    ("appsec", 200),
    ("tech_lead", 200),
    ("admin", 200),
])
def test_droit_de_decision_par_role(client, auth, make_finding, role, attendu):
    finding = make_finding()
    reponse = client.patch(
        f"/findings/{finding.id}/decision", json=DECISION, headers=auth(role)
    )
    assert reponse.status_code == attendu


# ---------------------------------------------------------------------------
# Seuils du Quality Gate : admin, tech_lead
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("role,attendu", [
    ("developer", 403),
    ("appsec", 403),
    ("tech_lead", 200),
    ("admin", 200),
])
def test_droit_de_reglage_des_seuils_par_role(client, auth, project, role, attendu):
    reponse = client.put(
        f"/projects/{project.id}/quality-gate/settings", json=SEUILS, headers=auth(role)
    )
    assert reponse.status_code == attendu


@pytest.mark.parametrize("role", TOUS_LES_ROLES)
def test_tout_utilisateur_connecte_peut_lire_les_seuils(client, auth, project, role):
    reponse = client.get(f"/projects/{project.id}/quality-gate/settings", headers=auth(role))
    assert reponse.status_code == 200
