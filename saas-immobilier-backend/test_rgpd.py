"""Tests de la protection des données : purge de fin de contrat, export, opposition du prospect,
effacement d'un collaborateur, choix de l'IA par agence, suppression de fiche.

Lancement, depuis le dossier du backend (PostgreSQL local sur le port 5544, comme test_security) :
    python3 -m unittest test_rgpd
"""
import io
import json
import os
import re
import unittest
import zipfile
from datetime import timedelta
from unittest import mock

import test_security as ts
from test_security import Base, PW

backend = ts.backend
FICHE = {"name": "Camille Martin", "email": "camille.rgpd@exemple.fr", "phone": "06 12 34 56 78", "budget": 300000,
         "location": "Senlis", "property_type": "Maison", "financing_status": "approved",
         "purchase_urgency": "immediate"}
import base64
PNG = "data:image/png;base64," + base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\x00" * 200).decode()


def sql(requete, params=()):
    conn = backend.get_db_connection()
    cur = conn.cursor()
    cur.execute(requete, params)
    try:
        lignes = cur.fetchall()
    except Exception:
        lignes = None
    conn.commit()
    conn.close()
    return lignes


class Rgpd(Base):
    def setUp(self):
        super().setUp()
        self.envoyes = []

        def faux(dest, sujet, texte, html, **kw):
            self.envoyes.append({"to": dest, "sujet": sujet, "texte": texte, "html": html})
            return True

        for p in (mock.patch.object(backend, "_envoyer_email", side_effect=faux),
                  mock.patch.dict(os.environ, {"BREVO_API_KEY": "cle", "MAIL_FROM": "contact@zelyro.fr",
                                               "FRONTEND_URL": "https://app.zelyro.fr",
                                               "API_PUBLIC_URL": "https://api.zelyro.fr", "CRON_SECRET": "secret-cron"})):
            p.start()
            self.addCleanup(p.stop)

    def agence(self, email):
        """(jeton directeur, id directeur)"""
        t = self.jeton(email)
        return t, sql("SELECT id FROM users WHERE email = %s", (email,))[0][0]

    def employe(self, uid, email):
        sql("""INSERT INTO users (email, password_hash, first_name, role, agency_owner_id)
               VALUES (%s, %s, 'Julien', 'employe', %s)""",
            (email, backend.generate_password_hash(PW, method='pbkdf2:sha256'), uid))
        r = self.c.post("/auth/login", json={"email": email, "password": PW})
        return r.get_json()["token"], sql("SELECT id FROM users WHERE email = %s", (email,))[0][0]

    def fiche(self, t, **kw):
        r = self.c.post("/api/v1/leads", json={**FICHE, **kw}, headers=self.h(t))
        self.assertEqual(r.status_code, 201, r.get_json())
        return r.get_json()

    def bien(self, t):
        r = self.c.post("/api/v1/properties", json={"title": "Maison", "address": "5 rue Vieille 60300 Senlis",
                                                      "property_type": "Maison", "price": 290000}, headers=self.h(t))
        self.assertEqual(r.status_code, 201, r.get_json())
        return r.get_json()["id"]

    def proposer(self, t, lead):
        return self.c.post(f"/api/v1/leads/{lead['id']}/send-mail", headers=self.h(t),
                           json={"subject": "Sélection", "body": "Bonjour, voici une sélection de biens pour vous.",
                                 "property_ids": [self.bien(t)]})

    def couper(self, uid, jours):
        """Abonnement terminé il y a `jours` jours."""
        sql("""UPDATE users SET is_active = FALSE, billing_suspended = TRUE, billing_ended_at = %s,
                      token_version = token_version + 1 WHERE id = %s""",
            (backend._maintenant() - timedelta(days=jours), uid))

    def admin_zelyro(self, email):
        """Jeton d'un compte administrateur de Zelyro (créé en base : l'inscription lui est fermée).
        À appeler sous mock.patch.dict(os.environ, {"ADMIN_EMAILS": email})."""
        sql("INSERT INTO users (email, password_hash) VALUES (%s, %s) ON CONFLICT (email) DO NOTHING",
            (email, backend.generate_password_hash(PW, method='pbkdf2:sha256')))
        return self.c.post("/auth/login", json={"email": email, "password": PW}).get_json()["token"]

    def purger(self, cle="secret-cron"):
        return self.c.post("/internal/purge", headers={"X-Cron-Key": cle} if cle is not None else {})

    def compte(self, table, colonne, valeur):
        return sql(f"SELECT count(*) FROM {table} WHERE {colonne} = %s", (valeur,))[0][0]


class TestPurgeFinDeContrat(Rgpd):
    def preparer_agence_complete(self, email):
        t, uid = self.agence(email)
        lead = self.fiche(t)
        self.c.post(f"/api/v1/leads/{lead['id']}/notes", json={"content": "note", "body": "note", "text": "note"}, headers=self.h(t))
        bien = self.c.post("/api/v1/properties", json={"title": "Maison", "address": "5 rue Vieille 60300 Senlis",
                                                         "property_type": "Maison", "price": 290000}, headers=self.h(t)).get_json()
        r = self.c.post(f"/api/v1/properties/{bien['id']}/photos", headers=self.h(t), json={"image": PNG, "miniature": PNG})
        self.assertEqual(r.status_code, 201, r.get_json())
        te, eid = self.employe(uid, "collab-" + email)
        sql("""INSERT INTO gmail_connections (user_id, google_email, refresh_token_enc, connected_at)
               VALUES (%s, 'a@gmail.com', 'x', now())""", (uid,))
        return t, uid, lead, bien, eid

    def test_agence_apres_delai_purgee_entierement(self):
        t, uid, lead, bien, eid = self.preparer_agence_complete("pg-1@x.fr")
        self.couper(uid, 31)
        with mock.patch.object(backend, "_revoquer_jeton_gmail", return_value=True) as rev:
            r = self.purger()
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        self.assertEqual(r.get_json()["agences_purgees"], 1)
        rev.assert_called_once()
        self.assertEqual(self.compte("leads", "user_id", uid), 0)
        self.assertEqual(self.compte("lead_notes", "lead_id", lead["id"]), 0)
        self.assertEqual(self.compte("properties", "user_id", uid), 0)
        self.assertEqual(self.compte("property_photos", "user_id", uid), 0)
        self.assertEqual(self.compte("gmail_connections", "user_id", uid), 0)
        self.assertEqual(self.compte("users", "id", eid), 0)
        reste = sql("SELECT email, purged_at FROM users WHERE id = %s", (uid,))
        self.assertTrue(reste == [] or (reste[0][0].endswith("@purge.invalid") and reste[0][1] is not None))
        log = sql("SELECT detail FROM admin_log WHERE action = 'agence purgée' AND target = %s", (f"compte {uid}",))
        self.assertEqual(len(log), 1)
        self.assertNotIn("Camille", log[0][0])

    def test_agence_dans_le_delai_de_grace_intacte(self):
        t, uid, lead, bien, eid = self.preparer_agence_complete("pg-2@x.fr")
        self.couper(uid, 10)
        self.assertEqual(self.purger().get_json()["agences_purgees"], 0)
        self.assertEqual(self.compte("leads", "user_id", uid), 1)
        self.assertEqual(self.compte("property_photos", "user_id", uid), 1)

    def test_agence_active_jamais_purgee_meme_avec_vieille_date(self):
        t, uid, lead, bien, eid = self.preparer_agence_complete("pg-3@x.fr")
        sql("UPDATE users SET billing_ended_at = %s WHERE id = %s", (backend._maintenant() - timedelta(days=90), uid))
        self.assertEqual(self.purger().get_json()["agences_purgees"], 0)
        self.assertEqual(self.compte("leads", "user_id", uid), 1)

    def test_compte_admin_zelyro_jamais_purge(self):
        with mock.patch.dict(os.environ, {"ADMIN_EMAILS": "equipe-pg@zelyro.fr"}):
            sql("INSERT INTO users (email, password_hash) VALUES (%s, %s)",
                ("equipe-pg@zelyro.fr", backend.generate_password_hash(PW, method='pbkdf2:sha256')))
            uid = sql("SELECT id FROM users WHERE email = 'equipe-pg@zelyro.fr'")[0][0]
            sql("INSERT INTO leads (user_id, name, email) VALUES (%s, 'Prospect équipe', 'p@x.fr')", (uid,))
            self.couper(uid, 90)
            self.assertEqual(self.purger().get_json()["agences_purgees"], 0)
            self.assertEqual(self.compte("leads", "user_id", uid), 1)

    def test_les_autres_agences_ne_sont_pas_touchees(self):
        ta, uid_a, lead_a, *_ = self.preparer_agence_complete("pg-4a@x.fr")
        tb, uid_b, lead_b, *_ = self.preparer_agence_complete("pg-4b@x.fr")
        self.couper(uid_a, 40)
        with mock.patch.object(backend, "_revoquer_jeton_gmail", return_value=True):
            self.purger()
        self.assertEqual(self.compte("leads", "user_id", uid_a), 0)
        self.assertEqual(self.compte("leads", "user_id", uid_b), 1)
        self.assertEqual(self.compte("property_photos", "user_id", uid_b), 1)
        self.assertEqual(self.compte("gmail_connections", "user_id", uid_b), 1)

    def test_route_protegee_par_la_cle(self):
        t, uid, *_ = self.preparer_agence_complete("pg-5@x.fr")
        self.couper(uid, 90)
        for cle in (None, "", "mauvaise"):
            self.assertEqual(self.purger(cle).status_code, 404)
        with mock.patch.dict(os.environ, {"CRON_SECRET": ""}):
            self.assertEqual(self.purger("").status_code, 404)
        self.assertEqual(self.compte("leads", "user_id", uid), 1)

    def test_reactivation_entre_selection_et_purge(self):
        """Un paiement qui rétablit l'agence au dernier moment annule la purge (le webhook Stripe)."""
        t, uid, *_ = self.preparer_agence_complete("pg-6@x.fr")
        self.couper(uid, 40)
        sql("UPDATE users SET is_active = TRUE, billing_suspended = FALSE WHERE id = %s", (uid,))
        self.assertFalse(backend._purger_agence(uid))
        self.assertEqual(self.compte("leads", "user_id", uid), 1)

    def test_echec_au_milieu_n_efface_rien(self):
        t, uid, lead, *_ = self.preparer_agence_complete("pg-7@x.fr")
        self.couper(uid, 40)
        with mock.patch.object(backend, "_revoquer_jeton_gmail", return_value=True), \
                mock.patch.object(backend, "_maintenant", side_effect=[backend._maintenant(), RuntimeError("panne")]):
            try:
                backend._purger_agence(uid)
            except Exception:
                pass
        self.assertEqual(self.compte("leads", "user_id", uid), 1)

    def test_journaux_techniques_purges(self):
        sql("""INSERT INTO password_resets (user_id, token_hash, expires_at)
               VALUES ((SELECT id FROM users LIMIT 1), %s, %s)""", ("h" * 64, backend._maintenant() - timedelta(days=3)))
        self.purger()
        self.assertEqual(self.compte("password_resets", "token_hash", "h" * 64), 0)


class TestExportComplet(Rgpd):
    def lire_zip(self, reponse):
        self.assertEqual(reponse.status_code, 200, reponse.get_data()[:300])
        z = zipfile.ZipFile(io.BytesIO(reponse.get_data()))
        return z, json.loads(z.read("donnees.json"))

    def test_export_d_une_agence_active(self):
        t, uid = self.agence("ex-1@x.fr")
        lead = self.fiche(t)
        bien = self.c.post("/api/v1/properties", json={"title": "Maison", "address": "5 rue Vieille 60300 Senlis",
                                                         "property_type": "Maison", "price": 290000}, headers=self.h(t)).get_json()
        self.c.post(f"/api/v1/properties/{bien['id']}/photos", headers=self.h(t), json={"image": PNG, "miniature": PNG})
        z, d = self.lire_zip(self.c.get("/api/v1/export/complet", headers=self.h(t)))
        self.assertEqual([p["name"] for p in d["prospects"]], ["Camille Martin"])
        self.assertEqual(len(d["biens"]), 1)
        self.assertTrue(any(n.startswith("photos/") for n in z.namelist()))
        brut = json.dumps(d)
        for secret in ("completion_token", "suivi_token"):
            self.assertNotIn(secret, brut)

    def test_export_sans_donnees_d_une_autre_agence(self):
        ta, _ = self.agence("ex-2a@x.fr")
        tb, _ = self.agence("ex-2b@x.fr")
        self.fiche(ta, name="Prospect de A", email="a@prospect.fr")
        z, d = self.lire_zip(self.c.get("/api/v1/export/complet", headers=self.h(tb)))
        self.assertEqual(d["prospects"], [])
        self.assertNotIn("Prospect de A", json.dumps(d))

    def test_employe_refuse(self):
        t, uid = self.agence("ex-3@x.fr")
        te, _ = self.employe(uid, "collab-ex-3@x.fr")
        self.assertEqual(self.c.get("/api/v1/export/complet", headers=self.h(te)).status_code, 403)

    def test_sans_session_refuse(self):
        self.assertEqual(self.c.get("/api/v1/export/complet").status_code, 401)

    def test_agence_coupee_recupere_ses_donnees_avec_le_jeton_d_export(self):
        t, uid = self.agence("ex-4@x.fr")
        self.fiche(t)
        self.couper(uid, 5)
        r = self.c.post("/auth/login", json={"email": "ex-4@x.fr", "password": PW})
        self.assertEqual(r.status_code, 403)
        corps = r.get_json()
        self.assertIn("export_token", corps)
        self.assertIn("purge_prevue", corps)
        h = self.h(corps["export_token"])
        z, d = self.lire_zip(self.c.get("/api/v1/export/complet", headers=h))
        self.assertEqual(len(d["prospects"]), 1)

    def test_jeton_d_export_ne_donne_acces_a_rien_d_autre(self):
        t, uid = self.agence("ex-5@x.fr")
        self.fiche(t)
        self.couper(uid, 5)
        tok = self.c.post("/auth/login", json={"email": "ex-5@x.fr", "password": PW}).get_json()["export_token"]
        for methode, url in [("get", "/api/v1/leads"), ("get", "/api/v1/leads/export"), ("get", "/api/v1/properties"),
                             ("post", "/api/v1/leads"), ("get", "/api/v1/gmail/status")]:
            with self.subTest(url):
                r = getattr(self.c, methode)(url, headers=self.h(tok), json=FICHE)
                self.assertEqual(r.status_code, 401, f"{methode.upper()} {url} -> {r.status_code}")

    def test_jeton_d_export_inutilisable_apres_reactivation(self):
        t, uid = self.agence("ex-6@x.fr")
        self.couper(uid, 5)
        tok = self.c.post("/auth/login", json={"email": "ex-6@x.fr", "password": PW}).get_json()["export_token"]
        sql("UPDATE users SET is_active = TRUE, billing_suspended = FALSE WHERE id = %s", (uid,))
        self.assertEqual(self.c.get("/api/v1/leads", headers=self.h(tok)).status_code, 401)

    def test_agence_purgee_n_a_plus_de_jeton_d_export(self):
        t, uid = self.agence("ex-7@x.fr")
        self.couper(uid, 40)
        with mock.patch.object(backend, "_revoquer_jeton_gmail", return_value=True):
            self.purger()
        r = self.c.post("/auth/login", json={"email": "ex-7@x.fr", "password": PW})
        self.assertNotIn("export_token", r.get_json() or {})

    def test_employe_d_une_agence_coupee_n_a_pas_de_jeton_d_export(self):
        t, uid = self.agence("ex-8@x.fr")
        self.employe(uid, "collab-ex-8@x.fr")
        self.couper(uid, 5)
        r = self.c.post("/auth/login", json={"email": "collab-ex-8@x.fr", "password": PW})
        self.assertNotIn("export_token", r.get_json() or {})


class TestOpposition(Rgpd):
    def lien(self, lead_id):
        return backend._jeton_opposition(lead_id)

    def test_get_ne_desinscrit_pas(self):
        t, uid = self.agence("op-1@x.fr")
        lead = self.fiche(t)
        r = self.c.get(f"/public/opposition/{self.lien(lead['id'])}")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Confirmer", r.get_data(as_text=True))
        self.assertIsNone(sql("SELECT opposition_at FROM leads WHERE id = %s", (lead["id"],))[0][0])

    def test_post_enregistre_l_opposition(self):
        t, uid = self.agence("op-2@x.fr")
        lead = self.fiche(t)
        r = self.c.post(f"/public/opposition/{self.lien(lead['id'])}")
        self.assertEqual(r.status_code, 200)
        self.assertIsNotNone(sql("SELECT opposition_at FROM leads WHERE id = %s", (lead["id"],))[0][0])
        self.assertEqual(self.compte("contact_opposition", "user_id", uid), 1)
        # idempotent
        self.assertEqual(self.c.post(f"/public/opposition/{self.lien(lead['id'])}").status_code, 200)
        self.assertEqual(self.compte("contact_opposition", "user_id", uid), 1)

    def test_jetons_invalides(self):
        t, uid = self.agence("op-3@x.fr")
        lead = self.fiche(t)
        bon = self.lien(lead["id"])
        for mauvais in ("1.abc", "x", f"{lead['id']}.{'0' * 32}", bon[:-1] + ("0" if bon[-1] != "0" else "1"),
                        f"{lead['id'] + 1}.{bon.split('.')[1]}"):
            with self.subTest(mauvais):
                self.assertEqual(self.c.post(f"/public/opposition/{mauvais}").status_code, 404)
        self.assertIsNone(sql("SELECT opposition_at FROM leads WHERE id = %s", (lead["id"],))[0][0])

    def test_plus_aucun_email_apres_opposition(self):
        t, uid = self.agence("op-4@x.fr")
        lead = self.fiche(t)
        self.c.post(f"/public/opposition/{self.lien(lead['id'])}")
        r = self.proposer(t, lead)
        self.assertEqual(r.status_code, 409)
        self.assertEqual(r.get_json()["code"], "opposition")
        self.assertEqual([m for m in self.envoyes if m['to'] == FICHE['email']], [])   # rien vers le prospect

    def test_opposition_survit_a_la_suppression_et_a_la_recreation_de_la_fiche(self):
        t, uid = self.agence("op-5@x.fr")
        lead = self.fiche(t)
        self.c.post(f"/public/opposition/{self.lien(lead['id'])}")
        self.assertEqual(self.c.delete(f"/api/v1/leads/{lead['id']}", headers=self.h(t)).status_code, 200)
        nouvelle = self.fiche(t)                       # même adresse e-mail
        r = self.proposer(t, nouvelle)
        self.assertEqual(r.status_code, 409)

    def test_opposition_limitee_a_l_agence_concernee(self):
        ta, uid_a = self.agence("op-6a@x.fr")
        tb, uid_b = self.agence("op-6b@x.fr")
        lead_a = self.fiche(ta)
        lead_b = self.fiche(tb)                        # même adresse e-mail chez une autre agence
        self.c.post(f"/public/opposition/{self.lien(lead_a['id'])}")
        r = self.proposer(tb, lead_b)
        self.assertEqual(r.status_code, 200, r.get_json())

    def test_fiche_deja_effacee(self):
        t, uid = self.agence("op-7@x.fr")
        lead = self.fiche(t)
        jeton = self.lien(lead["id"])
        self.c.delete(f"/api/v1/leads/{lead['id']}", headers=self.h(t))
        r = self.c.get(f"/public/opposition/{jeton}")
        self.assertEqual(r.status_code, 200)
        self.assertIn("plus d'e-mails", r.get_data(as_text=True))

    def test_le_lien_figure_dans_l_email_de_proposition(self):
        t, uid = self.agence("op-8@x.fr")
        lead = self.fiche(t)
        r = self.proposer(t, lead)
        self.assertEqual(r.status_code, 200, r.get_json())
        mail = self.envoyes[-1]
        self.assertRegex(mail["texte"] + mail["html"], r"https://api\.zelyro\.fr/public/opposition/\d+\.[0-9a-f]{32}")


class TestEffacementCollaborateur(Rgpd):
    def test_anonymisation_en_conservant_l_historique(self):
        t, uid = self.agence("co-1@x.fr")
        te, eid = self.employe(uid, "julien-co-1@x.fr")
        lead = self.fiche(t)
        self.c.post(f"/api/v1/leads/{lead['id']}/notes", json={"content": "note de Julien", "body": "note de Julien", "text": "note de Julien"},
                    headers=self.h(te))
        r = self.c.post(f"/api/v1/team/{eid}/erase", headers=self.h(t))
        self.assertEqual(r.status_code, 200, r.get_json())
        ligne = sql("SELECT email, first_name, is_active FROM users WHERE id = %s", (eid,))[0]
        self.assertTrue(ligne[0].endswith("@purge.invalid"))
        self.assertEqual(ligne[1], "Ancien collaborateur")
        self.assertFalse(ligne[2])
        self.assertEqual(self.c.post("/auth/login", json={"email": "julien-co-1@x.fr", "password": PW}).status_code, 401)
        self.assertEqual(self.c.get("/api/v1/leads", headers=self.h(te)).status_code, 401)
        self.assertGreaterEqual(self.compte("lead_notes", "lead_id", lead["id"]), 1)   # l'historique reste

    def test_reservee_au_directeur_et_a_son_agence(self):
        ta, uid_a = self.agence("co-2a@x.fr")
        tb, uid_b = self.agence("co-2b@x.fr")
        te, eid = self.employe(uid_a, "julien-co-2@x.fr")
        self.assertEqual(self.c.post(f"/api/v1/team/{eid}/erase", headers=self.h(te)).status_code, 403)
        self.assertEqual(self.c.post(f"/api/v1/team/{eid}/erase", headers=self.h(tb)).status_code, 404)
        self.assertEqual(sql("SELECT first_name FROM users WHERE id = %s", (eid,))[0][0], "Julien")

    def test_on_ne_peut_pas_effacer_le_directeur(self):
        t, uid = self.agence("co-3@x.fr")
        self.assertEqual(self.c.post(f"/api/v1/team/{uid}/erase", headers=self.h(t)).status_code, 404)
        self.assertEqual(self.c.get("/api/v1/leads", headers=self.h(t)).status_code, 200)

    def test_un_collaborateur_efface_ne_peut_pas_etre_reactive(self):
        t, uid = self.agence("co-4@x.fr")
        te, eid = self.employe(uid, "julien-co-4@x.fr")
        self.c.post(f"/api/v1/team/{eid}/erase", headers=self.h(t))
        self.c.put(f"/api/v1/team/{eid}/reactivate", headers=self.h(t))
        self.assertFalse(sql("SELECT is_active FROM users WHERE id = %s", (eid,))[0][0])


class TestChoixIA(Rgpd):
    MESSAGE = {"message": "Bonjour, je cherche une maison à Senlis, budget 300000 euros, financement accordé."}

    # Décision : l'IA est activée par défaut ; l'agence (le directeur) peut la couper à tout moment.
    def test_activee_par_defaut_et_coupable_par_l_agence(self):
        t, uid = self.agence("ia-1@x.fr")
        self.assertTrue(sql("SELECT ia_enabled FROM users WHERE id = %s", (uid,))[0][0])
        self.assertEqual(self.c.put("/auth/preferences", json={"ia_enabled": False}, headers=self.h(t)).status_code, 200)
        with mock.patch.object(backend.requests, "post") as p:
            r = self.c.post("/api/v1/extract", json=self.MESSAGE, headers=self.h(t))
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.get_json()["code"], "ia_disabled")
        p.assert_not_called()   # rien n'est envoyé à Anthropic une fois l'IA coupée

    def test_le_directeur_peut_la_couper_pas_l_employe(self):
        t, uid = self.agence("ia-2@x.fr")
        te, _ = self.employe(uid, "collab-ia-2@x.fr")
        self.assertEqual(self.c.put("/auth/preferences", json={"ia_enabled": False}, headers=self.h(te)).status_code, 403)
        self.assertTrue(sql("SELECT ia_enabled FROM users WHERE id = %s", (uid,))[0][0])
        self.assertEqual(self.c.put("/auth/preferences", json={"ia_enabled": False}, headers=self.h(t)).status_code, 200)
        self.assertFalse(sql("SELECT ia_enabled FROM users WHERE id = %s", (uid,))[0][0])

    def test_activee_l_extraction_appelle_le_service(self):
        t, uid = self.agence("ia-3@x.fr")
        self.c.put("/auth/preferences", json={"ia_enabled": True}, headers=self.h(t))
        faux = mock.Mock(status_code=200, text="")
        faux.json.return_value = {"content": [{"type": "text", "text": '{"name": "X"}'}]}
        with mock.patch.object(backend.requests, "post", return_value=faux) as p:
            r = self.c.post("/api/v1/extract", json=self.MESSAGE, headers=self.h(t))
        self.assertNotEqual(r.status_code, 403, r.get_data(as_text=True))
        self.assertTrue(p.called)

    def test_valeur_non_booleenne_refusee(self):
        t, uid = self.agence("ia-4@x.fr")
        self.assertEqual(self.c.put("/auth/preferences", json={"ia_enabled": "oui"}, headers=self.h(t)).status_code, 400)

    def test_le_reglage_est_visible_dans_le_profil(self):
        t, uid = self.agence("ia-5@x.fr")
        r = self.c.get("/auth/profile", headers=self.h(t))
        self.assertEqual(r.status_code, 200)
        self.assertIn("ia_enabled", r.get_data(as_text=True))


class TestSuppressionDeFiche(Rgpd):
    def test_journal_de_reception_vide_et_preuve_sans_donnee_personnelle(self):
        t, uid = self.agence("sf-1@x.fr")
        lead = self.fiche(t)
        sql("""INSERT INTO inbound_emails (message_id, user_id, source, lead_id, subject, detail)
               VALUES ('msg-sf-1', %s, 'gmail', %s, 'Demande de Camille Martin', 'camille.rgpd@exemple.fr')""", (uid, lead["id"]))
        self.assertEqual(self.c.delete(f"/api/v1/leads/{lead['id']}", headers=self.h(t)).status_code, 200)
        ligne = sql("SELECT subject, detail FROM inbound_emails WHERE message_id = 'msg-sf-1'")[0]
        self.assertEqual(ligne, (None, None))
        preuve = sql("SELECT admin_email, target, detail FROM admin_log WHERE action = 'prospect supprimé' AND target = %s",
                     (f"fiche {lead['id']}",))
        self.assertEqual(len(preuve), 1)
        self.assertNotRegex(" ".join(preuve[0]), r"Camille|exemple\.fr|0612")

    def test_fiche_inexistante_ne_laisse_aucune_preuve(self):
        t, uid = self.agence("sf-2@x.fr")
        self.assertEqual(self.c.delete("/api/v1/leads/99999999", headers=self.h(t)).status_code, 404)
        self.assertEqual(self.compte("admin_log", "target", "fiche 99999999"), 0)


class TestMesureAudience(Rgpd):
    UA = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/120 Safari/537.36", "Accept-Language": "fr-FR,fr;q=0.9"}

    class FauxLecteur:
        def get(self, ip):
            return {"country": {"iso_code": "fr"}, "city": {"names": {"fr": "Senlis"}},
                    "subdivisions": [{"names": {"fr": "Hauts-de-France"}}],
                    "location": {"latitude": 49.2066, "longitude": 2.5866}}

    def setUp(self):
        super().setUp()
        # Une base existante a (ou avait) la colonne « region » : on la recrée si une purge précédente l'a supprimée.
        sql("ALTER TABLE site_visites ADD COLUMN IF NOT EXISTS region VARCHAR(80)")
        sql("DELETE FROM site_visites")
        sql("DELETE FROM site_direct")

    def visiter(self):
        with mock.patch.object(backend, "_geo_lecteur", return_value=self.FauxLecteur()), \
                mock.patch.object(backend._random, "random", return_value=0.5):
            r = self.c.post("/public/stats/vue", json={"p": "/tarifs.html", "w": 1400}, headers=self.UA)
        self.assertEqual(r.status_code, 204)

    def test_visite_sans_region_et_position_a_une_decimale(self):
        self.visiter()
        v = sql("SELECT region, ville, lat, lon FROM site_visites")
        self.assertEqual(len(v), 1)
        self.assertIsNone(v[0][0])
        self.assertEqual(v[0][1], "Senlis")
        self.assertAlmostEqual(v[0][2], 49.2, places=4)
        self.assertAlmostEqual(v[0][3], 2.6, places=4)
        d = sql("SELECT lat, lon FROM site_direct")[0]
        self.assertAlmostEqual(d[0], 49.2, places=4)
        self.assertAlmostEqual(d[1], 2.6, places=4)

    def test_l_api_renvoie_toujours_les_villes_avec_leur_position(self):
        self.visiter()
        with mock.patch.dict(os.environ, {"ADMIN_EMAILS": "stats-rg@zelyro.fr"}):
            t = self.admin_zelyro("stats-rg@zelyro.fr")
            r = self.c.get("/admin/stats/resume?jours=7", headers=self.h(t))
            d = self.c.get("/admin/stats/direct", headers=self.h(t))
        self.assertEqual(r.status_code, 200, r.get_json())
        v = r.get_json()["villes"][0]
        self.assertEqual((v["ville"], round(v["lat"], 1), round(v["lon"], 1)), ("Senlis", 49.2, 2.6))
        self.assertEqual(d.get_json()["villes"][0]["ville"], "Senlis")
        self.assertNotIn("region", v)

    def test_la_purge_efface_les_anciennes_regions_et_arrondit_les_positions(self):
        maintenant = backend._maintenant()
        sql("""INSERT INTO site_visites (visiteur, page, pays, region, ville, lat, lon, cree_le)
               VALUES ('v1', '/', 'FR', 'Hauts-de-France', 'Senlis', 49.21, 2.59, %s),
                      ('v2', '/', 'FR', NULL, 'Paris', 48.9, 2.3, %s)""", (maintenant, maintenant))
        sql("""INSERT INTO site_direct (visiteur, page, pays, ville, lat, lon, debut, vu_le)
               VALUES ('v1', '/', 'FR', 'Senlis', 49.21, 2.59, %s, %s)""", (maintenant, maintenant))
        backend._purger_stats()
        backend._purger_stats()   # idempotente
        # la colonne « region » (donnée devenue inutile) est supprimée avec son contenu
        self.assertEqual(sql("""SELECT count(*) FROM information_schema.columns
                                WHERE table_name = 'site_visites' AND column_name = 'region'""")[0][0], 0)
        v = sql("SELECT lat, lon FROM site_visites ORDER BY visiteur")
        self.assertAlmostEqual(v[0][0], 49.2, places=4)
        self.assertAlmostEqual(v[0][1], 2.6, places=4)
        self.assertAlmostEqual(v[1][0], 48.9, places=4)
        d = sql("SELECT lat, lon FROM site_direct")[0]
        self.assertAlmostEqual(d[0], 49.2, places=4)
        self.assertAlmostEqual(d[1], 2.6, places=4)

    def test_la_purge_quotidienne_efface_les_visites_de_plus_de_13_mois(self):
        maintenant = backend._maintenant()
        sql("""INSERT INTO site_visites (visiteur, page, pays, cree_le)
               VALUES ('vieux', '/', 'FR', %s), ('ancien', '/', 'FR', %s), ('recent', '/', 'FR', %s)""",
            (maintenant - timedelta(days=396), maintenant - timedelta(days=400), maintenant - timedelta(days=30)))
        self.assertEqual(self.purger("mauvaise").status_code, 404)
        self.assertEqual(sql("SELECT count(*) FROM site_visites")[0][0], 3)
        r = self.purger()
        self.assertEqual(r.status_code, 200)
        self.assertIn("agences_purgees", r.get_json())
        self.assertEqual([x[0].strip() for x in sql("SELECT visiteur FROM site_visites")], ["recent"])


def hashlib_sha256(octets):
    return __import__("hashlib").sha256(octets).digest()


class TestEmpreinteOpposition(Rgpd):
    def test_cle_dediee_et_empreintes_deja_ecrites_avec_la_cle_derivee_de_secret_key(self):
        # Une désinscription écrite avec la clé dérivée de SECRET_KEY reste reconnue une fois la clé dédiée
        # (OPPOSITION_HMAC_KEY) définie ; et changer SECRET_KEY n'affecte plus les empreintes écrites avec la clé dédiée.
        t, uid = self.agence("emp-3@x.fr")
        mail = "Cle.Dediee@exemple.fr"
        avec_secret = backend._empreinte_email(mail, backend._CLE_EMPREINTE_EMAIL_SECRET)
        sql("INSERT INTO contact_opposition (user_id, email_hash) VALUES (%s, %s)", (uid, avec_secret))
        cle_dediee = hashlib_sha256(b'zelyro-empreinte-email:' + b"d" * 32)
        with mock.patch.object(backend, "_CLE_EMPREINTE_EMAIL", cle_dediee):
            dediee = backend._empreinte_email(mail)
            self.assertNotEqual(dediee, avec_secret)
            conn = backend.get_db_connection()
            cur = conn.cursor(cursor_factory=backend.RealDictCursor)
            self.assertTrue(backend._prospect_oppose(cur, uid, mail))      # ancienne empreinte (clé dérivée) reconnue
            conn.commit()
            conn.close()
            self.assertEqual([r[0].strip() for r in sql("SELECT email_hash FROM contact_opposition WHERE user_id = %s", (uid,))],
                             [dediee])                                      # migrée vers la clé dédiée
            # SECRET_KEY « renouvelée » : l'empreinte dédiée ne change pas, la désinscription reste reconnue
            with mock.patch.object(backend, "_CLE_EMPREINTE_EMAIL_SECRET", hashlib_sha256(b"autre-secret")):
                conn = backend.get_db_connection()
                cur = conn.cursor(cursor_factory=backend.RealDictCursor)
                self.assertTrue(backend._prospect_oppose(cur, uid, mail))
                conn.close()

    def test_ancienne_empreinte_toujours_reconnue(self):
        t, uid = self.agence("emp-1@x.fr")
        mail = "Ancien.Desinscrit@exemple.fr"
        ancienne = backend._empreinte_email_ancienne(mail)
        self.assertEqual(ancienne, __import__("hashlib").sha256(mail.lower().encode()).hexdigest())
        sql("INSERT INTO contact_opposition (user_id, email_hash) VALUES (%s, %s)", (uid, ancienne))
        conn = backend.get_db_connection()
        cur = conn.cursor(cursor_factory=backend.RealDictCursor)
        self.assertTrue(backend._prospect_oppose(cur, uid, mail))
        self.assertFalse(backend._prospect_oppose(cur, uid, "autre@exemple.fr"))
        conn.commit()
        conn.close()
        # migrée vers la nouvelle empreinte
        self.assertEqual([r[0].strip() for r in sql("SELECT email_hash FROM contact_opposition WHERE user_id = %s", (uid,))],
                         [backend._empreinte_email(mail)])

    def test_nouvelle_opposition_ecrit_la_nouvelle_empreinte(self):
        t, uid = self.agence("emp-2@x.fr")
        lead = self.fiche(t)
        self.assertEqual(self.c.post(f"/public/opposition/{backend._jeton_opposition(lead['id'])}").status_code, 200)
        nouvelle = backend._empreinte_email(FICHE["email"])
        ancienne = backend._empreinte_email_ancienne(FICHE["email"])
        self.assertNotEqual(nouvelle, ancienne)
        self.assertEqual([r[0].strip() for r in sql("SELECT email_hash FROM contact_opposition WHERE user_id = %s", (uid,))],
                         [nouvelle])


class TestRetentionJournalAdmin(Rgpd):
    def ligne(self, action, mois):
        sql("""INSERT INTO admin_log (admin_email, action, target, detail, created_at)
               VALUES ('x', %s, %s, 'd', %s)""",
            (action, f"cible-{action}-{mois}", backend._maintenant() - timedelta(days=mois * 30 + 5)))

    def existe(self, action, mois):
        return self.compte("admin_log", "target", f"cible-{action}-{mois}") == 1

    def test_douze_mois_sauf_preuve_d_effacement_trois_ans(self):
        for a, m in (("autre", 6), ("autre", 13), ("prospect supprimé", 13), ("prospect supprimé", 37), ("prospect supprimé", 30)):
            self.ligne(a, m)
        backend._purger_journaux()
        self.assertTrue(self.existe("autre", 6))
        self.assertFalse(self.existe("autre", 13))
        self.assertTrue(self.existe("prospect supprimé", 13))
        self.assertTrue(self.existe("prospect supprimé", 30))
        self.assertFalse(self.existe("prospect supprimé", 37))

    def test_toutes_les_preuves_d_effacement_gardees_trois_ans(self):
        for a in ("compte effacé", "collaborateur effacé", "agence purgée"):
            self.ligne(a, 13)
            self.ligne(a, 30)
            self.ligne(a, 37)
        backend._purger_journaux()
        for a in ("compte effacé", "collaborateur effacé", "agence purgée"):
            self.assertTrue(self.existe(a, 13), a)
            self.assertTrue(self.existe(a, 30), a)
            self.assertFalse(self.existe(a, 37), a)


class TestEffacementCompteParAdmin(Rgpd):
    ADMIN = "boss-er@zelyro.fr"

    def setUp(self):
        super().setUp()
        p = mock.patch.dict(os.environ, {"ADMIN_EMAILS": self.ADMIN})
        p.start()
        self.addCleanup(p.stop)
        self.ta = self.admin_zelyro(self.ADMIN)

    def effacer(self, uid, confirm, token=None):
        return self.c.post(f"/admin/users/{uid}/erase", json={"confirm_email": confirm},
                           headers=self.h(token or self.ta))

    def agence_complete(self, email):
        t, uid = self.agence(email)
        self.fiche(t)
        self.bien(t)
        te, eid = self.employe(uid, "collab-" + email)
        return t, uid, eid

    def test_non_admin_404(self):
        t, uid, eid = self.agence_complete("er-1@x.fr")
        self.assertEqual(self.effacer(uid, "er-1@x.fr", token=t).status_code, 404)
        self.assertEqual(self.compte("leads", "user_id", uid), 1)

    def test_mauvaise_confirmation_400_rien_supprime(self):
        t, uid, eid = self.agence_complete("er-2@x.fr")
        self.assertEqual(self.effacer(uid, "autre@x.fr").status_code, 400)
        self.assertEqual(self.c.post(f"/admin/users/{uid}/erase", headers=self.h(self.ta)).status_code, 400)
        self.assertEqual(self.compte("leads", "user_id", uid), 1)
        self.assertEqual(self.compte("properties", "user_id", uid), 1)
        self.assertEqual(self.compte("users", "id", uid), 1)

    def test_directeur_resilie_tout_est_efface_et_l_autre_agence_intacte(self):
        t, uid, eid = self.agence_complete("er-3@x.fr")
        tb, uid_b, eid_b = self.agence_complete("er-3b@x.fr")
        sql("UPDATE users SET billing_status = 'canceled', is_active = FALSE, billing_suspended = TRUE WHERE id = %s", (uid,))
        with mock.patch.object(backend, "_revoquer_jeton_gmail", return_value=True):
            r = self.effacer(uid, "ER-3@x.fr")   # insensible à la casse
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual(self.compte("leads", "user_id", uid), 0)
        self.assertEqual(self.compte("properties", "user_id", uid), 0)
        self.assertEqual(self.compte("users", "id", uid), 0)
        self.assertEqual(self.compte("users", "id", eid), 0)
        self.assertEqual(self.compte("leads", "user_id", uid_b), 1)
        self.assertEqual(self.compte("properties", "user_id", uid_b), 1)
        self.assertEqual(self.compte("users", "id", eid_b), 1)
        log = sql("SELECT admin_email, detail, target FROM admin_log WHERE action = 'compte effacé' AND target = %s",
                  (f"compte {uid}",))
        self.assertEqual(len(log), 1)
        self.assertNotIn("er-3@x.fr", log[0][2] + log[0][1])
        self.assertIn(self.ADMIN, log[0][0] + log[0][1])

    def test_directeur_avec_abonnement_actif_409(self):
        for i, statut in enumerate(("active", "trialing", "past_due")):
            t, uid, eid = self.agence_complete(f"er-4{i}@x.fr")
            sql("UPDATE users SET billing_status = %s WHERE id = %s", (statut, uid))
            r = self.effacer(uid, f"er-4{i}@x.fr")
            self.assertEqual(r.status_code, 409, statut)
            self.assertIn("abonnement", r.get_json()["message"])
            self.assertEqual(self.compte("leads", "user_id", uid), 1)

    def test_abonnement_stripe_non_annule_refuse_meme_sans_statut_actif(self):
        # impayé, incomplet, en pause, ou statut vide avec un abonnement renseigné : l'abonnement existerait encore
        for i, statut in enumerate(("unpaid", "incomplete", "paused", None, "")):
            t, uid, eid = self.agence_complete(f"er-6{i}@x.fr")
            sql("UPDATE users SET billing_status = %s, stripe_subscription_id = 'sub_test' WHERE id = %s", (statut, uid))
            r = self.effacer(uid, f"er-6{i}@x.fr")
            self.assertEqual(r.status_code, 409, statut)
            self.assertEqual(self.compte("leads", "user_id", uid), 1, statut)

    def test_abonnement_annule_ou_agence_sans_abonnement_peut_etre_effacee(self):
        t, uid, eid = self.agence_complete("er-7@x.fr")
        sql("UPDATE users SET billing_status = 'canceled', stripe_subscription_id = 'sub_fini' WHERE id = %s", (uid,))
        with mock.patch.object(backend, "_revoquer_jeton_gmail", return_value=True):
            self.assertEqual(self.effacer(uid, "er-7@x.fr").status_code, 200)
        t2, uid2, eid2 = self.agence_complete("er-8@x.fr")        # agence pilote : aucun abonnement Stripe
        with mock.patch.object(backend, "_revoquer_jeton_gmail", return_value=True):
            self.assertEqual(self.effacer(uid2, "er-8@x.fr").status_code, 200)
        self.assertEqual(self.compte("users", "id", uid2), 0)

    def test_collaborateur_anonymise(self):
        t, uid, eid = self.agence_complete("er-5@x.fr")
        r = self.effacer(eid, "collab-er-5@x.fr")
        self.assertEqual(r.status_code, 200, r.get_json())
        ligne = sql("SELECT email, first_name, is_active FROM users WHERE id = %s", (eid,))[0]
        self.assertTrue(ligne[0].endswith("@purge.invalid"))
        self.assertEqual((ligne[1], ligne[2]), ("Ancien collaborateur", False))
        self.assertEqual(self.compte("leads", "user_id", uid), 1)
        log = sql("SELECT target, detail FROM admin_log WHERE action = 'compte effacé' AND target = %s", (f"compte {eid}",))
        self.assertEqual(len(log), 1)
        self.assertNotIn("collab-er-5", log[0][0] + log[0][1])

    def test_compte_admin_zelyro_refuse(self):
        uid = sql("SELECT id FROM users WHERE email = %s", (self.ADMIN,))[0][0]
        self.assertEqual(self.effacer(uid, self.ADMIN).status_code, 403)
        self.assertEqual(self.compte("users", "id", uid), 1)


if __name__ == "__main__":
    unittest.main()
