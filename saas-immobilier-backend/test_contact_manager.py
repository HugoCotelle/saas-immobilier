"""Tests du « contact manager » : filtre anti-spam, annonce visée, statistiques par portail et par annonce,
rapport du lundi.

Lancement, depuis le dossier du backend (PostgreSQL local sur le port 5544, comme test_security) :
    python3 -m unittest test_contact_manager
"""
import os
import secrets
import unittest
from datetime import datetime, timedelta
from unittest import mock

import test_security as ts
from test_security import BaseInbound, PW

backend = ts.backend


class Regles(unittest.TestCase):
    def test_annonce_titre_et_reference(self):
        titre, ref = backend._annonce_du_message("Contact pour « T3 lumineux, Senlis »", "Réf. A123\nBonjour")
        self.assertEqual((titre, ref), ("T3 lumineux, Senlis", "A123"))

    def test_annonce_numero(self):
        self.assertEqual(backend._annonce_du_message("Annonce n° 2345678901", "")[1], "2345678901")

    def test_pas_de_fausse_reference(self):
        self.assertEqual(backend._annonce_du_message("Message", "la ref de votre annonce est claire"), (None, None))

    def test_titre_qui_cite_un_telephone_est_ignore(self):
        titre, _ = backend._annonce_du_message("x", "Bonjour « rappelez-moi au 06 12 34 56 78 »")
        self.assertIsNone(titre)
        titre, _ = backend._annonce_du_message("x", "Bonjour « ecrivez a paul@exemple.fr svp »")
        self.assertIsNone(titre)

    def test_spam_deux_mots(self):
        self.assertTrue(backend._est_spam('leboncoin', "Gagnez de l'argent", "viagra en ligne"))

    def test_un_mot_ne_suffit_pas(self):
        self.assertFalse(backend._est_spam('leboncoin', "Visite", "Je cherche un bien, mon seo est clair. 0612345678"))

    def test_transfert_sans_coordonnees_avec_liens(self):
        corps = "Viagra offre\nhttp://a.fr/1 http://a.fr/2 http://a.fr/3"
        self.assertTrue(backend._est_spam('portail', "Fwd", corps))
        self.assertFalse(backend._est_spam('portail', "Fwd", corps + "\nTel 06 12 34 56 78"))

    def test_vraie_demande_pas_spam(self):
        self.assertFalse(backend._est_spam('seloger', "Contact", "Bonjour, je souhaite visiter ce bien. 06 12 34 56 78"))


class ReglesRevue(unittest.TestCase):
    """Cas issus de la contre-vérification : faux positifs du filtre, données personnelles dans les titres, fuseau."""

    def test_vrais_messages_jamais_ecartes(self):
        cas = [
            ("leboncoin", "Contact", "Votre T3 rue du Casino m'intéresse, bien issu d'un héritage ? 06 12 34 56 78"),
            ("leboncoin", "Visite", "Je règle en bitcoin ou autre crypto-monnaie, acompte possible. paul@exemple.fr"),
            ("portail", "Fwd", "Contact : jean@seo-immobilier.fr ; bien en héritage, visite ?"),
            ("seloger", "Maison près du Casino, Deauville", "Je vends suite à un héritage, rendement garanti annoncé"),
            ("leboncoin", "Contact", "J'ai gagné à la loterie et je cherche un T4 près du casino de Deauville"),
            ("portail", "Fwd", "Suite à un héritage, je cherche une maison ; prêt personnel accordé http://a.fr/1 http://a.fr/2 http://a.fr/3"),
        ]
        for portail, sujet, corps in cas:
            with self.subTest(corps=corps):
                self.assertFalse(backend._est_spam(portail, sujet, corps))

    def test_un_message_avec_coordonnees_n_est_jamais_ecarte(self):
        self.assertFalse(backend._est_spam('leboncoin', "Offre", "Viagra et porn 06 12 34 56 78"))
        self.assertFalse(backend._est_spam('portail', "Offre", "Viagra et porn paul@exemple.fr"))

    def test_vrai_spam_toujours_ecarte(self):
        self.assertTrue(backend._est_spam('portail', "Fwd", "Viagra http://a.fr/1 http://a.fr/2 http://a.fr/3"))
        self.assertTrue(backend._est_spam('leboncoin', "Offre promotionnelle", "gagnez de l'argent avec xxx"))

    def test_titres_issus_du_texte_libre_du_prospect_ne_sont_pas_retenus(self):
        for corps in ('je suis "Jean Dupont"', '« 14 rue des Lilas, 60300 Senlis »', '"AB-123-CD"',
                      '"Dr Paul Henry, né le 12/03/1980"', '"FR76 3000 6000 0112 3456 7890 189"',
                      '« Mme Durand, 06 1 2 34 56 78 »', 'votre annonce « 14 rue des Lilas, Senlis »'):
            with self.subTest(corps=corps):
                self.assertIsNone(backend._annonce_du_message("Contact", corps)[0])

    def test_titre_apres_le_mot_annonce_et_titre_du_sujet(self):
        self.assertEqual(backend._annonce_du_message("Contact", 'votre annonce « T3 lumineux, Senlis »')[0], "T3 lumineux, Senlis")
        self.assertEqual(backend._annonce_du_message("Demande « Maison 5 pièces, jardin »", "")[0], "Maison 5 pièces, jardin")
        self.assertIsNone(backend._annonce_du_message("Contact « Cliquez http://evil.tld pour votre bonus »", "")[0])
        self.assertIsNone(backend._annonce_du_message("Contact « allez sur evil.xyz maintenant »", "")[0])

    def test_une_reference_n_est_ni_un_telephone_ni_un_debut_d_adresse_e_mail(self):
        for corps in ("Réf: 06.12.34.56.78", "ref #0612345678", "Réf: jean42@gmail.com"):
            with self.subTest(corps=corps):
                self.assertIsNone(backend._annonce_du_message("x", corps)[1])
        self.assertEqual(backend._annonce_du_message("x", "Réf. A123")[1], "A123")

    def test_telephones_avec_separateurs_typographiques(self):
        for texte in ("Tél : 06–12–34–56–78", "Tél : 06/12/34/56/78", "Tél : 06 12 34 56 78",
                      "Tél : 06 12 34 56 78", "+33 (0)6 12 34 56 78"):
            with self.subTest(texte=texte):
                self.assertEqual(backend._telephones_dans(texte), ["0612345678"])

    def test_adresse_a_accent_n_est_pas_tronquee(self):
        self.assertEqual(backend._emails_dans("Écrire à é.jean@exemple.fr"), ["é.jean@exemple.fr"])
        self.assertEqual(backend._emails_dans("Mail : jean.dupont@exemple.fr, merci"), ["jean.dupont@exemple.fr"])

    def test_bornes_de_semaine_en_heure_de_paris(self):
        from datetime import date
        self.assertEqual(backend._minuit_paris_en_utc(date(2026, 7, 6)), datetime(2026, 7, 5, 22, 0))     # heure d'été
        self.assertEqual(backend._minuit_paris_en_utc(date(2026, 1, 5)), datetime(2026, 1, 4, 23, 0))     # heure d'hiver


class DemandeDemo(ts.Base):
    """Formulaire de démonstration du site public."""

    CORPS = {"nom": "Julie Morel", "email": "julie@agence-morel.fr", "agence": "Agence Morel", "ville": "Senlis",
             "telephone": "06 11 22 33 44", "taille": "2-5", "outil": "Ubiflow", "creneau": "matin",
             "message": "Bonjour\nOn aimerait voir le matching."}

    def setUp(self):
        super().setUp()
        self.envoyes = []

        def faux(destinataire, sujet, texte, html, **kw):
            self.envoyes.append({"to": destinataire, "sujet": sujet, "texte": texte, "kw": kw})
            return True
        for p in (mock.patch.object(backend, "_envoyer_email", side_effect=faux),
                  mock.patch.object(backend, "_envoi_configure", return_value=True),
                  mock.patch.object(backend, "_lancer_en_arriere_plan", side_effect=lambda f, *a: f(*a))):
            p.start()
            self.addCleanup(p.stop)

    def envoyer(self, **kw):
        return self.c.post("/api/v1/demande-demo", json={**self.CORPS, **kw})

    def test_demande_complete(self):
        r = self.envoyer()
        self.assertEqual(r.status_code, 200)
        equipe, accuse = self.envoyes
        self.assertEqual(equipe["to"], "contact@zelyro.fr")
        self.assertEqual(equipe["sujet"], "Demande de démo Zelyro : Julie Morel (Agence Morel)")
        for attendu in ("julie@agence-morel.fr", "06 11 22 33 44", "Senlis", "2 à 5 personnes", "Ubiflow",
                        "plutôt le matin", "On aimerait voir le matching"):
            self.assertIn(attendu, equipe["texte"])
        self.assertEqual(equipe["kw"]["repondre_a"], ("julie@agence-morel.fr", "Julie Morel"))
        self.assertEqual(accuse["to"], "julie@agence-morel.fr")
        self.assertIn("Bonjour Julie", accuse["texte"])
        self.assertNotIn("matching", accuse["texte"])          # rien de la saisie, hors prénom

    def test_champs_obligatoires_seulement(self):
        r = self.c.post("/api/v1/demande-demo", json={"nom": "Paul Roy", "email": "paul@exemple.fr", "agence": "Roy Immo"})
        self.assertEqual(r.status_code, 200)

    def test_refus(self):
        for kw in ({"nom": "J"}, {"email": "pas-un-mail"}, {"agence": ""}, {"telephone": "123"},
                   {"taille": "999"}, {"creneau": "minuit"}):
            with self.subTest(kw=kw):
                self.assertEqual(self.envoyer(**kw).status_code, 400)
        self.assertEqual(self.envoyes, [])

    def test_champ_piege_robot(self):
        r = self.envoyer(site_web="http://spam.example")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.envoyes, [])

    def test_pas_d_injection_dans_le_sujet(self):
        self.envoyer(nom="Julie\r\nBcc: x@y.fr", agence="Agence\nMorel")
        self.assertNotRegex(self.envoyes[0]["sujet"], r"[\r\n]")

    def test_limite_par_adresse(self):
        self.assertEqual(self.envoyer().status_code, 200)
        self.assertEqual(self.envoyer().status_code, 200)
        self.assertEqual(self.envoyer().status_code, 429)

    def test_echec_d_envoi_a_l_equipe_est_signale(self):
        with mock.patch.object(backend, "_envoyer_email", return_value=False):
            r = self.envoyer()
        self.assertEqual(r.status_code, 502)
        self.assertIn("contact@zelyro.fr", r.get_json()["message"])

    def test_mails_de_demo_ne_rebouclent_pas(self):
        for sujet in ("Demande de démo Zelyro : Julie Morel (Agence Morel)", "Fwd: Votre demande de démo Zelyro"):
            self.assertTrue(backend._message_de_zelyro("tb@zelyro.fr", sujet, ""))
        self.assertFalse(backend._message_de_zelyro("x@exemple.fr", "Demande de démo", ""))


class Base(BaseInbound):
    def setUp(self):
        super().setUp()
        self.envoyes = []

        def faux(dest, sujet, texte, html, **kw):
            self.envoyes.append({"to": dest, "sujet": sujet, "texte": texte, "html": html})
            return True

        for p in (mock.patch.object(backend, "_envoyer_email", side_effect=faux),
                  mock.patch.dict(os.environ, {"BREVO_API_KEY": "cle", "MAIL_FROM": "contact@zelyro.fr",
                                               "FRONTEND_URL": "https://app.zelyro.fr", "CRON_SECRET": "secret-cron",
                                               "ANTHROPIC_API_KEY": ""})):
            p.start()
            self.addCleanup(p.stop)

    def sql(self, requete, params=()):
        conn = backend.get_db_connection(); cur = conn.cursor()
        cur.execute(requete, params)
        try:
            lignes = cur.fetchall()
        except Exception:
            lignes = None
        conn.commit(); conn.close()
        return lignes

    def stats(self, t, jours=30):
        r = self.c.get(f"/api/v1/reception/stats?days={jours}", headers=self.h(t))
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        return r.get_json()


class Reception(Base):
    def test_spam_ecarte_et_compte(self):
        adresse, t = self.adresse("cm1@x.fr")
        r = self.poster([self.item(adresse, sujet="Offre", texte="Gagnez de l'argent facile avec le viagra et une offre promotionnelle")])
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.c.get("/api/v1/leads", headers=self.h(t)).get_json(), [])
        s = self.stats(t)
        self.assertEqual((s["totals"]["received"], s["totals"]["created"], s["totals"]["spam"]), (1, 0, 1))
        self.assertEqual(s["ignored_reasons"], {"spam": 1})

    def test_vraie_demande_avec_annonce_et_portail(self):
        adresse, t = self.adresse("cm2@x.fr")
        self.poster([self.item(adresse, expediteur="notifications@leboncoin.fr", sujet="Contact pour « T3 lumineux, Senlis »",
                               texte="Réf. A123\nBonjour, je veux visiter. Tel : 06 12 34 56 78")])
        self.poster([self.item(adresse, expediteur="info@seloger.com", sujet="Demande pour « T3 lumineux, Senlis »",
                               texte="Réf. A123\nBonjour, merci de me rappeler au 06 98 76 54 32")])
        s = self.stats(t)
        self.assertEqual((s["totals"]["received"], s["totals"]["created"]), (2, 2))
        self.assertEqual({p["portal"]: p["created"] for p in s["by_portal"]}, {"leboncoin": 1, "seloger": 1})
        self.assertEqual(len(s["by_listing"]), 1)
        a = s["by_listing"][0]
        self.assertEqual((a["title"], a["reference"], a["contacts"]), ("T3 lumineux, Senlis", "A123", 2))
        self.assertEqual(a["portals"], {"LeBonCoin": 1, "SeLoger": 1})

    def test_suppression_d_un_prospect_efface_l_annonce_et_garde_les_statistiques(self):
        adresse, t = self.adresse("cm9@x.fr")
        self.poster([self.item(adresse, expediteur="notifications@leboncoin.fr", sujet="Contact pour « T3 lumineux, Senlis »",
                               texte="Réf. A123\nBonjour, je veux visiter. Tel : 06 12 34 56 78")])
        leads = self.c.get("/api/v1/leads", headers=self.h(t)).get_json()
        self.assertEqual(len(leads), 1)
        avant = self.stats(t)["totals"]
        self.assertEqual(self.c.delete(f"/api/v1/leads/{leads[0]['id']}", headers=self.h(t)).status_code, 200)
        reste = self.sql("""SELECT annonce, annonce_ref, subject FROM inbound_emails
                            WHERE user_id = (SELECT id FROM users WHERE email = 'cm9@x.fr') AND analysis = 'supprime'""")
        self.assertEqual(reste, [(None, None, None)])
        apres = self.stats(t)["totals"]
        self.assertEqual((apres["received"], apres["created"], apres["ignored"]),
                         (avant["received"], avant["created"], avant["ignored"]))

    def test_message_ecarte_recuperable_pendant_30_jours(self):
        adresse, t = self.adresse("cm10@x.fr")
        self.poster([self.item(adresse, sujet="Offre", texte="Gagnez de l'argent facile avec le viagra et une offre promotionnelle")])
        journal = self.c.get("/api/v1/reception/journal", headers=self.h(t)).get_json()
        ecartes = [m for m in journal["messages"] if m["can_rescue"]]
        self.assertEqual(len(ecartes), 1)
        mid = ecartes[0]["id"]
        _, t2 = self.adresse("cm11@x.fr")
        self.assertEqual(self.c.post(f"/api/v1/reception/messages/{mid}/not-spam", headers=self.h(t2)).status_code, 404)
        self.assertEqual(self.c.post("/api/v1/reception/messages/999999999/not-spam", headers=self.h(t)).status_code, 404)
        self.sql("UPDATE inbound_emails SET received_at = received_at - interval '31 days' WHERE id = %s", (mid,))
        backend._purger_journaux()
        self.assertEqual(self.sql("SELECT corps_spam, expediteur_spam FROM inbound_emails WHERE id = %s", (mid,)), [(None, None)])
        self.assertEqual(self.c.post(f"/api/v1/reception/messages/{mid}/not-spam", headers=self.h(t)).status_code, 410)

    def test_alerte_portail_comptee(self):
        adresse, t = self.adresse("cm3@x.fr")
        self.poster([self.item(adresse, sujet="Nouvelles annonces correspondant à vos critères",
                               texte="Voici 12 nouvelles annonces qui correspondent à vos critères de recherche.")])
        s = self.stats(t)
        self.assertEqual(s["totals"]["created"], 0)
        self.assertEqual(s["ignored_reasons"].get("alertes"), 1)

    def test_isolation_entre_agences_et_authentification(self):
        a1, t1 = self.adresse("cm4@x.fr")
        a2, t2 = self.adresse("cm4b@x.fr")
        self.poster([self.item(a1, texte="Bonjour, rappelez-moi au 06 12 34 56 78")])
        self.assertEqual(self.stats(t1)["totals"]["received"], 1)
        self.assertEqual(self.stats(t2)["totals"]["received"], 0)
        self.assertEqual(self.c.get("/api/v1/reception/stats").status_code, 401)

    def test_periode_et_valeur_invalide(self):
        adresse, t = self.adresse("cm5@x.fr")
        self.poster([self.item(adresse, texte="Bonjour, rappelez-moi au 06 12 34 56 78")])
        uid = self.sql("SELECT id FROM users WHERE email = 'cm5@x.fr'")[0][0]
        self.sql("UPDATE inbound_emails SET received_at = %s WHERE user_id = %s", (datetime.utcnow() - timedelta(days=20), uid))
        self.assertEqual(self.stats(t, 7)["totals"]["received"], 0)
        self.assertEqual(self.stats(t, 30)["totals"]["received"], 1)
        self.assertEqual(self.stats(t, 90)["days"], 90)
        r = self.c.get("/api/v1/reception/stats?days=abc", headers=self.h(t))
        self.assertEqual(r.get_json()["days"], 30)
        self.assertEqual(self.c.get("/api/v1/reception/stats?days=5", headers=self.h(t)).get_json()["days"], 30)


class Rapport(Base):
    def agence(self, email):
        td = self.jeton(email)
        id_d = self.sql("SELECT id FROM users WHERE email = %s", (email,))[0][0]
        self.sql("UPDATE users SET first_name = 'Camille' WHERE id = %s", (id_d,))
        mail_e = "collab-" + email
        self.sql("""INSERT INTO users (email, password_hash, first_name, role, agency_owner_id)
                    VALUES (%s, %s, 'Julien', 'employe', %s)""",
                 (mail_e, backend.generate_password_hash(PW, method='pbkdf2:sha256'), id_d))
        te = self.c.post("/auth/login", json={"email": mail_e, "password": PW}).get_json()["token"]
        return td, id_d, te

    def semaine_derniere(self, jour=2):
        aujourdhui = backend._aujourdhui()
        lundi = aujourdhui - timedelta(days=aujourdhui.weekday())
        return datetime.combine(lundi - timedelta(days=7) + timedelta(days=jour), datetime.min.time()) + timedelta(hours=10)

    def message(self, uid, source, quand, portail=None, lead=None, annonce=None, ref=None):
        self.sql("""INSERT INTO inbound_emails (message_id, user_id, source, lead_id, subject, received_at, portail, annonce, annonce_ref)
                    VALUES (%s, %s, %s, %s, 'x', %s, %s, %s, %s)""",
                 (secrets.token_hex(8), uid, source, lead, quand, portail or (source if source in ('leboncoin', 'seloger') else None),
                  annonce, ref))

    def lead_id(self, t):
        r = self.c.post("/api/v1/leads", json={"name": "Camille Martin", "email": f"p{secrets.token_hex(3)}@exemple.fr"},
                        headers=self.h(t))
        return r.get_json().get("id") or r.get_json()["lead"]["id"]

    def isoler(self, *ids):
        self.sql("UPDATE users SET rapport_hebdo_sent_on = %s WHERE NOT (id = ANY(%s))", (backend._aujourdhui(), list(ids)))

    def declencher(self, cle="secret-cron"):
        return self.c.post("/internal/rapport-hebdo/send", headers={"X-Cron-Key": cle} if cle is not None else {})

    def test_protege_par_la_cle(self):
        for cle in (None, "", "mauvaise"):
            self.assertEqual(self.declencher(cle).status_code, 404, cle)
        with mock.patch.dict(os.environ, {"CRON_SECRET": ""}):
            self.assertEqual(self.declencher("").status_code, 404)
        with mock.patch.dict(os.environ, {"BREVO_API_KEY": ""}):
            self.assertEqual(self.declencher().status_code, 503)
        self.assertEqual(self.envoyes, [])

    def test_envoi_au_directeur_une_seule_fois(self):
        td, id_d, te = self.agence("cm-r1@x.fr")
        self.isoler(id_d)
        lead = self.lead_id(td)
        q = self.semaine_derniere()
        self.message(id_d, "leboncoin", q, lead=lead, annonce="T3 lumineux", ref="A123")
        self.message(id_d, "seloger", q, lead=None)
        self.message(id_d, "spam", q, portail="leboncoin")
        r = self.declencher()
        self.assertEqual((r.status_code, r.get_json()["envoyes"]), (200, 1))
        self.assertEqual([m["to"] for m in self.envoyes], ["cm-r1@x.fr"])      # le collaborateur n'en reçoit pas
        mail = self.envoyes[0]
        self.assertIn("3 messages reçus", mail["texte"])
        self.assertIn("1 prospect créé", mail["texte"])
        self.assertIn("T3 lumineux (réf. A123)", mail["texte"])
        self.assertIn("LeBonCoin", mail["texte"])
        self.assertIn("Bonjour Camille", mail["texte"])
        self.assertEqual(self.declencher().get_json()["envoyes"], 0)           # déjà envoyé cette semaine
        self.assertEqual(len(self.envoyes), 1)

    def test_sans_activite_rien_n_est_envoye(self):
        td, id_d, te = self.agence("cm-r2@x.fr")
        self.isoler(id_d)
        self.assertEqual(self.declencher().get_json()["envoyes"], 0)
        self.assertEqual(self.envoyes, [])

    def test_activite_de_cette_semaine_ne_compte_pas(self):
        td, id_d, te = self.agence("cm-r3@x.fr")
        self.isoler(id_d)
        self.message(id_d, "leboncoin", datetime.utcnow() - timedelta(minutes=5))
        aujourdhui = backend._aujourdhui()
        if aujourdhui.weekday() == 0:       # un lundi, « il y a 5 minutes » peut tomber dans la semaine passée
            self.skipTest("lundi")
        self.assertEqual(self.declencher().get_json()["envoyes"], 0)

    def test_exception_pendant_l_envoi_rend_la_semaine(self):
        td, id_d, te = self.agence("cm-r10@x.fr")
        self.isoler(id_d)
        self.message(id_d, "leboncoin", self.semaine_derniere())
        with mock.patch.object(backend, "_envoyer_rapport", side_effect=RuntimeError("panne")):
            self.assertEqual(self.declencher().get_json()["envoyes"], 0)
        self.assertIsNone(self.sql("SELECT rapport_hebdo_sent_on FROM users WHERE id = %s", (id_d,))[0][0])
        self.assertEqual(self.declencher().get_json()["envoyes"], 1)           # le rapport n'est pas perdu

    def test_cle_non_ascii_donne_404(self):
        self.assertEqual(self.declencher("clé-é").status_code, 404)

    def test_desactive_par_le_directeur(self):
        td, id_d, te = self.agence("cm-r4@x.fr")
        self.isoler(id_d)
        self.message(id_d, "leboncoin", self.semaine_derniere())
        r = self.c.put("/auth/preferences", json={"rapport_hebdo_enabled": False}, headers=self.h(td))
        self.assertEqual((r.status_code, r.get_json()), (200, {"rapport_hebdo_enabled": False}))
        self.assertFalse(self.c.get("/auth/profile", headers=self.h(td)).get_json()["rapport_hebdo_enabled"])
        self.assertEqual(self.declencher().get_json()["envoyes"], 0)
        self.c.put("/auth/preferences", json={"rapport_hebdo_enabled": True}, headers=self.h(td))
        self.assertEqual(self.declencher().get_json()["envoyes"], 1)

    def test_valeur_invalide(self):
        td, id_d, te = self.agence("cm-r5@x.fr")
        for v in ("oui", 1, None):
            self.assertEqual(self.c.put("/auth/preferences", json={"rapport_hebdo_enabled": v}, headers=self.h(td)).status_code, 400)

    def test_echec_d_envoi_permet_de_reessayer(self):
        td, id_d, te = self.agence("cm-r6@x.fr")
        self.isoler(id_d)
        self.message(id_d, "leboncoin", self.semaine_derniere())
        with mock.patch.object(backend, "_envoyer_email", return_value=False):
            self.assertEqual(self.declencher().get_json()["envoyes"], 0)
        self.assertIsNone(self.sql("SELECT rapport_hebdo_sent_on FROM users WHERE id = %s", (id_d,))[0][0])
        self.assertEqual(self.declencher().get_json()["envoyes"], 1)

    def test_apercu_reserve_au_directeur(self):
        td, id_d, te = self.agence("cm-r7@x.fr")
        self.assertEqual(self.c.post("/api/v1/rapport-hebdo/preview", headers=self.h(te)).status_code, 403)
        self.assertEqual(self.c.post("/api/v1/rapport-hebdo/preview").status_code, 401)
        r = self.c.post("/api/v1/rapport-hebdo/preview", headers=self.h(td))
        self.assertEqual((r.status_code, r.get_json()["sent"]), (200, False))         # aucune activité
        self.message(id_d, "leboncoin", self.semaine_derniere())
        r = self.c.post("/api/v1/rapport-hebdo/preview", headers=self.h(td))
        self.assertEqual((r.status_code, r.get_json()["sent"]), (200, True))
        self.assertEqual(self.envoyes[-1]["to"], "cm-r7@x.fr")

    def test_contenu_echappe(self):
        td, id_d, te = self.agence("cm-r8@x.fr")
        self.isoler(id_d)
        lead = self.lead_id(td)
        self.message(id_d, "leboncoin", self.semaine_derniere(), lead=lead, annonce="<script>alert(1)</script> Maison")
        self.declencher()
        self.assertNotIn("<script>", self.envoyes[0]["html"])


class MessageTransfere(Base):
    """Un message transféré par Gmail garde son destinataire d'origine en « À » : l'adresse de réception de
    l'agence n'est que dans les destinataires de l'enveloppe (« Recipients » chez Brevo)."""

    def transfere(self, adresse, recipients, **kw):
        it = self.item(adresse, expediteur="notifications@seloger.com", sujet="Nouveau contact pour votre annonce",
                       texte="Nom : Sophie Martin\nTéléphone : 06 00 00 00 01\nBonjour, je veux visiter ce bien.")
        it["To"] = [{"Address": "tb@zelyro.fr", "Name": ""}]
        it["Recipients"] = recipients
        it.update(kw)
        return it

    def test_adresse_dans_les_destinataires_de_l_enveloppe(self):
        adresse, t = self.adresse("cm-t1@x.fr")
        for forme in ([adresse], [{"Address": adresse}], [{"Address": adresse.upper()}], [f"<{adresse}>"]):
            r = self.poster([self.transfere(adresse, forme)])
            self.assertEqual(r.status_code, 200)
        self.assertEqual(len(self.c.get("/api/v1/leads", headers=self.h(t)).get_json()), 4)

    def test_sans_adresse_de_reception_rien_n_est_cree(self):
        adresse, t = self.adresse("cm-t2@x.fr")
        self.poster([self.transfere(adresse, ["autre@exemple.fr"])])
        self.assertEqual(self.c.get("/api/v1/leads", headers=self.h(t)).get_json(), [])

    def test_valeurs_inattendues_sans_erreur(self):
        adresse, t = self.adresse("cm-t3@x.fr")
        for recipients in (None, "n'importe quoi", 5, [None, 3, {}], {"Address": "x@y.fr"}):
            self.assertEqual(self.poster([self.transfere(adresse, recipients)]).status_code, 200)
        self.assertEqual(self.c.get("/api/v1/leads", headers=self.h(t)).get_json(), [])


class FormulaireAutomatique(Base):
    """Le mail « Précisez votre recherche » part aussi pour un message quelconque, avec des garde-fous."""

    def setUp(self):
        super().setUp()
        p = mock.patch.object(backend, "_lancer_en_arriere_plan", side_effect=lambda f, *a: f(*a))
        p.start()
        self.addCleanup(p.stop)

    def mails_formulaire(self):
        return [m for m in self.envoyes if m["sujet"].startswith("Précisez votre recherche")]

    def envoyer(self, adresse, expediteur="paul.durand@exemple.fr", sujet="Visite de la maison à Senlis",
                texte="Bonjour, je suis intéressé par la maison. Nom : Paul Durand\nTéléphone : 06 11 22 33 44", **kw):
        it = self.item(adresse, expediteur=expediteur, sujet=sujet, texte=texte)
        it.update(kw)
        r = self.poster([it])
        self.assertEqual(r.status_code, 200)

    def leads(self, t):
        return self.c.get("/api/v1/leads", headers=self.h(t)).get_json()

    def test_message_quelconque_recoit_le_formulaire(self):
        adresse, t = self.adresse("cm-f1@x.fr")
        self.envoyer(adresse)
        self.assertEqual(len(self.leads(t)), 1)
        mails = self.mails_formulaire()
        self.assertEqual([m["to"] for m in mails], ["paul.durand@exemple.fr"])
        self.assertNotIn(" via ", mails[0]["texte"])
        self.assertIn("Vous avez contacté", mails[0]["texte"])
        self.assertRegex(mails[0]["texte"], r"completer\.html\?")

    def test_adresse_du_texte_prioritaire_sur_l_expediteur(self):
        adresse, t = self.adresse("cm-f2@x.fr")
        self.envoyer(adresse, texte="Bonjour, Nom : Paul Durand\nEmail : paul.vrai@exemple.fr\nTéléphone : 06 11 22 33 44")
        self.assertEqual([m["to"] for m in self.mails_formulaire()], ["paul.vrai@exemple.fr"])

    def test_portail_reconnu_garde_son_texte(self):
        adresse, t = self.adresse("cm-f3@x.fr")
        self.envoyer(adresse, expediteur="notifications@seloger.com", sujet="Nouveau contact pour votre annonce",
                     texte="Nom : Sophie Martin\nEmail : sophie@exemple.fr\nTéléphone : 06 00 00 00 01\nBonjour, je veux visiter.")
        mails = self.mails_formulaire()
        self.assertEqual([m["to"] for m in mails], ["sophie@exemple.fr"])
        self.assertIn("via SeLoger", mails[0]["texte"])

    def test_message_automatique_sans_reponse(self):
        adresse, t = self.adresse("cm-f4@x.fr")
        for entetes in ("Auto-Submitted: auto-replied\nFrom: x", ["Precedence: bulk", "To: y"], "List-Unsubscribe: <mailto:x@y.fr>",
                        "X-Auto-Response-Suppress: All"):
            self.envoyer(adresse, expediteur=f"auto{secrets.token_hex(2)}@exemple.fr", Headers=entetes,
                         texte=f"Bonjour, absente jusqu'à lundi. Tel : 06 {secrets.randbelow(90) + 10} 22 33 44")
        self.assertEqual(self.mails_formulaire(), [])
        self.assertEqual(len(self.leads(t)), 4)         # les prospects, eux, sont bien créés

    def test_expediteur_automatique_sans_reponse(self):
        adresse, t = self.adresse("cm-f5@x.fr")
        self.envoyer(adresse, expediteur="noreply@exemple.fr")
        self.envoyer(adresse, expediteur="notifications@exemple.fr", texte="Bonjour, nouvelle alerte. Tel : 06 99 88 77 66")
        self.assertEqual(self.mails_formulaire(), [])

    def test_transfert_manuel_sans_formulaire_au_transfereur(self):
        adresse, t = self.adresse("cm-f6@x.fr")
        self.envoyer(adresse, expediteur="hugo@agence.fr", sujet="Fwd: Nouveau contact",
                     texte="Bonjour, je veux visiter. Nom : Paul Durand\nTéléphone : 06 11 22 33 44")
        self.assertEqual(len(self.leads(t)), 1)
        self.assertEqual(self.mails_formulaire(), [])

    def test_jamais_a_un_collaborateur_de_l_agence(self):
        adresse, t = self.adresse("cm-f7@x.fr")
        id_d = self.sql("SELECT id FROM users WHERE email = 'cm-f7@x.fr'")[0][0]
        self.sql("""INSERT INTO users (email, password_hash, first_name, role, agency_owner_id)
                    VALUES ('collegue-f7@x.fr', %s, 'Julien', 'employe', %s)""",
                 (backend.generate_password_hash(PW, method='pbkdf2:sha256'), id_d))
        self.envoyer(adresse, expediteur="collegue-f7@x.fr")
        self.envoyer(adresse, expediteur="cm-f7@x.fr", texte="Bonjour, test. Tel : 06 55 44 33 22")
        self.assertEqual(self.mails_formulaire(), [])

    def test_boucle_notification_zelyro_ignoree(self):
        """Une notification de Zelyro renvoyée par un filtre Gmail ne crée ni prospect ni nouveau mail."""
        adresse, t = self.adresse("cm-f20@x.fr")
        avant = len(self.envoyes)
        with mock.patch.dict(os.environ, {"MAIL_FROM": "contact@zelyro.fr"}):
            # 1. expéditeur = adresse d'envoi de Zelyro
            self.envoyer(adresse, expediteur="contact@zelyro.fr", sujet="Nouveau prospect : Thomas Lefèvre",
                         texte="Thomas Lefèvre vous a contacté. Tel : 06 11 22 33 44")
            # 2. transféré à la main : sujet et texte de Zelyro
            self.envoyer(adresse, expediteur="tb@zelyro.fr", sujet="Fwd: Nouveau prospect via SeLoger : Sophie Martin",
                         texte="Bonjour, Sophie Martin vous a contacté via une annonce SeLoger. Tel : 06 22 33 44 55")
            # 3. seul le texte trahit l'origine
            self.envoyer(adresse, expediteur="tb@zelyro.fr", sujet="Fwd: info",
                         texte="Paul vous a contacté par e-mail, capté automatiquement par Zelyro. Tel : 06 33 44 55 66")
            # 4. le formulaire envoyé au prospect
            self.envoyer(adresse, expediteur="tb@zelyro.fr", sujet="Précisez votre recherche — Agence Test",
                         texte="Bonjour, merci. Tel : 06 44 55 66 77")
        self.assertEqual(self.leads(t), [])
        self.assertEqual(len(self.envoyes), avant)
        n = self.sql("SELECT COUNT(*) FROM inbound_emails WHERE source = 'zelyro-boucle'")[0][0]
        self.assertGreaterEqual(n, 4)

    def test_mail_normal_de_la_meme_adresse_garde_son_prospect(self):
        adresse, t = self.adresse("cm-f21@x.fr")
        with mock.patch.dict(os.environ, {"MAIL_FROM": "contact@zelyro.fr"}):
            self.envoyer(adresse, expediteur="tb@zelyro.fr", sujet="Demande de visite - maison Senlis",
                         texte="Bonjour, je veux visiter. Nom : Paul Durand\nTéléphone : 06 11 22 33 44")
        self.assertEqual(len(self.leads(t)), 1)

    def test_frein_notifications_en_rafale(self):
        adresse, t = self.adresse("cm-f22@x.fr")
        notifs = lambda: [m for m in self.envoyes if m["sujet"].startswith("Nouveau prospect")]
        with mock.patch.object(backend, "NOTIFICATIONS_PROSPECT_PAR_HEURE", 3):
            for i in range(6):
                self.envoyer(adresse, expediteur=f"rafale{i}@exemple.fr", sujet=f"Visite {i}",
                             texte=f"Bonjour, je veux visiter. Nom : Paul Durand{i}\nTéléphone : 06 11 22 33 4{i}")
        self.assertEqual(len(self.leads(t)), 6)
        self.assertEqual(len(notifs()), 3)

    def test_plafond_par_jour(self):
        adresse, t = self.adresse("cm-f8@x.fr")
        with mock.patch.object(backend, "FORMULAIRES_AUTO_PAR_JOUR", 2):
            for i in range(4):
                self.envoyer(adresse, expediteur=f"prospect{i}@exemple.fr", texte=f"Bonjour, Nom : Paul Durand\nTéléphone : 06 11 22 33 4{i}")
        self.assertEqual(len(self.mails_formulaire()), 2)
        self.assertEqual(len(self.leads(t)), 4)

    def test_pas_de_formulaire_si_opposition(self):
        adresse, t = self.adresse("cm-f9@x.fr")
        uid = self.sql("SELECT id FROM users WHERE email = 'cm-f9@x.fr'")[0][0]
        self.sql("INSERT INTO contact_opposition (user_id, email_hash) VALUES (%s, %s)", (uid, backend._empreinte_email("paul.durand@exemple.fr")))
        self.envoyer(adresse)
        self.assertEqual(self.mails_formulaire(), [])


class LectureDesCoordonnees(unittest.TestCase):
    """Formes de numéros et d'adresses vues dans de vrais messages, et bruit numérique qui n'est pas un numéro."""

    def test_formes_de_numero_reconnues(self):
        n = "0612345678"
        formes = ["06 12 34 56 78", "06.12.34.56.78", "06-12-34-56-78", n, "+33 6 12 34 56 78", "+33612345678",
                  "0033612345678", "+33 (0)6 12 34 56 78", "06\u00a012\u00a034\u00a056\u00a078", "06\u202f12\u202f34\u202f56\u202f78",
                  "06–12–34–56–78", "06/12/34/56/78", "0612 345 678", "061 234 5678", "06  12  34  56  78", "0 6 12 34 56 78"]
        for f in formes:
            self.assertEqual(backend._telephones_dans(f"Bonjour, rappelez-moi au {f} merci"), [n], f)

    def test_bruit_numerique_n_est_pas_un_numero(self):
        for b in ["Prix : 380 000 €", "Prix 1 250 000 euros", "Budget 0 à 300 000", "Référence 0612345", "Code postal 75006 Paris",
                  "annonce n° 2345678901", "SIRET 123 456 789 00012", "Le 12/10/2026 à 14h30", "Le 01 02 2026 à 10 30",
                  "DPE 142 kWh/m²/an GES 28", "Total 10 501 234 567", "code 0612345678901", "Rdv le 12.06.2026 à 14.30 puis 15.45",
                  "Loyer 1 150 € + 120 € de charges", "https://www.seloger.com/annonces/123456789.htm?ref=0612345678"]:
            self.assertEqual(backend._telephones_dans("Bonjour, " + b + ". Merci."), [], b)

    def test_adresses_e_mail(self):
        for e in ["sophie.martin@example.com", "jean+immo@gmail.com", "élodie.durand@orange.fr", "o'brien@exemple.fr",
                  "o\u2019brien@exemple.fr", "a_b-c@sub.domaine.co.uk"]:
            for contexte in ("Email : {}", "<{}>", "({})", "écrivez-moi à {}, merci", "mailto:{}", "{}.", "'{}'"):
                self.assertEqual(backend._emails_dans("Bonjour. " + contexte.format(e)), [e.lower()], contexte.format(e))

    def test_adresses_du_portail_exclues(self):
        for e in ["noreply@seloger.com", "notification@leboncoin.fr", "no-reply@service.brevo.com", "postmaster@x.fr"]:
            self.assertEqual(backend._emails_dans("Mail " + e), [], e)


if __name__ == "__main__":
    unittest.main()
