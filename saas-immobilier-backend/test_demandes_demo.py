"""Tests des demandes de démonstration (enregistrement, notifications rejouables, espace administrateur, export,
mesure du parcours) contre une vraie base PostgreSQL.

    TEST_DATABASE_URL=postgresql://user:mdp@localhost/base_de_test python3 test_demandes_demo.py

ATTENTION : la base indiquée reçoit des données de test (adresses @t.test) ; utilisez une base de test.
Aucun e-mail réel n'est envoyé : l'envoi (Brevo) est remplacé par un double qui enregistre les appels.
"""
import os, sys, json
if not os.getenv("TEST_DATABASE_URL"):
    sys.exit("Définissez TEST_DATABASE_URL (une base de test, jamais celle de production).")
os.environ.update(DATABASE_URL=os.environ["TEST_DATABASE_URL"], SECRET_KEY="x" * 48, FRONTEND_URL="https://app.test",
                  RATELIMIT_STORAGE_URI="memory://", ANTHROPIC_API_KEY="", BREVO_API_KEY="cle-de-test",
                  MAIL_FROM="demo@zelyro.test", ADMIN_EMAILS="admin@t.test", CRON_SECRET="secret-cron-test")
HERE = os.path.dirname(os.path.abspath(__file__))
import importlib.util
spec = importlib.util.spec_from_file_location("appz", os.path.join(HERE, "app.py"))
appz = importlib.util.module_from_spec(spec); spec.loader.exec_module(appz)
import jwt
from datetime import datetime, timedelta, timezone
from unittest import mock

appz.init_database()
appz._assurer_schema()
conn = appz.get_db_connection(); cur = conn.cursor()
cur.execute("DELETE FROM demandes_demo"); cur.execute("DELETE FROM acquisition_depenses")
cur.execute("DELETE FROM site_evenements"); cur.execute("DELETE FROM site_visites")
cur.execute("DELETE FROM users WHERE email LIKE '%@t.test'"); conn.commit()


def ok(cond, msg):
    print(("OK   " if cond else "FAIL ") + msg)
    if not cond:
        ok.failed = True
ok.failed = False


def mk(email):
    cur.execute("""INSERT INTO users (email, password_hash, first_name, company_name, plan, role, ia_enabled)
                   VALUES (%s,'x','Test','Agence Test','agence','admin',TRUE) RETURNING id""", (email,))
    i = cur.fetchone()[0]; conn.commit(); return i


def tok(uid):
    cur.execute("SELECT token_version FROM users WHERE id=%s", (uid,)); v = cur.fetchone()[0]; conn.commit()
    return jwt.encode({"id": uid, "v": v, "exp": datetime.now(timezone.utc) + timedelta(hours=1)}, appz.SECRET_KEY, algorithm="HS256")


def sql(q, p=()):
    cur.execute(q, p); r = cur.fetchall() if cur.description else None; conn.commit(); return r


admin_h = {"Authorization": "Bearer " + tok(mk("admin@t.test"))}
autre_h = {"Authorization": "Bearer " + tok(mk("agence@t.test"))}
c = appz.app.test_client()
appz.limiter.enabled = False

# --- doubles : e-mails enregistrés, envoi en arrière-plan rendu synchrone
envois = []
etat = {"mode": "ok"}      # ok | refus | exception


def faux_envoi(dest, sujet, texte, html, nom_expediteur=None, repondre_a=None, pieces_jointes=None):
    envois.append({"dest": dest, "sujet": sujet, "texte": texte, "expediteur": nom_expediteur, "reply": repondre_a})
    if etat["mode"] == "exception":
        raise RuntimeError("panne simulée")
    return etat["mode"] == "ok"


def synchrone(f, *a):
    f(*a)


patch1 = mock.patch.object(appz, "_envoyer_email", faux_envoi)
patch2 = mock.patch.object(appz, "_lancer_en_arriere_plan", synchrone)
patch1.start(); patch2.start()

REF1 = "a1b2c3d4e5f60718293a4b5c"


def demande(**kw):
    d = {"id_demande": REF1, "nom": "Claire Moreau", "agence": "Agence du Marais", "email": "claire@t.test",
         "telephone": "06 12 34 56 78", "fonction": "dirigeant", "site_web": "",
         "utm_source": "facebook", "utm_medium": "paid", "utm_campaign": "test_a", "utm_content": "video_1",
         "clic_pub": "meta", "page": "/demo-agences.html", "referent": "https://l.instagram.com/x?u=1", "w": 390}
    d.update(kw)
    return {k: v for k, v in d.items() if v is not None}


def post(d, h=None):
    return c.post("/api/v1/demande-demo", json=d, headers=h or {"User-Agent": "Mozilla/5.0 (iPhone) Mobile"})


# ---------------------------------------------------------------- 1. enregistrement et notifications
r = post(demande())
ok(r.status_code == 200 and r.get_json().get("ref") == REF1 and r.get_json().get("doublon") is False, "demande valide : 200 avec la référence")
lignes = sql("SELECT * FROM demandes_demo")
ok(len(lignes) == 1, "la demande est enregistrée en base (une ligne)")
cols = [d[0] for d in cur.description]; L = dict(zip(cols, lignes[0])) if lignes else {}
ok(L.get("canal") == "meta" and L.get("clic_pub") is True and L.get("source") == "facebook" and L.get("campagne") == "test_a"
   and L.get("contenu") == "video_1", "source d'acquisition et paramètres UTM conservés")
ok(L.get("fonction") == "Dirigeant ou gérant" and L.get("decideur") is True, "fonction et décideur enregistrés")
ok(L.get("appareil") == "mobile" and L.get("referent") == "l.instagram.com" and L.get("page") == "/demo-agences",
   "appareil, référent (domaine seul) et page enregistrés")
ok(L.get("statut") == "nouvelle" and L.get("cree_le") is not None, "statut commercial initial et horodatage")
ok(L.get("notif_statut") == "envoyee" and L.get("accuse_statut") == "envoye" and L.get("notif_tentatives") == 1,
   "notification et accusé marqués envoyés")
equipe = [e for e in envois if e["dest"] == "contact@zelyro.fr"]
accuse = [e for e in envois if e["dest"] == "claire@t.test"]
ok(len(equipe) == 1 and len(accuse) == 1, "un e-mail à l'équipe et un accusé au visiteur")
ok(equipe[0]["reply"][0] == "claire@t.test" and equipe[0]["expediteur"] == "Zelyro · demandes de démo",
   "Reply-To = adresse du prospect ; expéditeur = nom de Zelyro (pas celui du visiteur)")
ok("Dirigeant ou gérant" in equipe[0]["texte"] and "facebook" in equipe[0]["texte"] and REF1 in equipe[0]["texte"],
   "l'e-mail d'équipe contient la fonction, l'origine et la référence")
ok("Claire" in accuse[0]["texte"] and "06 12" not in accuse[0]["texte"] and "Marais" not in accuse[0]["texte"],
   "l'accusé ne reprend que le prénom")

# ---------------------------------------------------------------- 2. doublons
n = len(envois)
r = post(demande())
ok(r.status_code == 200 and sql("SELECT count(*) FROM demandes_demo")[0][0] == 1 and len(envois) == n,
   "même identifiant renvoyé (double clic) : succès, aucune ligne ni e-mail de plus")
r = post(demande(id_demande="b" * 24))
ok(r.status_code == 200 and r.get_json()["doublon"] is True and sql("SELECT count(*) FROM demandes_demo")[0][0] == 1
   and len(envois) == n and sql("SELECT nb_soumissions FROM demandes_demo")[0][0] == 2,
   "même adresse dans la semaine : doublon signalé, compteur incrémenté, pas de nouvel e-mail")
r = post(demande(id_demande="c" * 24, email="CLAIRE@T.TEST"))
ok(r.get_json()["doublon"] is True and sql("SELECT count(*) FROM demandes_demo")[0][0] == 1, "doublon insensible à la casse de l'adresse")

# ---------------------------------------------------------------- 3. validation, robots
ok(post(demande(nom="A", id_demande="d" * 24)).status_code == 400, "nom trop court refusé")
ok(post(demande(email="pas-un-mail", id_demande="d" * 24)).status_code == 400, "e-mail invalide refusé")
ok(post(demande(agence="", id_demande="d" * 24)).status_code == 400, "agence manquante refusée")
ok(post(demande(telephone="123", email="x1@t.test", id_demande="d" * 24)).status_code == 400, "téléphone trop court refusé")
ok(post(demande(telephone=None, fonction=None, email="sans-tel@t.test", id_demande="e" * 24)).status_code == 200
   and sql("SELECT telephone, fonction FROM demandes_demo WHERE email='sans-tel@t.test'")[0] == (None, None),
   "téléphone et fonction facultatifs côté serveur")
av = sql("SELECT count(*) FROM demandes_demo")[0][0]
r = post(demande(site_web="http://spam", email="robot@t.test", id_demande="f" * 24))
ok(r.status_code == 200 and sql("SELECT count(*) FROM demandes_demo")[0][0] == av, "champ piège : fausse réussite, rien d'enregistré")
r = post(demande(email="inj@t.test", id_demande="1" * 24, utm_source="<script>alert(1)</script>meta", utm_campaign="x\r\nBcc: a@b.c"))
Linj = sql("SELECT source, campagne FROM demandes_demo WHERE email='inj@t.test'")[0]
ok(r.status_code == 200 and "<" not in Linj[0] and "\n" not in Linj[1] and ":" in Linj[1], "paramètres UTM nettoyés (balises, retours à la ligne)")
r = post(demande(email="mauvaisref@t.test", id_demande="ZZ"))
ok(r.status_code == 200 and len(r.get_json()["ref"]) == 24, "référence invalide du navigateur : le serveur en génère une")
r = post(demande(email="direct@t.test", id_demande="2" * 24, utm_source=None, utm_medium=None, clic_pub=None, referent=None))
ok(sql("SELECT canal FROM demandes_demo WHERE email='direct@t.test'")[0][0] == "direct", "canal direct sans paramètre")
r = post(demande(email="g@t.test", id_demande="3" * 24, utm_source=None, clic_pub="google"))
ok(sql("SELECT canal FROM demandes_demo WHERE email='g@t.test'")[0][0] == "google", "canal Google d'après le clic publicitaire")

# ---------------------------------------------------------------- 4. panne de messagerie : la demande n'est jamais perdue
etat["mode"] = "refus"; envois.clear()
r = post(demande(email="panne@t.test", id_demande="4" * 24))
Lp = sql("SELECT notif_statut, notif_tentatives, notif_erreur, accuse_statut FROM demandes_demo WHERE email='panne@t.test'")
ok(r.status_code == 200 and len(Lp) == 1, "messagerie en refus : la demande est enregistrée et le visiteur reçoit 200")
ok(Lp[0][0] == "echec" and Lp[0][1] == 1 and Lp[0][2], "notification en échec, tentative et cause notées")
etat["mode"] = "exception"
r = post(demande(email="panne2@t.test", id_demande="5" * 24))
ok(r.status_code == 200 and sql("SELECT notif_statut FROM demandes_demo WHERE email='panne2@t.test'")[0][0] == "echec",
   "exception de la messagerie : demande enregistrée, notification en échec")
etat["mode"] = "ok"; envois.clear()
# renvoi automatique (tâche planifiée) : trop tôt, rien ne part
rc = c.post("/internal/demandes-demo/relance", headers={"X-Cron-Key": "secret-cron-test"})
ok(rc.status_code == 200 and rc.get_json()["envoyees"] == 0, "relance automatique : respecte le délai d'attente de 5 minutes")
ok(c.post("/internal/demandes-demo/relance").status_code == 404 and c.post("/internal/demandes-demo/relance", headers={"X-Cron-Key": "faux"}).status_code == 404,
   "relance automatique : refusée sans la clé")
sql("UPDATE demandes_demo SET notif_derniere_tentative = (now() at time zone 'utc') - interval '10 minutes', accuse_derniere_tentative = (now() at time zone 'utc') - interval '10 minutes'")
rc = c.post("/internal/demandes-demo/relance", headers={"X-Cron-Key": "secret-cron-test"})
ok(rc.get_json()["envoyees"] == 2, "relance automatique après le délai : les 2 notifications en échec repartent")
ok(sql("SELECT count(*) FROM demandes_demo WHERE notif_statut <> 'envoyee'")[0][0] == 0, "plus aucune notification en échec")
ok(len([e for e in envois if e["dest"] == "contact@zelyro.fr"]) == 2, "exactement un e-mail d'équipe par demande relancée (aucun doublon)")
n = len(envois); c.post("/internal/demandes-demo/relance", headers={"X-Cron-Key": "secret-cron-test"})
ok(len(envois) == n, "une seconde relance n'envoie plus rien")

# abandon après 6 tentatives, puis renvoi manuel
etat["mode"] = "refus"
post(demande(email="abandon@t.test", id_demande="6" * 24))
for _ in range(7):
    sql("UPDATE demandes_demo SET notif_derniere_tentative = (now() at time zone 'utc') - interval '10 minutes' WHERE email='abandon@t.test'")
    c.post("/internal/demandes-demo/relance", headers={"X-Cron-Key": "secret-cron-test"})
La = sql("SELECT id, notif_statut, notif_tentatives FROM demandes_demo WHERE email='abandon@t.test'")[0]
ok(La[1] == "abandon" and La[2] == 6, "après 6 tentatives la notification est abandonnée (visible, non perdue)")
etat["mode"] = "ok"
ok(c.post(f"/admin/demandes-demo/{La[0]}/renvoyer").status_code == 401, "renvoi manuel : refusé sans connexion administrateur")
ok(c.post(f"/admin/demandes-demo/{La[0]}/renvoyer", headers=autre_h).status_code == 404, "renvoi manuel : refusé à un non-administrateur")
r = c.post(f"/admin/demandes-demo/{La[0]}/renvoyer", headers=admin_h)
ok(r.status_code == 200 and r.get_json()["demande"]["notif_statut"] == "envoyee", "renvoi manuel par l'administrateur : notification partie")
etat["mode"] = "refus"
post(demande(email="lot1@t.test", id_demande="7" * 24)); post(demande(email="lot2@t.test", id_demande="8" * 24))
etat["mode"] = "ok"
r = c.post("/admin/demandes-demo/relancer", headers=admin_h)
ok(r.status_code == 200 and r.get_json()["envoyees"] >= 2 and sql("SELECT count(*) FROM demandes_demo WHERE notif_statut <> 'envoyee'")[0][0] == 0,
   "relance groupée par l'administrateur")

# messagerie non configurée : la demande est quand même enregistrée
with mock.patch.dict(os.environ, {"BREVO_API_KEY": ""}):
    r = post(demande(email="nonconf@t.test", id_demande="9" * 24))
    Lc = sql("SELECT notif_statut, notif_erreur FROM demandes_demo WHERE email='nonconf@t.test'")[0]
    ok(r.status_code == 200 and Lc[0] == "echec" and "configur" in (Lc[1] or ""), "messagerie non configurée : demande enregistrée, cause visible")
c.post("/internal/demandes-demo/relance", headers={"X-Cron-Key": "secret-cron-test"})

# base indisponible : on le dit, rien n'est compté
with mock.patch.object(appz, "_enregistrer_demande", side_effect=RuntimeError("base coupée")):
    r = post(demande(email="base@t.test", id_demande="0" * 24))
ok(r.status_code == 503 and "contact@zelyro.fr" in r.get_json()["message"], "base indisponible : 503 (le site ne comptera aucune demande)")

# ---------------------------------------------------------------- 5. limites de débit
appz.limiter.enabled = True
codes = [post(demande(email=f"rl{i}@t.test", id_demande=("%024x" % (100 + i)))).status_code for i in range(7)]
ok(codes[:5] == [200] * 5 and 429 in codes[5:], "limite de débit : 5 demandes par heure et par adresse IP")
appz.limiter.enabled = False
appz.limiter.reset()

# ---------------------------------------------------------------- 6. espace administrateur
ok(c.get("/admin/demandes-demo").status_code == 401 and c.get("/admin/demandes-demo", headers=autre_h).status_code == 404,
   "liste : refusée sans connexion, invisible pour un non-administrateur")
r = c.get("/admin/demandes-demo", headers=admin_h); J = r.get_json()
ok(r.status_code == 200 and len(J["demandes"]) >= 8 and J["messagerie_prete"] is True, "liste des demandes pour l'administrateur")
r = c.get("/admin/demandes-demo?canal=meta&q=claire@t.test", headers=admin_h)
ok(all(d["canal"] == "meta" for d in r.get_json()["demandes"]) and len(r.get_json()["demandes"]) == 1, "filtres canal et recherche")
idc = sql("SELECT id FROM demandes_demo WHERE email='claire@t.test'")[0][0]
r = c.put(f"/admin/demandes-demo/{idc}", json={"statut": "demo_realisee"}, headers=admin_h); D = r.get_json()
ok(r.status_code == 200 and D["statut"] == "demo_realisee" and D["qualifiee_le"] and D["demo_programmee_le"] and D["demo_realisee_le"]
   and not D["client_le"], "passer en « démo réalisée » renseigne aussi les étapes précédentes")
r = c.put(f"/admin/demandes-demo/{idc}", json={"statut": "client", "note": "Signé =cmd|' /C calc'!A0"}, headers=admin_h)
ok(r.get_json()["client_le"] and r.get_json()["statut"] == "client", "passage en client")
r = c.put(f"/admin/demandes-demo/{idc}", json={"statut": "qualifiee"}, headers=admin_h); D = r.get_json()
ok(D["qualifiee_le"] and not D["demo_programmee_le"] and not D["demo_realisee_le"] and not D["client_le"], "retour en arrière : les étapes suivantes sont effacées")
c.put(f"/admin/demandes-demo/{idc}", json={"statut": "client"}, headers=admin_h)
ok(c.put(f"/admin/demandes-demo/{idc}", json={"statut": "inconnu"}, headers=admin_h).status_code == 400, "statut inconnu refusé")
ok(c.put("/admin/demandes-demo/999999", json={"note": "x"}, headers=admin_h).status_code == 404, "demande inexistante : 404")
ok(c.put(f"/admin/demandes-demo/{idc}", json={"demo_prevue_le": "2026-12-01T10:00:00Z"}, headers=admin_h).get_json()["demo_prevue_le"].startswith("2026-12-01T10:00"),
   "date de démonstration prévue")
idg = sql("SELECT id FROM demandes_demo WHERE email='g@t.test'")[0][0]
c.put(f"/admin/demandes-demo/{idg}", json={"statut": "qualifiee"}, headers=admin_h)
idp = sql("SELECT id FROM demandes_demo WHERE email='panne@t.test'")[0][0]
c.put(f"/admin/demandes-demo/{idp}", json={"statut": "perdue"}, headers=admin_h)

# dépenses et coût d'acquisition
ok(c.post("/admin/acquisition/depenses", json={"canal": "meta", "debut": "2026-11-16", "fin": "2026-11-22", "montant_eur": "210,00", "note": "test 7 jours"},
          headers=admin_h).status_code == 201, "dépense saisie (virgule décimale acceptée)")
ok(c.post("/admin/acquisition/depenses", json={"canal": "tv", "debut": "2026-11-16", "montant_eur": 5}, headers=admin_h).status_code == 400, "canal inconnu refusé")
ok(c.post("/admin/acquisition/depenses", json={"canal": "meta", "debut": "2026-11-16", "montant_eur": -5}, headers=admin_h).status_code == 400, "montant négatif refusé")
ok(c.post("/admin/acquisition/depenses", json={"canal": "meta", "debut": "2026-11-16", "montant_eur": 5}).status_code == 401, "dépense : refusée sans connexion")
Jd = c.get("/admin/acquisition/depenses", headers=admin_h).get_json()["depenses"]
ok(len(Jd) == 1 and Jd[0]["montant_eur"] == 210.0, "liste des dépenses")
sql("UPDATE acquisition_depenses SET debut = current_date, fin = current_date")
r = c.get("/admin/demandes-demo/resume?jours=30", headers=admin_h); R = r.get_json()
meta = next(x for x in R["canaux"] if x["canal"] == "meta")
ok(r.status_code == 200 and meta["clients"] == 1 and meta["realisees"] == 1 and meta["qualifiees"] == 1 and meta["depense_eur"] == 210.0,
   "résumé : entonnoir et dépense du canal Meta")
ok(meta["cout_acquisition"] == 210.0 and meta["cout_par_demande"] == round(210.0 / meta["demandes"], 2) and meta["taux_client"] == round(100.0 / meta["demandes"], 1),
   "résumé : coût d'acquisition (dépense / clients), coût par demande, taux de transformation")
gg = next(x for x in R["canaux"] if x["canal"] == "google")
ok(gg["cout_acquisition"] is None and gg["depense_eur"] is None, "pas de coût affiché quand aucune dépense n'est saisie")
ok(R["total"]["demandes"] == sum(x["demandes"] for x in R["canaux"]) and R["sante"]["messagerie_prete"] is True, "résumé : totaux et santé de la messagerie")

# export CSV
r = c.get("/admin/demandes-demo/export.csv", headers=admin_h)
corps = r.data.decode("utf-8")
ok(r.status_code == 200 and corps.startswith("﻿") and "attachment" in r.headers["Content-Disposition"] and r.headers["Cache-Control"] == "no-store",
   "export CSV : UTF-8 avec BOM, en pièce jointe, non mis en cache")
ok(corps.count("\n") >= 9 and "claire@t.test" in corps and corps.split("\n")[0].startswith("﻿ref;cree_le;nom"), "export CSV : en-têtes et lignes")
cur.execute("UPDATE demandes_demo SET nom = %s WHERE id = %s", ("=HYPERLINK(\"http://x\")", idg)); conn.commit()
corps = c.get("/admin/demandes-demo/export.csv", headers=admin_h).data.decode("utf-8")
ok(";'=HYPERLINK" in corps.replace('"', '') or "'=HYPERLINK" in corps, "export CSV : cellule commençant par = neutralisée (injection de formules)")
ok(c.get("/admin/demandes-demo/export.csv").status_code == 401 and c.get("/admin/demandes-demo/export.csv", headers=autre_h).status_code == 404,
   "export CSV : réservé à l'administrateur")
ok(sql("SELECT count(*) FROM admin_log WHERE action = 'demandes_demo_exportees'")[0][0] >= 2, "export journalisé")

# effacement
idr = sql("SELECT id FROM demandes_demo WHERE email='robot@t.test'")
idl = sql("SELECT id FROM demandes_demo WHERE email='lot1@t.test'")[0][0]
ok(c.delete(f"/admin/demandes-demo/{idl}", headers=admin_h).status_code == 200 and not sql("SELECT 1 FROM demandes_demo WHERE id=%s", (idl,)),
   "effacement définitif d'une demande (RGPD)")

# ---------------------------------------------------------------- 7. mesure du parcours
UA = {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) AppleWebKit Mobile Safari", "Accept-Language": "fr-FR,fr;q=0.9"}
ev = lambda **k: c.post("/public/stats/evenement", data=json.dumps(dict({"p": "/demo-agences.html", "w": 390, "s": "facebook", "c": "test_a"}, **k)), headers=UA)
ok(ev(e="cta_clic").status_code == 204 and ev(e="formulaire_debut").status_code == 204 and ev(e="video_lecture").status_code == 204
   and ev(e="formulaire_erreur", d="email").status_code == 204, "événements du parcours acceptés (204)")
ok(sql("SELECT count(*) FROM site_evenements")[0][0] == 4 and sql("SELECT detail FROM site_evenements WHERE evenement='formulaire_erreur'")[0][0] == "email",
   "événements enregistrés, nom du champ seulement")
ev(e="n_importe_quoi"); ev(e="cta_clic", p="/page-inconnue")
ok(sql("SELECT count(*) FROM site_evenements")[0][0] == 4, "événement ou page hors liste : ignoré")
c.post("/public/stats/evenement", data=json.dumps({"p": "/demo-agences.html", "e": "cta_clic"}), headers=dict(UA, DNT="1"))
c.post("/public/stats/evenement", data=json.dumps({"p": "/demo-agences.html", "e": "cta_clic"}), headers=dict(UA, **{"Sec-GPC": "1"}))
ok(sql("SELECT count(*) FROM site_evenements")[0][0] == 4, "« Ne pas me suivre » (DNT, GPC) : rien n'est enregistré")
c.post("/public/stats/evenement", data=json.dumps({"p": "/demo-agences.html", "e": "cta_clic"}), headers={"User-Agent": "Googlebot/2.1"})
ok(sql("SELECT count(*) FROM site_evenements")[0][0] == 4, "robots : rien n'est enregistré")
ok(sql("SELECT count(*) FROM information_schema.columns WHERE table_name='site_evenements' AND column_name IN ('ip','adresse_ip')")[0][0] == 0,
   "aucune colonne d'adresse IP")
# les pages de prospection sont enfin mesurées
c.post("/public/stats/vue", data=json.dumps({"p": "/demo-agences.html", "w": 390, "s": "facebook", "c": "test_a"}), headers=UA)
c.post("/public/stats/vue", data=json.dumps({"p": "/demo-merci.html", "w": 390}), headers=dict(UA, **{"X-Forwarded-For": "10.1.1.1"}))
ok(sql("SELECT count(*) FROM site_visites WHERE page IN ('/demo-agences','/demo-merci')")[0][0] == 2, "demo-agences et demo-merci sont enregistrées dans les visites (la seconde, sans demande, comme suspecte : voir section 8)")
R = c.get("/admin/demandes-demo/resume?jours=30", headers=admin_h).get_json()["parcours_page"]
ok(R["visiteurs"] == 1 and R["clic_bouton"] == 1 and R["formulaire_commence"] == 1 and R["video_lue"] == 1 and R["erreurs_formulaire"] == 1,
   "résumé : parcours de la page (visiteurs, bouton, formulaire commencé, vidéo, erreurs)")

# ---------------------------------------------------------------- 8. conservation
sql("UPDATE demandes_demo SET cree_le = (now() at time zone 'utc') - interval '4 years', dernier_contact_le = NULL WHERE email='g@t.test'")
sql("UPDATE demandes_demo SET cree_le = (now() at time zone 'utc') - interval '4 years', dernier_contact_le = NULL WHERE email='claire@t.test'")
appz._purger_demandes_demo()
ok(not sql("SELECT 1 FROM demandes_demo WHERE email='g@t.test'") and sql("SELECT 1 FROM demandes_demo WHERE email='claire@t.test'"),
   "purge à 3 ans : demande ancienne effacée, client conservé")
ok(sql("SELECT count(*) FROM demandes_demo WHERE cree_le > (now() at time zone 'utc') - interval '1 day'")[0][0] > 5, "les demandes récentes sont conservées")


# ---------------------------------------------------------------- 9. classification des sources (SEO, GEO, annuaires)
CAS = [
    # (utm_source, utm_medium, clic_pub, hôte d'origine, canal attendu)
    ("facebook", "paid", "meta", "l.instagram.com", "meta"),
    (None, None, "meta", None, "meta"),
    ("google", "cpc", "google", None, "google"),
    (None, None, "google", "google.fr", "google"),
    (None, None, "", "www.google.fr", "google_organique"),
    (None, None, "", "google.com", "google_organique"),
    (None, None, "", "google.co.uk", "google_organique"),
    ("google", "organic", "", None, "google_organique"),
    (None, None, "", "www.bing.com", "bing_organique"),
    ("bing", "organic", "", None, "bing_organique"),
    ("chatgpt.com", None, "", None, "chatgpt"),
    (None, None, "", "chatgpt.com", "chatgpt"),
    (None, None, "", "chat.openai.com", "chatgpt"),
    (None, None, "", "www.perplexity.ai", "perplexity"),
    ("perplexity", None, "", None, "perplexity"),
    (None, None, "", "gemini.google.com", "gemini"),
    ("gemini", "referral", "", None, "gemini"),
    (None, None, "", "claude.ai", "claude"),
    (None, None, "", "copilot.microsoft.com", "copilot"),
    (None, None, "", "www.appvizer.fr", "appvizer"),
    ("appvizer", "listing", "", None, "appvizer"),
    (None, None, "", "www.capterra.com", "capterra"),
    (None, None, "", "capterra.fr", "capterra"),
    (None, None, "", "lnkd.in", "linkedin"),
    ("newsletter", "email", "", None, "email"),
    ("harvey", None, "", None, "email"),
    ("partenaire", "lien", "", None, "autre"),
    (None, None, "", "blog-immo.example", "referent"),
    (None, None, "", "mail.google.com", "referent"),
    (None, None, "", "www.zelyro.fr", "direct"),
    (None, None, "", None, "direct"),
    # pièges : un domaine qui ressemble sans être le bon ne doit pas passer
    (None, None, "", "chatgpt.com.pirate.example", "referent"),
    (None, None, "", "notgoogle.fr", "referent"),
    (None, None, "", "google.fr.pirate.example", "referent"),
]
for s_, m_, cp_, h_, attendu in CAS:
    obtenu = appz._canal_demande(s_, m_, cp_, h_)
    ok(obtenu == attendu, f"canal {attendu} : source={s_} medium={m_} clic={cp_ or '-'} domaine={h_} (obtenu {obtenu})")
ok(all(appz._canal_demande(*x[:4]) in appz.DEMO_CANAUX for x in CAS), "tout canal calculé figure dans la liste des canaux")
ok(len(appz.DEMO_CANAUX) == len(set(appz.DEMO_CANAUX)) and all(len(x) <= 20 for x in appz.DEMO_CANAUX), "canaux uniques et compatibles avec la colonne (20 caractères)")

# Mêmes règles pour les visites (colonne source de site_visites).
with appz.app.test_request_context("/"):
    VIS = [({"s": "chatgpt.com"}, "chatgpt"), ({"r": "https://chatgpt.com/c/secret-123?x=1"}, "chatgpt"),
           ({"r": "https://www.perplexity.ai/search/abc"}, "perplexity"), ({"r": "https://gemini.google.com/app"}, "gemini"),
           ({"r": "https://claude.ai/chat/uuid"}, "claude"), ({"r": "https://copilot.microsoft.com/"}, "copilot"),
           ({"r": "https://www.google.fr/search?q=logiciel+agence"}, "google-organique"), ({"r": "https://www.bing.com/search?q=x"}, "bing-organique"),
           ({"r": "https://www.appvizer.fr/immobilier"}, "appvizer"), ({"r": "https://www.capterra.com/p/1/x"}, "capterra"),
           ({"r": "https://mail.google.com/mail/u/0/"}, "e-mail"), ({"s": "facebook"}, "facebook"), ({"s": "google"}, "google"),
           ({"r": "https://blog-immo.example/article"}, "blog-immo.example"), ({}, "direct")]
    for dn, attendu in VIS:
        obtenu = appz._source_stats(dn)
        ok(obtenu == attendu, f"visite : {dn} -> {attendu} (obtenu {obtenu})")
        ok("secret" not in obtenu and "?" not in obtenu and "/" not in obtenu, "visite : aucun chemin ni paramètre du site d'origine n'est conservé")
for nom, canal in [("chatgpt", "chatgpt"), ("google-organique", "google_organique"), ("bing-organique", "bing_organique"), ("facebook", "meta"),
                   ("google", "google"), ("e-mail", "email"), ("blog-immo.example", "referent"), ("campagne-x", "autre"), ("direct", "direct"), ("interne", None)]:
    ok(appz._canal_depuis_source_visite(nom) == canal, f"visite {nom} rattachée au canal {canal}")

# Origine portée par le lien jusqu'au formulaire (le visiteur a changé de page sur zelyro.fr entre-temps).
sql("DELETE FROM demandes_demo WHERE email LIKE %s", ("src%@t.test",))
r = post(demande(id_demande="d1" * 12, email="src1@t.test", utm_source=None, utm_medium=None, clic_pub=None,
                 referent="https://www.zelyro.fr/logiciel-agence-immobiliere.html", referent_origine="chatgpt.com"))
ok(r.status_code == 200 and sql("SELECT canal, referent FROM demandes_demo WHERE email='src1@t.test'")[0] == ("chatgpt", "chatgpt.com"),
   "origine portée par le lien : une demande venue de ChatGPT puis d'une page du site est classée « chatgpt »")
r = post(demande(id_demande="d2" * 12, email="src2@t.test", utm_source=None, utm_medium=None, clic_pub=None,
                 referent="https://www.perplexity.ai/search/x?q=secret", referent_origine="chatgpt.com"))
ok(sql("SELECT canal, referent FROM demandes_demo WHERE email='src2@t.test'")[0] == ("perplexity", "perplexity.ai"),
   "le référent direct prime sur l'origine portée, et seul le nom de domaine est enregistré")
r = post(demande(id_demande="d3" * 12, email="src3@t.test", utm_source=None, utm_medium=None, clic_pub=None,
                 referent="https://www.zelyro.fr/tarifs.html", referent_origine="https://pirate.example/a?b=c#d"))
ok(sql("SELECT canal, referent FROM demandes_demo WHERE email='src3@t.test'")[0] == ("referent", "pirate.example"),
   "origine portée : seul le nom de domaine est gardé (ni chemin, ni paramètres)")
r = post(demande(id_demande="d4" * 12, email="src4@t.test", utm_source=None, utm_medium=None, clic_pub=None,
                 referent="https://www.google.fr/", referent_origine=None))
ok(sql("SELECT canal FROM demandes_demo WHERE email='src4@t.test'")[0][0] == "google_organique", "demande venue de Google sans publicité : « google_organique »")
sql("UPDATE demandes_demo SET statut='client', qualifiee_le=now() at time zone 'utc', client_le=now() at time zone 'utc' WHERE email='src1@t.test'")

# Visites par canal dans le résumé de l'espace administrateur.
for i, (ref_, s_) in enumerate([("https://chatgpt.com/", None), ("https://www.google.fr/", None), ("https://www.capterra.com/x", None), (None, "linkedin")]):
    d_ = {"p": "/tarifs.html", "w": 1400}
    if ref_: d_["r"] = ref_
    if s_: d_["s"] = s_
    c.post("/public/stats/vue", data=json.dumps(d_), headers=dict({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Test%d" % i, "Accept-Language": "fr"}, **{"X-Forwarded-For": "10.9.9.%d" % (i + 1)}))
R = c.get("/admin/demandes-demo/resume?jours=30", headers=admin_h).get_json()
par = {x["canal"]: x for x in R["canaux"]}
ok(par.get("chatgpt", {}).get("visites", 0) >= 1 and par["chatgpt"]["demandes"] == 1 and par["chatgpt"]["clients"] == 1 and par["chatgpt"]["qualifiees"] == 1,
   "résumé : le canal ChatGPT montre visites, demande, qualifiée et client")
ok(par.get("google_organique", {}).get("visites", 0) >= 1 and par.get("capterra", {}).get("visites", 0) >= 1 and par.get("linkedin", {}).get("visites", 0) >= 1,
   "résumé : visites par canal (Google organique, Capterra, LinkedIn)")
ok(par["chatgpt"].get("taux_visite_demande") is not None, "résumé : taux visite -> demande calculé")
ok(c.post("/admin/acquisition/depenses", json={"canal": "chatgpt", "debut": "2026-11-16", "montant_eur": 5}, headers=admin_h).status_code in (200, 201),
   "les nouveaux canaux sont acceptés pour la saisie de dépenses (ex. annuaire payant)")
ok(c.get("/admin/demandes-demo?canal=chatgpt", headers=admin_h).get_json()["demandes"] != [], "filtre par canal ChatGPT")

# ---------------------------------------------------------------- 8. conversions fiables et nature des visites
import threading
HUMAIN = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
          "Accept-Language": "fr-FR,fr;q=0.9"}
conf = lambda ref, h=None: c.post("/api/v1/demande-demo/confirmation", json={"ref": ref}, headers=h or HUMAIN)
conv = lambda r: r.get_json().get("conversion") if r.status_code in (200, 503) else None
ref_n = lambda n: "%024x" % (0xc0ffee000000 + n)

# --- 8.1 confirmation : une seule conversion, seulement pour une demande réellement en base
r = post(demande(email="conv1@t.test", id_demande=ref_n(1)), HUMAIN)
ok(r.status_code == 200 and r.get_json()["ref"] == ref_n(1), "8.1 demande enregistrée avant toute mesure")
ok(sql("SELECT conversion_le FROM demandes_demo WHERE ref=%s", (ref_n(1),))[0][0] is None, "8.1 une demande qui vient d'être enregistrée n'est pas encore « mesurée »")
r = conf(ref_n(1))
ok(r.status_code == 200 and r.get_json() == {"conversion": True}, "8.1 première confirmation : conversion autorisée, réponse minimale (aucune donnée personnelle)")
ok(sql("SELECT conversion_le FROM demandes_demo WHERE ref=%s", (ref_n(1),))[0][0] is not None, "8.1 la mesure est notée en base sur la demande")
ok(conv(conf(ref_n(1))) is False and conv(conf(ref_n(1))) is False, "8.2 rechargement ou second onglet : plus de conversion (même demande, même confirmation)")

# --- 8.3 fausses conversions
ok(conv(conf(ref_n(999))) is False, "8.3 identifiant bien formé mais inconnu (inventé) : aucune conversion")
for faux in ("", "abc", "G" * 24, "a" * 23, "a" * 25, "'; DROP TABLE demandes_demo;--", None, 12345, ["x"], {"a": 1}):
    r = c.post("/api/v1/demande-demo/confirmation", json={"ref": faux}, headers=HUMAIN)
    ok(r.status_code == 200 and r.get_json() == {"conversion": False}, "8.3 identifiant invalide refusé : %r" % (faux,))
r = c.post("/api/v1/demande-demo/confirmation", data="pas du json", headers=HUMAIN)
ok(r.status_code == 200 and r.get_json() == {"conversion": False}, "8.3 corps illisible : aucune conversion")
ok(c.post("/api/v1/demande-demo/confirmation", json={}, headers=HUMAIN).get_json() == {"conversion": False}, "8.3 sans identifiant : aucune conversion")
ok(c.get("/api/v1/demande-demo/confirmation").status_code == 405, "8.3 la route n'accepte que POST (pas d'appel par simple lien)")
r = post(demande(email="piege@t.test", id_demande=ref_n(2), site_web="http://spam.test"), HUMAIN)
ok(r.status_code == 200 and "ref" not in r.get_json() and not sql("SELECT 1 FROM demandes_demo WHERE email='piege@t.test'"),
   "8.3 robot du champ piège : réponse sans identifiant, rien en base, donc aucune conversion possible")
ok(conv(conf(ref_n(2))) is False, "8.3 l'identifiant du robot du champ piège ne produit aucune conversion")
r = post(demande(email="", id_demande=ref_n(3)), HUMAIN)
ok(r.status_code == 400 and conv(conf(ref_n(3))) is False, "8.3 formulaire refusé (400) : aucune conversion")

# --- 8.4 robots et requêtes sans langue : refusés SANS consommer la conversion
post(demande(email="conv4@t.test", id_demande=ref_n(4)), HUMAIN)
for nom, h in (("Googlebot", {"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "Accept-Language": "fr"}),
               ("navigateur sans interface", {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/126.0 Safari/537.36", "Accept-Language": "fr"}),
               ("ChatGPT-User", {"User-Agent": "Mozilla/5.0 AppleWebKit/537.36 (compatible; ChatGPT-User/1.0)", "Accept-Language": "en"}),
               ("script curl", {"User-Agent": "curl/8.5.0"}),
               ("sans User-Agent", {"User-Agent": "", "Accept-Language": "fr"}),
               ("sans langue", {"User-Agent": HUMAIN["User-Agent"]})):
    ok(conv(conf(ref_n(4), h)) is False, "8.4 %s : aucune conversion" % nom)
ok(sql("SELECT conversion_le FROM demandes_demo WHERE ref=%s", (ref_n(4),))[0][0] is None, "8.4 …et la conversion de la vraie personne reste disponible")
ok(conv(conf(ref_n(4))) is True, "8.4 la vraie personne obtient ensuite sa conversion")

# --- 8.5 délai : une demande ancienne ne peut plus être mesurée
post(demande(email="conv5@t.test", id_demande=ref_n(5)), HUMAIN)
sql("UPDATE demandes_demo SET cree_le = cree_le - interval '2 hours' WHERE ref=%s", (ref_n(5),))
ok(conv(conf(ref_n(5))) is False, "8.5 demande enregistrée depuis plus d'une heure : aucune conversion")

# --- 8.6 doublon : la même personne qui renvoie le formulaire n'est pas comptée deux fois
r1 = post(demande(email="dbl@t.test", id_demande=ref_n(6)), HUMAIN).get_json()
r2 = post(demande(email="dbl@t.test", id_demande=ref_n(7)), HUMAIN).get_json()
ok(r1["doublon"] is False and r2["doublon"] is True and r2["ref"] == ref_n(6), "8.6 second envoi reconnu comme doublon, même référence")
ok(conv(conf(r1["ref"])) is True, "8.6 la première demande donne une conversion")
ok(conv(conf(r2["ref"])) is False, "8.6 le doublon (même référence) ne produit pas de seconde conversion")
ok(sql("SELECT count(*) FROM demandes_demo WHERE email='dbl@t.test'")[0][0] == 1, "8.6 une seule demande en base")
# demande dont la page de confirmation n'a jamais été vue, puis renvoi : mesurée une fois, pas deux
r1 = post(demande(email="dbl2@t.test", id_demande=ref_n(8)), HUMAIN).get_json()
r2 = post(demande(email="dbl2@t.test", id_demande=ref_n(9)), HUMAIN).get_json()
ok(conv(conf(r2["ref"])) is True and conv(conf(r1["ref"])) is False, "8.6 onglet fermé avant la confirmation puis renvoi : mesurée une seule fois")

# --- 8.7 appels simultanés : un seul « vrai »
post(demande(email="conv7@t.test", id_demande=ref_n(10)), HUMAIN)
resultats = []
def appel():
    cl = appz.app.test_client()
    resultats.append(cl.post("/api/v1/demande-demo/confirmation", json={"ref": ref_n(10)}, headers=HUMAIN).get_json()["conversion"])
fils = [threading.Thread(target=appel) for _ in range(10)]
[f.start() for f in fils]; [f.join() for f in fils]
ok(len(resultats) == 10 and resultats.count(True) == 1, "8.7 dix appels simultanés : exactement une conversion (%d)" % resultats.count(True))

# --- 8.8 panne de base : aucune conversion, jamais de « true » par défaut
post(demande(email="conv8@t.test", id_demande=ref_n(11)), HUMAIN)
with mock.patch.object(appz, "_base", side_effect=RuntimeError("base coupée")):
    r = conf(ref_n(11))
ok(r.status_code == 503 and r.get_json() == {"conversion": False}, "8.8 base indisponible : 503 et aucune conversion")
ok(conv(conf(ref_n(11))) is True, "8.8 une fois la base revenue, la conversion reste possible (non consommée à tort)")

# --- 8.9 nature des visites : humain, robot, suspect
sql("DELETE FROM site_visites"); sql("DELETE FROM site_direct")
vue = lambda p, h, w=1280, **k: c.post("/public/stats/vue", data=json.dumps(dict({"p": p, "w": w}, **k)), headers=h)
nat = lambda page: sql("SELECT nature, raison FROM site_visites WHERE page=%s ORDER BY id DESC LIMIT 1", (page,))
fx = lambda i: {"X-Forwarded-For": "10.20.0.%d" % i}
vue("/tarifs.html", dict(HUMAIN, **fx(1)))
ok(nat("/tarifs") == [("humain", None)], "8.9 visiteur humain : « humain »")
ok(sql("SELECT count(*) FROM site_direct")[0][0] == 1, "8.9 un humain est « en direct »")
casse = [("/login.html", "Googlebot", {"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1)", "Accept-Language": "fr"}, ("robot", "agent_robot")),
         ("/cgu.html", "Bingbot", {"User-Agent": "Mozilla/5.0 (compatible; bingbot/2.0)", "Accept-Language": "fr"}, ("robot", "agent_robot")),
         ("/mentions-legales.html", "GPTBot", {"User-Agent": "Mozilla/5.0 AppleWebKit/537.36 (compatible; GPTBot/1.1)"}, ("robot", "agent_robot")),
         ("/confidentialite.html", "Chrome sans interface", {"User-Agent": "Mozilla/5.0 HeadlessChrome/126.0", "Accept-Language": "fr"}, ("robot", "agent_robot")),
         ("/annonces.html", "Perplexity-User", {"User-Agent": "Mozilla/5.0 (compatible; Perplexity-User/1.0)", "Accept-Language": "en"}, ("robot", "agent_robot")),
         ("/rdv.html", "outil de test de vitesse", {"User-Agent": "Mozilla/5.0 Chrome-Lighthouse", "Accept-Language": "en"}, ("robot", "agent_robot")),
         ("/formulaire.html", "sans User-Agent", {"User-Agent": "", "Accept-Language": "fr"}, ("robot", "sans_agent")),
         ("/completer.html", "script (curl)", {"User-Agent": "curl/8.5.0"}, ("robot", "agent_robot")),
         ("/rejoindre-agence.html", "sans langue", {"User-Agent": HUMAIN["User-Agent"]}, ("suspect", "sans_langue"))]
for i, (page, nom, h, attendu) in enumerate(casse):
    vue(page, dict(h, **fx(30 + i)))
    ok(nat(page[:-5]) == [attendu], "8.9 %s : %s / %s" % (nom, attendu[0], attendu[1]))
ok(sql("SELECT count(*) FROM site_direct")[0][0] == 1, "8.9 robots et suspects ne sont jamais « en direct »")
# vrais navigateurs qui ne doivent PAS être pris pour des robots
for i, (nom, ua) in enumerate([("LinkedIn (navigateur intégré)", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 [LinkedInApp]/9.30"),
                               ("Instagram (navigateur intégré)", "Mozilla/5.0 (iPhone) AppleWebKit/605.1.15 Mobile/15E148 Instagram 330.0"),
                               ("Facebook (navigateur intégré)", "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/126 Mobile Safari/537.36 [FB_IAB/FB4A;FBAV/460.0]"),
                               ("Safari iPhone", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Version/17.5 Mobile/15E148 Safari/604.1"),
                               ("Firefox", "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0")]):
    vue("/rdv.html" if i == 0 else "/tarifs.html", {"User-Agent": ua, "Accept-Language": "fr-FR", **fx(60 + i)}, w=390)
    ok(nat("/rdv" if i == 0 else "/tarifs")[0][0] == "humain", "8.9 %s : reste « humain »" % nom)
# taille d'écran impossible
for i, w in enumerate((None, 0, -5, 20000, "abc")):
    corps = {"p": "/annonces.html"}
    if w is not None: corps["w"] = w
    c.post("/public/stats/vue", data=json.dumps(corps), headers=dict(HUMAIN, **fx(80 + i)))
    ok(nat("/annonces") == [("suspect", "ecran_invalide")], "8.9 largeur d'écran %r : suspect" % (w,))
# « Ne pas me suivre » : rien du tout
avant = sql("SELECT count(*) FROM site_visites")[0][0]
vue("/cgu.html", dict(HUMAIN, DNT="1", **fx(90))); vue("/cgu.html", dict(HUMAIN, **{"Sec-GPC": "1"}, **fx(91)))
ok(sql("SELECT count(*) FROM site_visites")[0][0] == avant, "8.9 « Ne pas me suivre » : rien n'est enregistré, même comme robot")

# --- 8.10 page de confirmation : visite humaine seulement après une demande enregistrée
sql("DELETE FROM site_visites")
vue("/demo-merci.html", dict(HUMAIN, **fx(100)))
ok(nat("/demo-merci") == [("suspect", "merci_sans_demande")], "8.10 /demo-merci sans identifiant de demande : suspect")
vue("/demo-merci.html", dict(HUMAIN, **fx(101)), m=ref_n(777))
ok(nat("/demo-merci") == [("suspect", "merci_sans_demande")], "8.10 /demo-merci avec un identifiant inventé : suspect")
vue("/demo-merci.html", dict(HUMAIN, **fx(102)), m="pas-un-identifiant")
ok(nat("/demo-merci") == [("suspect", "merci_sans_demande")], "8.10 /demo-merci avec un identifiant mal formé : suspect")
vue("/demo-merci.html", dict(HUMAIN, **fx(103)), m=ref_n(5))      # demande de 2 heures, mais < 24 h
ok(nat("/demo-merci") == [("humain", None)], "8.10 /demo-merci juste après une vraie demande : visite humaine")
sql("UPDATE demandes_demo SET cree_le = cree_le - interval '30 hours' WHERE ref=%s", (ref_n(5),))
vue("/demo-merci.html", dict(HUMAIN, **fx(104)), m=ref_n(5))
ok(nat("/demo-merci") == [("suspect", "merci_sans_demande")], "8.10 /demo-merci avec une demande de plus de 24 h : suspect")
vue("/demo-merci.html", {"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1)", "Accept-Language": "fr", **fx(105)}, m=ref_n(6))
ok(nat("/demo-merci") == [("robot", "agent_robot")], "8.10 robot sur /demo-merci, même avec un identifiant valide : robot")
n_presence = sql("SELECT count(*) FROM site_direct WHERE page='/demo-merci'")[0][0]
c.post("/public/stats/presence", data=json.dumps({"p": "/demo-merci.html", "w": 1280, "m": ref_n(6)}), headers=dict(HUMAIN, **fx(103)))
ok(sql("SELECT count(*) FROM site_direct WHERE page='/demo-merci'")[0][0] == n_presence == 0, "8.10 la page de confirmation n'est jamais « en direct »")

# --- 8.11 rafale : trop de pages différentes en quelques minutes
sql("DELETE FROM site_visites"); sql("DELETE FROM site_direct")
pages = sorted(appz.STATS_PAGES - {'demo-merci'})
bot_rafale = dict(HUMAIN, **fx(120))
for p in pages[:appz.STATS_RAFALE_PAGES]:
    vue("/" + p + ".html", bot_rafale)
ok(sql("SELECT count(*) FROM site_visites WHERE nature='humain'")[0][0] == appz.STATS_RAFALE_PAGES, "8.11 %d pages en 10 minutes : encore humain" % appz.STATS_RAFALE_PAGES)
vue("/" + pages[appz.STATS_RAFALE_PAGES] + ".html", bot_rafale)
ok(sql("SELECT nature, raison FROM site_visites ORDER BY id DESC LIMIT 1") == [("suspect", "rafale")], "8.11 la page suivante est une rafale : suspect")

# --- 8.12 le tableau de bord ne compte que les humains et montre les autres à part
sql("DELETE FROM site_visites"); sql("DELETE FROM site_direct")
for i in range(3):
    vue("/tarifs.html", dict(HUMAIN, **fx(140 + i)))
vue("/tarifs.html", {"User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1)", "Accept-Language": "fr", **fx(150)})
vue("/tarifs.html", {"User-Agent": "Mozilla/5.0 HeadlessChrome/126", "Accept-Language": "fr", **fx(151)})
vue("/cgu.html", {"User-Agent": HUMAIN["User-Agent"], **fx(152)})
D = c.get("/admin/stats/direct", headers=admin_h).get_json()
ok(D["aujourdhui"]["visites"] == 3 and D["aujourdhui"]["visiteurs"] == 3, "8.12 en direct : « aujourd'hui » ne compte que les 3 humains")
ok(D["aujourdhui"]["robots"] == 2 and D["aujourdhui"]["suspects"] == 1, "8.12 en direct : 2 robots et 1 visite suspecte affichés à part")
ok(D["en_direct"] == 3, "8.12 « sur le site maintenant » : 3 humains")
ok(sorted({j["nature"] for j in D["journal"]}) == ["humain", "robot", "suspect"] and all("raison" in j for j in D["journal"]),
   "8.12 le journal montre la nature et la raison de chaque visite")
Rz = c.get("/admin/stats/resume?jours=30", headers=admin_h).get_json()
ok(Rz["totaux"]["visites"] == 3 and Rz["totaux"]["visiteurs"] == 3, "8.12 bilan : totaux humains seulement")
ok(sum(p["visites"] for p in Rz["pages"]) == 3 and sum(a["visites"] for a in Rz["appareils"]) == 3
   and sum(s["visites"] for s in Rz["sources"]) == 3, "8.12 bilan : pages, sources et appareils sans robots")
q = Rz["qualite"]
ok(q["humain"]["visites"] == 3 and q["robot"]["visites"] == 2 and q["suspect"]["visites"] == 1, "8.12 qualité du trafic : 3 humains, 2 robots, 1 suspect")
ok({(r["nature"], r["raison"]): r["visites"] for r in q["raisons"]} == {("robot", "agent_robot"): 2, ("suspect", "sans_langue"): 1},
   "8.12 qualité du trafic : raisons détaillées")
vide = c.get("/admin/stats/resume?jours=1", headers=admin_h).get_json()["qualite"]
ok(set(vide) >= {"humain", "robot", "suspect", "raisons"}, "8.12 les trois natures sont toujours présentes")
ok(c.get("/admin/stats/direct").status_code == 401 and c.get("/admin/stats/resume", headers=autre_h).status_code in (403, 404),
   "8.12 espace réservé à l'administrateur")
# acquisition : les robots n'entrent pas dans les visiteurs par canal
sql("DELETE FROM site_visites")
vue("/demo-agences.html", dict(HUMAIN, **fx(160)), s="facebook")
vue("/demo-agences.html", {"User-Agent": "Mozilla/5.0 (compatible; bingbot/2.0)", "Accept-Language": "fr", **fx(161)}, s="facebook")
Ra = c.get("/admin/demandes-demo/resume?jours=30", headers=admin_h).get_json()
ok(Ra["parcours_page"]["visiteurs"] == 1, "8.12 acquisition : un robot sur la page de démonstration n'est pas un visiteur (%s)" % Ra["parcours_page"]["visiteurs"])

# --- 8.13 base existante : colonnes ajoutées sans perte, anciennes lignes = humain
sql("INSERT INTO site_visites (visiteur, page, cree_le) VALUES ('ancienne00000000', '/tarifs', now() at time zone 'utc')")
ok(sql("SELECT nature, raison FROM site_visites WHERE visiteur='ancienne00000000'") == [("humain", None)], "8.13 ancienne ligne (sans nature) : humain")
sql("ALTER TABLE site_visites DROP COLUMN nature"); sql("ALTER TABLE site_visites DROP COLUMN raison"); sql("ALTER TABLE demandes_demo DROP COLUMN conversion_le")
appz._schema_pret = False
appz._assurer_schema()
ok(sql("SELECT count(*) FROM information_schema.columns WHERE (table_name='site_visites' AND column_name IN ('nature','raison')) "
       "OR (table_name='demandes_demo' AND column_name='conversion_le')")[0][0] == 3,
   "8.13 une base existante reçoit les trois colonnes au démarrage (contrôle de schéma)")
ok(sql("SELECT nature FROM site_visites WHERE visiteur='ancienne00000000'") == [("humain",)], "8.13 les lignes existantes restent « humain »")
sql("DELETE FROM site_visites WHERE visiteur='ancienne00000000'")

patch1.stop(); patch2.stop()
cur.execute("DELETE FROM users WHERE email LIKE '%@t.test'"); conn.commit()
print("\nÉCHEC" if ok.failed else "\nTOUS LES TESTS PASSENT")
sys.exit(1 if ok.failed else 0)
