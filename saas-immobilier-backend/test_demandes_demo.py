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
UA = {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) AppleWebKit Mobile Safari"}
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
ok(sql("SELECT count(*) FROM site_visites WHERE page IN ('/demo-agences','/demo-merci')")[0][0] == 2, "demo-agences et demo-merci sont maintenant comptées dans les visites")
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

patch1.stop(); patch2.stop()
cur.execute("DELETE FROM users WHERE email LIKE '%@t.test'"); conn.commit()
print("\nÉCHEC" if ok.failed else "\nTOUS LES TESTS PASSENT")
sys.exit(1 if ok.failed else 0)
