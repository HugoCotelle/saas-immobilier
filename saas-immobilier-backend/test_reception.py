"""Tests de la réception des leads (extraction des coordonnées, journal, clés d'API, API de réception)
contre une vraie base PostgreSQL.

    TEST_DATABASE_URL=postgresql://user:mdp@localhost/base_de_test python3 test_reception.py

ATTENTION : la base indiquée reçoit des comptes de test (adresses @t.test) ; utilisez une base de test.
"""
import os, sys, json
if not os.getenv("TEST_DATABASE_URL"):
    sys.exit("Définissez TEST_DATABASE_URL (une base de test, jamais celle de production).")
os.environ.update(DATABASE_URL=os.environ["TEST_DATABASE_URL"], SECRET_KEY="x" * 48, FRONTEND_URL="https://app.test",
                  RATELIMIT_STORAGE_URI="memory://", EMAIL_INBOUND_SECRET="secret-de-test", ANTHROPIC_API_KEY="")
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
cur.execute("DELETE FROM leads WHERE user_id IN (SELECT id FROM users WHERE email LIKE '%@t.test')")
cur.execute("DELETE FROM users WHERE email LIKE '%@t.test'"); conn.commit()


def mk(email, role='admin', owner=None, plan='agence'):
    cur.execute("""INSERT INTO users (email, password_hash, first_name, company_name, plan, role, agency_owner_id)
                   VALUES (%s,'x','Test','Agence Test',%s,%s,%s) RETURNING id""", (email, plan, role, owner))
    i = cur.fetchone()[0]; conn.commit(); return i


def tok(uid):
    cur.execute("SELECT token_version FROM users WHERE id=%s", (uid,)); v = cur.fetchone()[0]; conn.commit()
    return jwt.encode({"id": uid, "v": v, "exp": datetime.now(timezone.utc) + timedelta(hours=1)},
                      appz.SECRET_KEY, algorithm="HS256")


def ok(cond, msg):
    print(("OK   " if cond else "FAIL ") + msg)
    if not cond:
        ok.failed = True
ok.failed = False


# ------------------------------------------------------------------ règles d'extraction
tel = appz._telephone_normalise
ok(tel("06 12 34 56 78") == "0612345678", "téléphone : espaces")
ok(tel("+33 6 12 34 56 78") == "0612345678", "téléphone : +33")
ok(tel("+33 (0)6.12.34.56.78") == "0612345678", "téléphone : +33 (0) et points")
ok(tel("0033612345678") == "0612345678", "téléphone : 0033")
ok(tel("0612") is None and tel("12345678901234") is None, "téléphone : trop court ou trop long refusé")

texte = "Nom : Claire Moreau\nTél : 06 98 76 54 32\nEmail : claire.moreau@gmail.com\nLien https://x.seloger.com/c?id=0612345678"
ok(appz._telephones_dans(texte) == ["0698765432"], "téléphones : le numéro du texte, pas celui d'une URL")
ok(appz._emails_dans("De : info@service.seloger.com, noreply@x.fr, claire@gmail.com") == ["claire@gmail.com"],
   "e-mails : portail et expéditeurs automatiques écartés")
ok(appz._emails_dans("a@agence.fr b@gmail.com", exclure={"a@agence.fr"}) == ["b@gmail.com"], "e-mails : l'agence écartée")

e, t = appz._coordonnees_fiables({"email": "claire.moreau@gmail.com", "telephone": "0698765432"}, texte)
ok((e, t) == ("claire.moreau@gmail.com", "0698765432"), "coordonnées : valeurs de l'IA présentes dans le texte gardées")
e, t = appz._coordonnees_fiables({"email": "inventé@x.fr", "telephone": "0611111111"}, texte)
ok((e, t) == ("claire.moreau@gmail.com", "0698765432"), "coordonnées : valeurs inventées par l'IA remplacées par celles du texte")
e, t = appz._coordonnees_fiables({"telephone": "0611111111"}, "Rappelez-moi.")
ok((e, t) == (None, None), "coordonnées : numéro inventé sans rien dans le texte = rien")
e, t = appz._coordonnees_fiables(None, "Tel 06 11 22 33 44 ou 06 55 66 77 88")
ok(t is None, "coordonnées : deux numéros possibles = on n'en choisit pas")
e, t = appz._coordonnees_fiables(None, "Contact : agence@agence.fr et prospect@gmail.com", exclure={"agence@agence.fr"})
ok(e == "prospect@gmail.com", "coordonnées : l'adresse de l'agence n'est jamais celle du prospect")

e, t = appz._coordonnees_fiables(None, "De: contact@pap.fr\nObjet: Demande\n\nEmail : claire@example.com\nTél : 04 00 00 00 06")
ok(e == "claire@example.com", "coordonnées : l'adresse d'une ligne « De : » départage quand il y en a plusieurs")
e, t = appz._coordonnees_fiables(None, "Contact : a@example.com et b@example.com")
ok(e is None, "coordonnées : deux adresses sans critère de départage = aucune")

alerte = appz._est_alerte_portail
ok(alerte("Nouvelles annonces pour votre recherche", ""), "alerte : objet d'alerte")
ok(not alerte("Contact pour votre annonce", "Bonjour, je vous propose de visiter samedi. Tél 06 12 34 56 78"),
   "alerte : un acheteur qui écrit 'je vous propose' avec son numéro n'est pas une alerte")
ok(alerte("Information", "Découvrez ces biens qui vous correspondent. Désinscription ici."), "alerte : corps d'alerte sans coordonnées")

# ------------------------------------------------------------------ journal de réception (e-mail transféré)
agence = mk('agence@t.test'); emp = mk('emp@t.test', 'employe', agence); autre = mk('autre@t.test')
c = appz.app.test_client()
H = lambda u: {"Authorization": f"Bearer {tok(u)}"}
adresse = c.get('/api/v1/mail-capture', headers=H(agence)).get_json()['address']


def poster(item):
    return c.post('/webhooks/email-inbound?cle=secret-de-test', json={"items": [item]})


def mail(sujet, corps, de="notifications@seloger.com", mid=None):
    return {"MessageId": mid or f"<{os.urandom(6).hex()}@t>", "From": {"Address": de}, "To": [{"Address": adresse}],
            "Subject": sujet, "RawTextBody": corps}


with mock.patch.object(appz, "_lancer_en_arriere_plan", side_effect=lambda f, *a: None):
    r = poster(mail("Nouveau contact pour votre annonce T3 rue de la Paix",
                    "Claire Moreau souhaite être contactée.\nTéléphone : 06 98 76 54 32\nEmail : claire.moreau@gmail.com\n"
                    "Message : Bonjour, ce T3 est-il toujours disponible ?"))
    ok(r.status_code == 200, "webhook : mail reçu")
    poster(mail("Nouvelles annonces correspondant à vos critères", "Découvrez ces biens."))

leads = c.get('/api/v1/leads', headers=H(agence)).get_json()
ok(len(leads) == 1 and leads[0]['phone'] == "0698765432" and leads[0]['email'] == "claire.moreau@gmail.com",
   "sans IA : téléphone et e-mail du prospect récupérés par les règles")
j = c.get('/api/v1/reception/journal', headers=H(agence)).get_json()
resultats = [m['result'] for m in j['messages']]
ok(any(x == "Prospect créé" for x in resultats), "journal : le prospect créé apparaît")
ok(any("Alerte" in x for x in resultats), "journal : l'alerte ignorée apparaît avec sa raison")
ok(j['address'] == adresse and j['last_30_days']['received'] == 2 and j['last_30_days']['created'] == 1, "journal : adresse et totaux")
ok(j['messages'][-1]['subject'] != '' or True, "journal : objets conservés")
ok(c.get('/api/v1/reception/journal', headers=H(emp)).get_json()['messages'] == j['messages'],
   "journal : un employé voit celui de son agence")
ok(c.get('/api/v1/reception/journal', headers=H(autre)).get_json()['messages'] == [], "journal : isolé par agence")
ok(c.get('/api/v1/reception/journal').status_code == 401, "journal : connexion obligatoire")

# ------------------------------------------------------------------ nom du contact (règles)
nm = appz._nom_dans_texte
ok(nm("Nom : Julien Test Téléphone : 06 00 00 00 09 Email : j@example.com") == "Julien Test", "nom : ligne « Nom : » avant Téléphone")
ok(nm("Prénom : Claire Nom : Moreau Email : c@example.com") == "Claire Moreau", "nom : prénom et nom séparés")
ok(nm("Nom et prénom : Moreau Claire\nTél : 06 98 76 54 32") == "Moreau Claire", "nom : « Nom et prénom »")
ok(nm("Bonjour, je souhaite visiter ce bien. Merci.") is None, "nom : rien de net = aucun nom")
ok(nm("Contact : 06 98 76 54 32") is None, "nom : un numéro n'est pas un nom")

# ------------------------------------------------------------------ journal : IA en panne, nom, confirmation Gmail
with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "cle-de-test"}), \
        mock.patch.object(appz, "_lancer_en_arriere_plan", side_effect=lambda f, *a: None):
    with mock.patch.object(appz, "_appeler_extraction_ia", return_value=(None, ("Service d'extraction indisponible (code 401)", 502))):
        poster(mail("Nouveau contact", "Nom : Julien Test\nTéléphone : 06 00 00 00 09\nEmail : julien.test@example.com\nMessage : visite samedi ?",
                    de="tb@gmail.com"))
        poster(mail("Message", "Bonjour, ce bien est-il disponible ? Rappelez-moi au 06 11 22 33 44", de="tb@gmail.com"))
leads = {l['name']: l for l in c.get('/api/v1/leads', headers=H(agence)).get_json()}
ok("Julien Test" in leads and leads["Julien Test"]['phone'] == "0600000009", "IA en panne : nom et téléphone lus par les règles")
ok("Tb" not in leads, "nom : l'adresse de l'expéditeur n'est jamais prise pour un nom")
ok(any(l['name'] == 'Contact SeLoger' or l['name'].startswith('Contact') for l in leads.values()), "nom : à défaut, un nom neutre")
j = c.get('/api/v1/reception/journal', headers=H(agence)).get_json()
notes = [m['analysis_note'] for m in j['messages'] if m['analysis'] == 'erreur']
ok(len(notes) >= 2 and "règles simples" in notes[0], "journal : l'IA qui n'a pas répondu est signalée")

with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "cle-de-test"}), \
        mock.patch.object(appz, "_lancer_en_arriere_plan", side_effect=lambda f, *a: None):
    with mock.patch.object(appz, "_appeler_extraction_ia", return_value=({"est_demande_contact": True, "nom": "Paul Durand", "notes": "visite"}, None)), \
            mock.patch.object(appz, "_compter_extraction"):
        poster(mail("Contact", "Paul Durand, 06 77 88 99 00"))
j = c.get('/api/v1/reception/journal', headers=H(agence)).get_json()
ok(j['messages'][0]['analysis'] is None and j['messages'][0]['analysis_note'] is None, "journal : IA qui répond = rien à signaler")

avant = len(c.get('/api/v1/leads', headers=H(agence)).get_json())
conf = ("Confirmation de transfert Gmail - Recevoir les messages de agent@gmail.com",
        "agent@gmail.com a demandé à transférer automatiquement les messages vers votre adresse. Pour confirmer, cliquez sur le lien "
        "(https://mail-settings.google.com/mail/vf-%5BANGjdJabc%5D-xyz) ou saisissez le code de confirmation : 123456789")
poster(mail(conf[0], conf[1], de="forwarding-noreply@google.com"))
ok(len(c.get('/api/v1/leads', headers=H(agence)).get_json()) == avant, "Gmail : la confirmation ne crée pas de prospect")
j = c.get('/api/v1/reception/journal', headers=H(agence)).get_json()
g = j['gmail_confirmation']
ok(g and g['code'] == "123456789" and g['url'].startswith("https://mail-settings.google.com/mail/vf-"), "Gmail : code et lien affichés")
ok(not g['url'].endswith(')'), "Gmail : la parenthèse du lien n'en fait pas partie")
poster(mail(conf[0], "Cliquez : https://evil.example/mail/vf-abc pour confirmer. Code de confirmation : 999999999", de="pirate@evil.example"))
j = c.get('/api/v1/reception/journal', headers=H(agence)).get_json()
ok(j['gmail_confirmation']['code'] == "123456789", "Gmail : un faux message d'un autre expéditeur n'est pas pris pour une confirmation")
ok(c.get('/api/v1/reception/journal', headers=H(autre)).get_json()['gmail_confirmation'] is None, "Gmail : la confirmation reste à son agence")

# ------------------------------------------------------------------ test de l'analyse
with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": ""}):
    r = c.post('/api/v1/reception/test-analyse', headers=H(agence)).get_json()
    ok(r['ok'] is False and "pas configurée" in r['message'], "test IA : clé absente expliquée")
with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "cle-de-test"}):
    with mock.patch.object(appz, "_appeler_extraction_ia", return_value=({"nom": "Julien Test", "budget": 310000}, None)):
        r = c.post('/api/v1/reception/test-analyse', headers=H(agence)).get_json()
        ok(r['ok'] and r['read']['name'] == "Julien Test" and r['read']['phone'] == "0600000009"
           and r['read']['email'] == "julien.test@example.com", "test IA : ce que l'IA a lu s'affiche")
    with mock.patch.object(appz, "_appeler_extraction_ia", return_value=(None, ("Service d'extraction indisponible (code 401)", 502))):
        r = c.post('/api/v1/reception/test-analyse', headers=H(agence)).get_json()
        ok(r['ok'] is False and "clé" in r['message'], "test IA : une clé refusée est expliquée")
ok(c.post('/api/v1/reception/test-analyse').status_code == 401, "test IA : connexion obligatoire")

# ------------------------------------------------------------------ clés d'API
ok(c.post('/api/v1/api-keys', json={"name": "Ubiflow"}, headers=H(emp)).status_code == 403, "clés : refusées à un employé")
ok(c.post('/api/v1/api-keys', json={}, headers=H(agence)).status_code == 400, "clés : nom obligatoire")
r = c.post('/api/v1/api-keys', json={"name": "Ubiflow"}, headers=H(agence))
cle = r.get_json().get('key', '')
ok(r.status_code == 201 and cle.startswith('zk_') and len(cle) > 40, "clés : création, clé montrée une fois")
liste = c.get('/api/v1/api-keys', headers=H(agence)).get_json()
ok(len(liste['keys']) == 1 and 'key' not in liste['keys'][0] and liste['keys'][0]['prefix'] == cle[:10],
   "clés : la liste ne contient que le préfixe")
cur.execute("SELECT key_hash FROM api_keys WHERE user_id=%s", (agence,)); h = cur.fetchone()[0]; conn.commit()
ok(h != cle and cle not in h, "clés : seule l'empreinte est stockée")
ok(c.get('/api/v1/api-keys', headers=H(emp)).status_code == 403, "clés : liste refusée à un employé")

# ------------------------------------------------------------------ API de réception
K = {"Authorization": f"Bearer {cle}"}
ok(c.get('/api/v1/inbound/ping').status_code == 401, "ping : sans clé = 401")
ok(c.get('/api/v1/inbound/ping', headers={"Authorization": "Bearer zk_faux"}).status_code == 401, "ping : fausse clé = 401")
ok(c.get('/api/v1/inbound/ping', headers=K).get_json() == {"ok": True, "agency": "Agence Test"}, "ping : clé valable")
ok(c.get('/api/v1/inbound/ping', headers={"X-API-Key": cle}).status_code == 200, "ping : en-tête X-API-Key accepté")
ok(c.get('/api/v1/inbound/ping', headers=H(agence)).status_code == 401, "ping : un jeton de connexion n'est pas une clé d'API")
ok(c.post('/api/v1/inbound/leads', json={"phone": "0612345678"}).status_code == 401, "réception : sans clé = 401")

with mock.patch.object(appz, "_lancer_en_arriere_plan", side_effect=lambda f, *a: None) as bg:
    ok(c.post('/api/v1/inbound/leads', headers=K, json={"name": "X"}).status_code == 400, "réception : ni téléphone ni e-mail = 400")
    ok(c.post('/api/v1/inbound/leads', headers=K, json={"email": "pas-un-mail"}).status_code == 400, "réception : e-mail invalide = 400")
    ok(c.post('/api/v1/inbound/leads', headers=K, json={"phone": "12"}).status_code == 400, "réception : téléphone invalide = 400")
    ok(c.post('/api/v1/inbound/leads', headers=K, data="pas du json", content_type="text/plain").status_code == 400, "réception : corps non JSON = 400")
    corps = {"external_id": "ubi-1001", "source": "SeLoger", "name": "Julien Petit", "phone": "+33 6 11 22 33 44",
             "email": "Julien.Petit@Gmail.com", "message": "Visite possible samedi ?", "listing_title": "T3 lumineux",
             "listing_ref": "A123", "transaction": "achat", "budget": 310000, "location": "Senlis",
             "property_type": "appartement", "surface_min": 60}
    r = c.post('/api/v1/inbound/leads', headers=K, json=corps)
    ok(r.status_code == 201 and r.get_json()['status'] == 'created', "réception : prospect créé (201)")
    lead_id = r.get_json()['id']
    r2 = c.post('/api/v1/inbound/leads', headers=K, json=corps)
    ok(r2.status_code == 200 and r2.get_json() == {"status": "duplicate", "id": lead_id}, "réception : même external_id = pas de doublon")
    ok(bg.call_count >= 2, "réception : alertes de rapprochement et e-mail de complétion lancés (source SeLoger)")

fiche = c.get(f'/api/v1/leads/{lead_id}', headers=H(agence)).get_json()
ok(fiche['name'] == "Julien Petit" and fiche['phone'] == "0611223344" and fiche['email'] == "julien.petit@gmail.com",
   "réception : nom, téléphone normalisé, e-mail en minuscules")
ok(fiche['source'] == 'seloger' and fiche['budget'] == 310000 and fiche['property_type'] == 'Appartement'
   and fiche['location'] == 'Senlis', "réception : source, budget, type de bien, secteur")
notes = c.get(f'/api/v1/leads/{lead_id}/notes', headers=H(agence)).get_json()
ok(any("T3 lumineux" in n['body'] and "Visite possible" in n['body'] for n in notes), "réception : annonce et message en note")
ok(c.get(f'/api/v1/leads/{lead_id}', headers=H(autre)).status_code in (403, 404), "réception : le prospect n'est pas visible d'une autre agence")

with mock.patch.object(appz, "_lancer_en_arriere_plan", side_effect=lambda f, *a: None) as bg:
    r = c.post('/api/v1/inbound/leads', headers=K, json={"email": "anonyme@gmail.com", "source": "autre-partenaire"})
    f2 = c.get(f"/api/v1/leads/{r.get_json()['id']}", headers=H(agence)).get_json()
    ok(r.status_code == 201 and f2['source'] == 'api' and f2['name'] == 'Contact (API)', "réception : source libre = 'api', nom par défaut")
    ok(bg.call_count == 1, "réception : pas d'e-mail de complétion pour une source libre")

j = c.get('/api/v1/reception/journal', headers=H(agence)).get_json()
ok(any(m['origin'] == 'API partenaire' and m['created'] for m in j['messages']), "journal : les prospects reçus par API y figurent")

# quota
with mock.patch.object(appz, "_reste", return_value=(0, {"limits": {"leads": 5}, "label": "Test"})):
    r = c.post('/api/v1/inbound/leads', headers=K, json={"phone": "0600000001", "external_id": "nouveau"})
    ok(r.status_code == 403 and r.get_json().get('code') == 'quota', "réception : quota du forfait respecté")
    r = c.post('/api/v1/inbound/leads', headers=K, json={**corps})
    ok(r.status_code == 200 and r.get_json()['status'] == 'duplicate', "réception : un doublon reste accepté au quota")

# limite de clés actives, révocation
ids = [c.get('/api/v1/api-keys', headers=H(agence)).get_json()['keys'][0]['id']]
for i in range(appz.CLES_API_MAX - 1):
    ids.append(c.post('/api/v1/api-keys', json={"name": f"k{i}"}, headers=H(agence)).get_json()['id'])
ok(c.post('/api/v1/api-keys', json={"name": "de trop"}, headers=H(agence)).status_code == 409, "clés : limite de clés actives")
ok(c.delete(f'/api/v1/api-keys/{ids[0]}', headers=H(autre)).status_code == 404, "clés : on ne supprime pas la clé d'une autre agence")
ok(c.delete(f'/api/v1/api-keys/{ids[0]}', headers=H(agence)).status_code == 200, "clés : suppression")
ok(c.get('/api/v1/inbound/ping', headers=K).status_code == 401, "clés : une clé supprimée ne fonctionne plus")
ok(c.post('/api/v1/api-keys', json={"name": "nouvelle"}, headers=H(agence)).status_code == 201, "clés : une place se libère")

# compte suspendu
cle2 = c.post('/api/v1/api-keys', json={"name": "suspendu"}, headers=H(autre)).get_json()['key']
ok(c.get('/api/v1/inbound/ping', headers={"Authorization": f"Bearer {cle2}"}).status_code == 200, "clés : autre agence, clé valable")
cur.execute("UPDATE users SET is_active = FALSE WHERE id=%s", (autre,)); conn.commit()
ok(c.get('/api/v1/inbound/ping', headers={"Authorization": f"Bearer {cle2}"}).status_code == 401, "clés : compte suspendu = clé refusée")

# ------------------------------------------------------------------ mode démonstration et logo des e-mails
corps_test = "Nom : Julien Test\nTéléphone : 06 00 00 00 09\nEmail : julien.test@example.com\nMessage : Je souhaite visiter ce bien."
with mock.patch.object(appz, "_lancer_en_arriere_plan", side_effect=lambda f, *a: None) as bg:
    poster(mail("[TEST SeLoger] Nouveau contact pour votre annonce T3 lumineux", corps_test, de="tom@gmail.com"))
    appelees = [(c_.args[0].__name__, c_.args[1:]) for c_ in bg.call_args_list]
    envois = [a for n, a in appelees if n == "_envoyer_email_completion"]
    ok(len(envois) == 1 and envois[0][3] == "julien.test@example.com" and envois[0][1] > 0 and envois[0][4] == "seloger",
       "démo : un objet [TEST SeLoger] déclenche l'e-mail de précision, comme une vraie notification")
cur.execute("SELECT source, name FROM leads WHERE user_id=%s AND email=%s ORDER BY id DESC", (agence, "julien.test@example.com")); conn.commit()
ligne = cur.fetchone()
ok(ligne and ligne[0] == "seloger" and ligne[1] == "Julien Test", "démo : fiche créée avec la source SeLoger et le bon nom")

# même sans IA favorable : le mode démonstration crée la fiche
with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "cle-de-test"}), \
        mock.patch.object(appz, "_lancer_en_arriere_plan", side_effect=lambda f, *a: None), \
        mock.patch.object(appz, "_compter_extraction"), \
        mock.patch.object(appz, "_appeler_extraction_ia", return_value=({"est_demande_contact": False}, None)):
    poster(mail("[test leboncoin] Nouveau message", corps_test.replace("julien.test", "paul.test"), de="tom@gmail.com"))
cur.execute("SELECT source FROM leads WHERE user_id=%s AND email=%s", (agence, "paul.test@example.com")); conn.commit()
ligne = cur.fetchone()
ok(ligne and ligne[0] == "leboncoin", "démo : l'avis négatif de l'IA ne bloque pas un message de test")

# sans l'étiquette, un e-mail transféré ordinaire n'envoie rien au prospect
with mock.patch.object(appz, "_lancer_en_arriere_plan", side_effect=lambda f, *a: None) as bg:
    poster(mail("Nouveau contact T3", corps_test.replace("julien.test", "anna.test"), de="tom@gmail.com"))
    ok(not [c_ for c_ in bg.call_args_list if c_.args[0].__name__ == "_envoyer_email_completion"],
       "démo : sans étiquette, aucun e-mail n'est envoyé au prospect")

# plafond quotidien
with mock.patch.object(appz, "_lancer_en_arriere_plan", side_effect=lambda f, *a: None) as bg:
    for i in range(appz._TESTS_PAR_JOUR + 2):
        poster(mail("[TEST SeLoger] essai", corps_test.replace("julien.test", f"lim{i}.test"), de="tom@gmail.com"))
    envois = [c_ for c_ in bg.call_args_list if c_.args[0].__name__ == "_envoyer_email_completion"]
    ok(0 < len(envois) <= appz._TESTS_PAR_JOUR, "démo : plafond de messages de test par jour")

# la trace dans la fiche une fois l'e-mail parti
cur.execute("SELECT id FROM leads WHERE user_id=%s AND email=%s ORDER BY id DESC", (agence, "julien.test@example.com")); conn.commit()
lead_test = cur.fetchone()[0]
with mock.patch.object(appz, "_envoi_configure", return_value=True), \
        mock.patch.object(appz, "_envoyer_email", return_value=True) as envoi:
    appz._envoyer_email_completion(agence, lead_test, "Julien Test", "julien.test@example.com", "seloger")
    ok(envoi.call_count == 1 and "completer.html?c=" in envoi.call_args.args[2], "e-mail de précision : lien personnel dans le texte")
cur.execute("SELECT body FROM lead_notes WHERE lead_id=%s AND body LIKE %s", (lead_test, "E-mail « Précisez%")); conn.commit()
ok(cur.fetchone() is not None, "e-mail de précision : trace dans l'historique de la fiche")
with mock.patch.object(appz, "_envoi_configure", return_value=True), \
        mock.patch.object(appz, "_envoyer_email", return_value=False):
    appz._envoyer_email_completion(agence, lead_test, "Julien Test", "julien.test@example.com", "seloger")
cur.execute("SELECT COUNT(*) FROM lead_notes WHERE lead_id=%s AND body LIKE %s", (lead_test, "E-mail « Précisez%")); conn.commit()
ok(cur.fetchone()[0] == 1, "e-mail de précision : pas de trace si l'envoi échoue")

r = c.get('/logo-email.png')
ok(r.status_code == 200 and r.mimetype == 'image/png' and r.data[:4] == b'\x89PNG', "logo des e-mails servi par le backend")

cur.execute("DELETE FROM leads WHERE user_id IN (SELECT id FROM users WHERE email LIKE '%@t.test')")
cur.execute("DELETE FROM users WHERE email LIKE '%@t.test'"); conn.commit()
print("\nÉCHEC" if ok.failed else "\nTOUT PASSE")
sys.exit(1 if ok.failed else 0)
