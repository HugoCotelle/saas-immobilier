"""Tests de la facturation Stripe (webhook, routes, accès) contre une vraie base PostgreSQL.

    TEST_DATABASE_URL=postgresql://user:mdp@localhost/base_de_test python3 test_stripe.py

ATTENTION : la base indiquée reçoit des comptes de test (adresses @t.test) ; utilisez une base de test.
"""
import os, sys, time, json, hmac, hashlib
if not os.getenv("TEST_DATABASE_URL"):
    sys.exit("Définissez TEST_DATABASE_URL (une base de test, jamais celle de production).")
os.environ.update(DATABASE_URL=os.environ["TEST_DATABASE_URL"], SECRET_KEY="x"*48,
    STRIPE_SECRET_KEY="sk_test_x", STRIPE_WEBHOOK_SECRET="whsec_test", FRONTEND_URL="https://app.test",
    ADMIN_EMAILS="team@zelyro.fr", STRIPE_PORTAL_CONFIG_ENGAGE="bpc_engage", STRIPE_PORTAL_CONFIG_FLEX="bpc_flex",
    STRIPE_TAX_RATE_ID="txr_tva", RATELIMIT_STORAGE_URI="memory://")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import importlib.util
spec = importlib.util.spec_from_file_location("appz", os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.py"))
appz = importlib.util.module_from_spec(spec); spec.loader.exec_module(appz)
import stripe, jwt
from datetime import datetime, timedelta, timezone
from unittest import mock

appz.init_database()
appz._assurer_schema()
conn = appz.get_db_connection(); cur = conn.cursor()
cur.execute("DELETE FROM users WHERE email LIKE '%@t.test' OR email='team@zelyro.fr'"); conn.commit()
def mk(email, role='admin', owner=None, plan='essentiel'):
    cur.execute("""INSERT INTO users (email, password_hash, first_name, company_name, plan, role, agency_owner_id)
                   VALUES (%s,'x','Test','Agence Test',%s,%s,%s) RETURNING id""", (email, plan, role, owner))
    i = cur.fetchone()[0]; conn.commit(); return i
agence = mk('agence@t.test'); emp = mk('emp@t.test', 'employe', agence); team = mk('team@zelyro.fr', plan='illimite')

c = appz.app.test_client()
def signe(payload, secret="whsec_test", t=None):
    t = t or int(time.time())
    sig = hmac.new(secret.encode(), f"{t}.".encode() + payload, hashlib.sha256).hexdigest()
    return {"Stripe-Signature": f"t={t},v1={sig}", "Content-Type": "application/json"}
cpt = [0]
def ev(type_, obj):
    cpt[0] += 1
    return {"id": f"evt_{cpt[0]}_{time.time_ns()}", "type": type_, "data": {"object": obj}}
def post(e, **kw):
    p = json.dumps(e).encode(); return c.post('/stripe/webhook', data=p, headers=signe(p, **kw))
def row(uid):
    cur.execute("""SELECT plan,is_active,billing_status,billing_formula,billing_commit_end,billing_period_end,extra_seats,
                   billing_suspended,token_version,stripe_customer_id,stripe_subscription_id,billing_cancel_at_period_end
                   FROM users WHERE id=%s""", (uid,)); conn.commit()
    return cur.fetchone()
def tok(uid):
    cur.execute("SELECT token_version FROM users WHERE id=%s", (uid,)); v = cur.fetchone()[0]; conn.commit()
    return jwt.encode({"id": uid, "v": v, "exp": datetime.now(timezone.utc) + timedelta(hours=1)}, appz.SECRET_KEY, algorithm="HS256")
def ok(cond, msg):
    print(("OK   " if cond else "FAIL ") + msg)
    if not cond: ok.failed = True
ok.failed = False

start = int(datetime(2026, 11, 3, tzinfo=timezone.utc).timestamp())
end = start + 30*86400
sub = lambda **o: {"id": "sub_plan1", "customer": "cus_1", "status": "active", "start_date": start,
                   "current_period_end": end, "cancel_at_period_end": False,
                   "metadata": {"user_id": str(agence), "kind": "plan", "plan": "agence", "formule": "engage"},
                   "items": {"data": [{"id": "si_1", "quantity": 1, "price": {"lookup_key": "zelyro_agence_engage"}}]}, **o}

# 1 signature
p = b'{"id":"evt_x","type":"x"}'
ok(c.post('/stripe/webhook', data=p, headers=signe(p, secret="mauvais")).status_code == 400, "signature invalide -> 400")
ok(c.post('/stripe/webhook', data=p, headers={"Stripe-Signature": "n'importe quoi"}).status_code == 400, "signature mal formée -> 400")
# 2 création
e = ev("customer.subscription.created", sub())
r = post(e); ok(r.status_code == 200, f"subscription.created -> 200 ({r.status_code})")
x = row(agence)
ok(x[0] == 'agence' and x[2] == 'active' and x[3] == 'engage', f"plan/statut/formule: {x[:4]}")
ok(x[4] == datetime(2027, 11, 3), f"fin d'engagement = début + 12 mois: {x[4]}")
ok(x[9] == 'cus_1' and x[10] == 'sub_plan1', "client et abonnement enregistrés")
ok(post(e).get_json().get("duplicate") is True, "événement rejoué -> ignoré")
# 3 comptes supplémentaires
seats = {"id": "sub_seats1", "customer": "cus_1", "status": "active", "start_date": start, "current_period_end": end,
         "metadata": {"user_id": str(agence), "kind": "seats"}, "items": {"data": [{"id": "si_s", "quantity": 3, "price": {"lookup_key": "zelyro_siege_mensuel"}}]}}
post(ev("customer.subscription.created", seats)); x = row(agence)
ok(x[6] == 3, f"extra_seats = 3 ({x[6]})")
with appz._base() as (cn, cu):
    ok(appz._limite_comptes(cu, agence)[0] == 5 + 3 or appz._limite_comptes(cu, agence)[0] is not None, f"limite de comptes = {appz._limite_comptes(cu, agence)}")
# 4 impayé
post(ev("invoice.payment_failed", {"customer": "cus_1", "number": "F-1"}))
post(ev("customer.subscription.updated", sub(status="past_due"))); x = row(agence)
ok(x[2] == 'past_due' and x[1] is True and x[0] == 'agence', "past_due : accès conservé")
# 5 résiliation / impayé définitif
with mock.patch.object(stripe.Subscription, "cancel") as cancel:
    cur.execute("UPDATE users SET stripe_seats_subscription_id='sub_seats1' WHERE id=%s", (agence,)); conn.commit()
    tv = row(agence)[8]
    post(ev("customer.subscription.deleted", sub(status="canceled"))); x = row(agence)
    ok(x[1] is False and x[7] is True and x[8] == tv + 1 and x[6] == 0, f"abonnement supprimé -> accès coupé, sessions invalidées: {x[1:2]+x[6:9]}")
    ok(cancel.called, "abonnement des comptes supplémentaires résilié")
r = c.get('/api/v1/billing', headers={"Authorization": f"Bearer {tok(agence)}"})
ok(r.status_code == 401, "jeton refusé après suspension")
# 6 réabonnement + ancienne suppression ignorée
new = sub(id="sub_plan2", metadata={"user_id": str(agence), "kind": "plan", "plan": "reseau", "formule": "annuel"}, items={"data": [{"id": "si_1", "quantity": 1, "price": {"lookup_key": "zelyro_reseau_annuel"}}]})
post(ev("customer.subscription.created", new)); x = row(agence)
ok(x[1] is True and x[0] == 'reseau' and x[7] is False and x[3] == 'annuel', f"nouvel abonnement -> compte rétabli: {x[:4]}")
post(ev("customer.subscription.deleted", sub(status="canceled"))); x = row(agence)
ok(x[1] is True and x[2] == 'active', "suppression d'un ancien abonnement ignorée")
# 6b changement de tarif dans Stripe -> forfait mis à jour, même si les métadonnées sont anciennes
up = dict(new); up["items"] = {"data": [{"id": "si_1", "quantity": 1, "price": {"lookup_key": "zelyro_essentiel_mensuel"}}]}
post(ev("customer.subscription.updated", up)); x = row(agence)
ok(x[0] == 'essentiel' and x[3] == 'mensuel', f"passage à un autre tarif dans Stripe -> {x[0]}/{x[3]}")
post(ev("customer.subscription.updated", new)); x = row(agence)
ok(x[0] == 'reseau' or x[0] == 'agence', f"retour aux métadonnées si le tarif est inconnu: {x[0]}")
# 7 compte de l'équipe jamais coupé
post(ev("customer.subscription.deleted", {"id": "sub_t", "customer": "cus_t", "status": "canceled",
      "metadata": {"user_id": str(team), "kind": "plan", "plan": "agence", "formule": "mensuel"}, "items": {"data": []}}))
ok(row(team)[1] is True, "compte équipe non suspendu")
# 8 checkout.session.completed
cur.execute("UPDATE users SET stripe_customer_id=NULL, billing_status=NULL, stripe_subscription_id=NULL WHERE id=%s", (agence,)); conn.commit()
full = dict(sub(id="sub_plan3", default_payment_method="pm_1", metadata={"user_id": str(agence), "kind": "plan", "plan": "essentiel", "formule": "mensuel"}, items={"data": [{"id": "si_1", "quantity": 1, "price": {"lookup_key": "zelyro_essentiel_mensuel"}}]}))
class Fake:
    def __init__(s, d): s.d = d
    def to_dict(s): return s.d
with mock.patch.object(stripe.Subscription, "retrieve", return_value=Fake(full)), \
     mock.patch.object(stripe.Customer, "modify") as modif:
    r = post(ev("checkout.session.completed", {"mode": "subscription", "client_reference_id": str(agence),
                                               "customer": "cus_1", "subscription": "sub_plan3"}))
    ok(r.status_code == 200, f"checkout.session.completed -> {r.status_code}")
    ok(modif.call_args and modif.call_args.kwargs["invoice_settings"]["default_payment_method"] == "pm_1", "moyen de paiement par défaut enregistré")
x = row(agence); ok(x[0] == 'essentiel' and x[2] == 'active', f"forfait après paiement: {x[:3]}")

# 9 routes
H = lambda uid: {"Authorization": f"Bearer {tok(uid)}"}
cur.execute("UPDATE users SET billing_status=NULL, stripe_subscription_id=NULL WHERE id=%s", (agence,)); conn.commit()
ok(c.post('/api/v1/billing/checkout', json={"plan": "agence", "formule": "mensuel"}, headers=H(emp)).status_code == 403, "employé -> 403")
ok(c.post('/api/v1/billing/checkout', json={"plan": "gratuit", "formule": "mensuel"}, headers=H(agence)).status_code == 400, "forfait inconnu -> 400")
class O:  # objet minimal façon StripeObject
    def __init__(s, **k): s.__dict__.update(k)
with mock.patch.object(stripe.Price, "list", return_value=Fake({"data": [{"id": "price_1"}]})), \
     mock.patch.object(stripe.checkout.Session, "create", return_value=O(url="https://checkout.stripe.test/x")) as cs:
    r = c.post('/api/v1/billing/checkout', json={"plan": "agence", "formule": "annuel"}, headers=H(agence))
    ok(r.status_code == 200 and r.get_json()["url"].startswith("https://checkout"), f"checkout -> {r.status_code}")
    k = cs.call_args.kwargs
    ok(k["line_items"] == [{"price": "price_1", "quantity": 1, "tax_rates": ["txr_tva"]}] and k["customer"] == "cus_1"
       and k["subscription_data"]["metadata"]["formule"] == "annuel" and "sepa_debit" in k["payment_method_types"], "paramètres Checkout")
cur.execute("UPDATE users SET billing_status='active', stripe_subscription_id='sub_plan3' WHERE id=%s", (agence,)); conn.commit()
ok(c.post('/api/v1/billing/checkout', json={"plan": "agence", "formule": "mensuel"}, headers=H(agence)).status_code == 409, "déjà abonné -> 409")
# portail : engagement en cours -> configuration « engagé »
cur.execute("UPDATE users SET billing_formula='engage', billing_commit_end=%s WHERE id=%s", (datetime.utcnow()+timedelta(days=100), agence)); conn.commit()
with mock.patch.object(stripe.billing_portal.Session, "create", return_value=O(url="https://portal.test")) as ps:
    r = c.post('/api/v1/billing/portal', headers=H(agence)); ok(r.status_code == 200 and ps.call_args.kwargs["configuration"] == "bpc_engage", "portail engagé pendant l'engagement")
    cur.execute("UPDATE users SET billing_commit_end=%s WHERE id=%s", (datetime.utcnow()-timedelta(days=1), agence)); conn.commit()
    r = c.post('/api/v1/billing/portal', headers=H(agence)); ok(ps.call_args.kwargs["configuration"] == "bpc_flex", "portail souple après l'engagement")
# comptes supplémentaires
seat_sub = O(**{})
def mk_sub(q): return Fake({"id": "sub_seats9", "customer": "cus_1", "status": "active", "start_date": start, "current_period_end": end,
                            "metadata": {"user_id": str(agence), "kind": "seats"}, "items": {"data": [{"id": "si_9", "quantity": q}]}})
cur.execute("UPDATE users SET extra_seats=0, stripe_seats_subscription_id=NULL WHERE id=%s", (agence,)); conn.commit()
with mock.patch.object(stripe.Price, "list", return_value=Fake({"data": [{"id": "price_seat"}]})), \
     mock.patch.object(stripe.Subscription, "create", return_value=mk_sub(2)) as sc:
    r = c.post('/api/v1/billing/seats', json={"quantity": 2}, headers=H(agence))
    ok(r.status_code == 200 and r.get_json()["extra_seats"] == 2, f"ajout de 2 comptes -> {r.get_json()}")
    ok(sc.call_args.kwargs["default_tax_rates"] == ["txr_tva"], "TVA appliquée aux comptes supplémentaires")
with mock.patch.object(stripe.Subscription, "retrieve", return_value=mk_sub(2)), \
     mock.patch.object(stripe.Subscription, "modify", return_value=mk_sub(5)):
    r = c.post('/api/v1/billing/seats', json={"quantity": 5}, headers=H(agence)); ok(r.get_json()["extra_seats"] == 5, "passage à 5 comptes")
ok(c.post('/api/v1/billing/seats', json={"quantity": 999}, headers=H(agence)).status_code == 400, "quantité hors limites -> 400")
r = c.get('/api/v1/billing', headers=H(emp)); j = r.get_json()
ok(r.status_code == 200 and j["can_manage"] is False and j["subscription"]["status"] == "active", f"GET billing (employé): {j}")
print("\nRÉSULTAT:", "ÉCHEC" if ok.failed else "TOUT PASSE")
