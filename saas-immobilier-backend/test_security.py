"""Tests de sécurité du backend, contre une vraie base PostgreSQL."""
import os
import re
import secrets
import subprocess
import sys
import time
import unittest
from datetime import timedelta
from unittest import mock

import jwt as pyjwt

HERE = os.path.dirname(os.path.abspath(__file__))
PG = "postgresql://postgres@127.0.0.1:5544"
DB_URL = f"{PG}/immo_test"
SECRET = "test-secret-" + "x" * 40
ENV_BASE = {"SECRET_KEY": SECRET, "DATABASE_URL": DB_URL, "ANTHROPIC_API_KEY": "sk-ant-api03-fake"}


def sh(*args, env=None, check=True):
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run(args, cwd=HERE, env=e, capture_output=True, text=True, check=check)


def reset_db():
    sh("psql", "-h", "127.0.0.1", "-p", "5544", "-U", "postgres", "-c", "DROP DATABASE IF EXISTS immo_test WITH (FORCE)")
    sh("psql", "-h", "127.0.0.1", "-p", "5544", "-U", "postgres", "-c", "CREATE DATABASE immo_test ENCODING 'UTF8' TEMPLATE template0 LC_COLLATE 'C' LC_CTYPE 'C'")


# ---------------------------------------------------------------- démarrage
class TestDemarrage(unittest.TestCase):
    def importer(self, env):
        code = "import app; print('IMPORT_OK')"
        e = {k: v for k, v in os.environ.items() if k not in ("SECRET_KEY", "JWT_SECRET")}
        e.update({"DATABASE_URL": DB_URL})
        e.update(env)
        return subprocess.run([sys.executable, "-c", code], cwd=HERE, env=e, capture_output=True, text=True)

    def test_refuse_sans_secret(self):
        r = self.importer({})
        self.assertNotIn("IMPORT_OK", r.stdout)
        self.assertIn("SECRET_KEY absente", r.stderr)

    def test_refuse_secret_court(self):
        r = self.importer({"SECRET_KEY": "court"})
        self.assertNotIn("IMPORT_OK", r.stdout)

    def test_refuse_ancienne_valeur_par_defaut(self):
        r = self.importer({"SECRET_KEY": "your-secret-key-change-in-production"})
        self.assertNotIn("IMPORT_OK", r.stdout)

    def test_accepte_jwt_secret_de_env_example(self):
        r = self.importer({"JWT_SECRET": "j" * 40})
        self.assertIn("IMPORT_OK", r.stdout, r.stderr)

    def test_accepte_secret_valide(self):
        r = self.importer({"SECRET_KEY": SECRET})
        self.assertIn("IMPORT_OK", r.stdout, r.stderr)


class TestInitDb(unittest.TestCase):
    def test_init_sans_compte_de_test(self):
        reset_db()
        r = sh(sys.executable, "app.py", "init-db", env=ENV_BASE)
        self.assertIn("initialisée", r.stdout)
        out = sh("psql", "-h", "127.0.0.1", "-p", "5544", "-U", "postgres", "-d", "immo_test", "-tAc",
                 "SELECT count(*) FROM users").stdout.strip()
        self.assertEqual(out, "0")
        cols = sh("psql", "-h", "127.0.0.1", "-p", "5544", "-U", "postgres", "-d", "immo_test", "-tAc",
                  "SELECT string_agg(column_name, ',') FROM information_schema.columns WHERE table_name='leads'").stdout
        for c in ("financing_status", "purchase_urgency", "lead_quality", "financing_amount", "notes"):
            self.assertIn(c, cols)

    def test_init_idempotent(self):
        sh(sys.executable, "app.py", "init-db", env=ENV_BASE)
        sh(sys.executable, "app.py", "init-db", env=ENV_BASE)

    def test_demo_mot_de_passe_aleatoire(self):
        reset_db()
        r = sh(sys.executable, "app.py", "init-db", "--demo", env=ENV_BASE)
        self.assertIn("demo@example.com /", r.stdout)
        self.assertNotIn("password123", r.stdout)
        n = sh("psql", "-h", "127.0.0.1", "-p", "5544", "-U", "postgres", "-d", "immo_test", "-tAc",
               "SELECT count(*) FROM leads WHERE user_id=(SELECT id FROM users WHERE email='demo@example.com')").stdout.strip()
        self.assertEqual(n, "33")
        # Deuxième passage : rien de plus (la base n'est plus vide).
        r2 = sh(sys.executable, "app.py", "init-db", "--demo", env=ENV_BASE)
        self.assertNotIn("Compte de démonstration", r2.stdout)


# ---------------------------------------------------------------- API
os.environ.update(ENV_BASE)
os.environ["ALLOWED_ORIGINS"] = "https://app.zelyro.fr"
os.environ["OPEN_REGISTRATION"] = "1"
sys.path.insert(0, HERE)
reset_db()
sh(sys.executable, "app.py", "init-db", env=ENV_BASE)
import app as backend  # noqa: E402

PW = "un-mot-de-passe-solide"


class Base(unittest.TestCase):
    def setUp(self):
        backend.limiter.reset()
        self.c = backend.app.test_client()

    def inscrire(self, email, pw=PW, **kw):
        return self.c.post("/auth/register", json={"email": email, "password": pw, **kw})

    def jeton(self, email):
        r = self.inscrire(email)
        if r.status_code == 409:
            r = self.c.post("/auth/login", json={"email": email, "password": PW})
        return r.get_json()["token"]

    def h(self, tok):
        return {"Authorization": f"Bearer {tok}"}


class TestRoutesSupprimees(Base):
    def test_init_db_absente(self):
        self.assertEqual(self.c.post("/api/v1/init-db").status_code, 404)

    def test_debug_cle_absente(self):
        tok = self.jeton("a@x.fr")
        self.assertEqual(self.c.get("/api/v1/debug-cle", headers=self.h(tok)).status_code, 404)


class TestAuth(Base):
    def test_mot_de_passe_court(self):
        self.assertEqual(self.inscrire("court@x.fr", "abc").status_code, 400)

    def test_mot_de_passe_trop_long(self):
        self.assertEqual(self.inscrire("long@x.fr", "a" * 200).status_code, 400)

    def test_email_invalide(self):
        self.assertEqual(self.inscrire("pas-un-email").status_code, 400)

    def test_inscription_et_doublon_insensible_a_la_casse(self):
        self.assertEqual(self.inscrire("Marie@Agence.fr").status_code, 201)
        self.assertEqual(self.inscrire("marie@agence.fr").status_code, 409)
        self.assertEqual(self.inscrire("MARIE@AGENCE.FR").status_code, 409)

    def test_login_insensible_a_la_casse(self):
        self.inscrire("casse@x.fr")
        r = self.c.post("/auth/login", json={"email": "CASSE@x.FR", "password": PW})
        self.assertEqual(r.status_code, 200)
        self.assertIn("token", r.get_json())

    def test_ancien_compte_avec_majuscules_en_base(self):
        """Un compte créé avant le correctif, avec une adresse en majuscules, doit pouvoir se connecter."""
        conn = backend.get_db_connection()
        cur = conn.cursor()
        cur.execute("INSERT INTO users (email, password_hash) VALUES (%s, %s)",
                    ("Ancien.Compte@Agence.fr", backend.generate_password_hash(PW)))
        conn.commit(); conn.close()
        r = self.c.post("/auth/login", json={"email": "ancien.compte@agence.fr", "password": PW})
        self.assertEqual(r.status_code, 200)

    def test_mauvais_mot_de_passe_et_inconnu_meme_reponse(self):
        self.inscrire("reel@x.fr")
        a = self.c.post("/auth/login", json={"email": "reel@x.fr", "password": "mauvais-mot-de-passe"})
        b = self.c.post("/auth/login", json={"email": "inconnu@x.fr", "password": "mauvais-mot-de-passe"})
        self.assertEqual(a.status_code, 401)
        self.assertEqual(b.status_code, 401)
        self.assertEqual(a.get_json(), b.get_json())

    def test_corps_non_json(self):
        r = self.c.post("/auth/login", data="pas du json", content_type="text/plain")
        self.assertEqual(r.status_code, 400)
        r = self.c.post("/auth/register", data="x", content_type="text/plain")
        self.assertEqual(r.status_code, 400)

    def test_email_stocke_en_minuscules(self):
        self.inscrire("Stocke@X.fr")
        conn = backend.get_db_connection(); cur = conn.cursor()
        cur.execute("SELECT email FROM users WHERE lower(email)='stocke@x.fr'")
        self.assertEqual(cur.fetchone()[0], "stocke@x.fr")
        conn.close()


class TestJetons(Base):
    def forger(self, secret, **claims):
        base = {"id": 1, "email": "a@x.fr", "exp": int(time.time()) + 3600}
        base.update(claims)
        return pyjwt.encode({k: v for k, v in base.items() if v is not None}, secret, algorithm="HS256")

    def test_jeton_signe_avec_ancienne_cle_par_defaut(self):
        tok = self.forger("your-secret-key-change-in-production")
        self.assertEqual(self.c.get("/api/v1/leads", headers=self.h(tok)).status_code, 401)

    def test_jeton_valide(self):
        tok = self.jeton("ok@x.fr")
        self.assertEqual(self.c.get("/api/v1/leads", headers=self.h(tok)).status_code, 200)

    def test_jeton_expire(self):
        tok = self.forger(SECRET, exp=int(time.time()) - 10)
        self.assertEqual(self.c.get("/api/v1/leads", headers=self.h(tok)).status_code, 401)

    def test_jeton_sans_expiration(self):
        tok = self.forger(SECRET, exp=None)
        self.assertEqual(self.c.get("/api/v1/leads", headers=self.h(tok)).status_code, 401)

    def test_jeton_sans_id(self):
        tok = pyjwt.encode({"email": "a@x.fr", "exp": int(time.time()) + 3600}, SECRET, algorithm="HS256")
        self.assertEqual(self.c.get("/api/v1/leads", headers=self.h(tok)).status_code, 401)

    def test_alg_none(self):
        tok = pyjwt.encode({"id": 1, "exp": int(time.time()) + 3600}, None, algorithm="none")
        self.assertEqual(self.c.get("/api/v1/leads", headers=self.h(tok)).status_code, 401)

    def test_sans_jeton(self):
        self.assertEqual(self.c.get("/api/v1/leads").status_code, 401)

    def test_duree_du_jeton(self):
        tok = self.jeton("duree@x.fr")
        data = pyjwt.decode(tok, SECRET, algorithms=["HS256"])
        self.assertAlmostEqual(data["exp"] - data["iat"], 24 * 3600, delta=5)


class TestIsolation(Base):
    def test_un_utilisateur_ne_voit_pas_les_donnees_d_un_autre(self):
        ta = self.jeton("agence-a@x.fr")
        tb = self.jeton("agence-b@x.fr")
        r = self.c.post("/api/v1/leads", json={"name": "Prospect de A", "budget": "250000"}, headers=self.h(ta))
        self.assertEqual(r.status_code, 201)
        lead_id = r.get_json()["id"]
        r = self.c.post("/api/v1/properties", json={"title": "Bien de A", "price": 200000}, headers=self.h(ta))
        self.assertEqual(r.status_code, 201)

        # B ne voit rien
        self.assertEqual(self.c.get("/api/v1/leads", headers=self.h(tb)).get_json(), [])
        self.assertEqual(self.c.get("/api/v1/properties", headers=self.h(tb)).get_json(), [])
        self.assertEqual(self.c.get(f"/api/v1/leads/{lead_id}", headers=self.h(tb)).status_code, 404)
        self.assertEqual(self.c.get("/api/v1/improved-matches", headers=self.h(tb)).get_json(), [])
        self.assertEqual(self.c.get("/api/v1/stats", headers=self.h(tb)).get_json()["total_leads"], 0)
        self.assertEqual(self.c.get("/api/v1/leads/quality/cold", headers=self.h(tb)).get_json(), [])
        # B ne peut pas modifier la fiche de A
        r = self.c.put(f"/api/v1/leads/{lead_id}/update-financing", json={"budget": 1}, headers=self.h(tb))
        self.assertEqual(r.status_code, 404)
        # ... et la fiche de A est intacte
        r = self.c.get(f"/api/v1/leads/{lead_id}", headers=self.h(ta))
        self.assertEqual(r.get_json()["budget"], 250000)

    def test_user_id_du_corps_ignore(self):
        ta = self.jeton("userid-a@x.fr")
        tb = self.jeton("userid-b@x.fr")
        conn = backend.get_db_connection(); cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email='userid-b@x.fr'")
        id_b = cur.fetchone()[0]; conn.close()
        r = self.c.post("/api/v1/leads", json={"name": "Intrus", "user_id": id_b}, headers=self.h(ta))
        self.assertEqual(r.status_code, 201)
        self.assertEqual(self.c.get("/api/v1/leads", headers=self.h(tb)).get_json(), [])


class TestValidation(Base):
    def test_valeurs_extremes_ne_font_pas_de_500(self):
        t = self.jeton("valid@x.fr")
        r = self.c.post("/api/v1/leads", json={
            "name": "N" * 500, "budget": "99999999999999", "phone": "0" * 60,
            "financing_status": "pirate", "purchase_urgency": "<script>", "email": "e" * 400,
        }, headers=self.h(t))
        self.assertEqual(r.status_code, 201, r.get_data(as_text=True))
        lead = r.get_json()
        self.assertIsNone(lead["budget"])
        self.assertEqual(len(lead["phone"]), 20)
        self.assertEqual(len(lead["name"]), 255)
        self.assertEqual(lead["financing_status"], "unknown")
        self.assertEqual(lead["purchase_urgency"], "unknown")

    def test_mise_a_jour_valeurs_invalides(self):
        t = self.jeton("maj@x.fr")
        lead = self.c.post("/api/v1/leads", json={"name": "Maj"}, headers=self.h(t)).get_json()
        r = self.c.put(f"/api/v1/leads/{lead['id']}/update-financing", json={
            "budget": "abc", "financing_amount": 10 ** 15, "financing_status": "approved",
            "purchase_urgency": "immediate", "notes": "n" * 5000, "location": "Lille",
        }, headers=self.h(t))
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        d = self.c.get(f"/api/v1/leads/{lead['id']}", headers=self.h(t)).get_json()
        self.assertIsNone(d["budget"])
        self.assertIsNone(d["financing_amount"])
        self.assertEqual(d["financing_status"], "approved")
        self.assertEqual(len(d["notes"]), 2000)

    def test_mise_a_jour_sans_json(self):
        t = self.jeton("maj2@x.fr")
        lead = self.c.post("/api/v1/leads", json={"name": "Maj2"}, headers=self.h(t)).get_json()
        r = self.c.put(f"/api/v1/leads/{lead['id']}/update-financing", data="x", content_type="text/plain", headers=self.h(t))
        self.assertIn(r.status_code, (200, 400))  # jamais 500

    def test_bien_valeurs_extremes(self):
        t = self.jeton("bien@x.fr")
        r = self.c.post("/api/v1/properties", json={
            "title": "T", "price": "99999999999999", "size": -5, "rooms": "trois",
            "description": "d" * 20000, "address": "a" * 900,
        }, headers=self.h(t))
        self.assertEqual(r.status_code, 201, r.get_data(as_text=True))
        b = r.get_json()
        self.assertIsNone(b["price"]); self.assertIsNone(b["size"]); self.assertIsNone(b["rooms"])
        self.assertEqual(len(b["description"]), 5000)

    def test_parcours_normal_du_frontend(self):
        """Les valeurs envoyées par les formulaires actuels passent sans changement."""
        t = self.jeton("normal@x.fr")
        r = self.c.post("/api/v1/leads", json={
            "name": "Thomas Martin", "email": "thomas.martin@email.fr", "phone": "0612345678",
            "budget": "280000", "location": "Lille", "property_type": "Appartement",
            "financing_status": "approved", "purchase_urgency": "1-3_months",
        }, headers=self.h(t))
        lead = r.get_json()
        self.assertEqual((lead["budget"], lead["location"], lead["financing_status"]), (280000, "Lille", "approved"))
        r = self.c.put(f"/api/v1/leads/{lead['id']}/update-financing", json={
            "budget": 300000, "location": "Lille", "property_type": "Maison",
            "financing_status": "in_progress", "purchase_urgency": "3-6_months",
            "financing_amount": 250000, "notes": "Visite prévue",
        }, headers=self.h(t))
        self.assertEqual(r.status_code, 200)
        d = self.c.get(f"/api/v1/leads/{lead['id']}", headers=self.h(t)).get_json()
        self.assertEqual((d["budget"], d["property_type"], d["financing_status"], d["purchase_urgency"],
                          d["financing_amount"], d["notes"]),
                         (300000, "Maison", "in_progress", "3-6_months", 250000, "Visite prévue"))
        m = self.c.get("/api/v1/improved-matches", headers=self.h(t))
        self.assertEqual(m.status_code, 200)

    def test_corps_trop_gros(self):
        t = self.jeton("gros@x.fr")
        r = self.c.post("/api/v1/leads", data='{"name":"' + "a" * 200000 + '"}', content_type="application/json", headers=self.h(t))
        self.assertEqual(r.status_code, 413)


class TestErreursGeneriques(Base):
    def test_pas_de_fuite_de_details(self):
        t = self.jeton("err@x.fr")
        with mock.patch.object(backend, "get_db_connection", side_effect=Exception("relation secrete_interne does not exist")):
            for method, url in (("get", "/api/v1/leads"), ("get", "/api/v1/properties"), ("get", "/api/v1/stats"),
                                ("get", "/auth/profile"), ("get", "/api/v1/improved-matches")):
                r = getattr(self.c, method)(url, headers=self.h(t))
                self.assertEqual(r.status_code, 500, url)
                self.assertNotIn("secrete_interne", r.get_data(as_text=True), url)
            r = self.c.post("/auth/login", json={"email": "err@x.fr", "password": PW})
            self.assertEqual(r.status_code, 500)
            self.assertNotIn("secrete_interne", r.get_data(as_text=True))


class TestCors(Base):
    def origine(self, o, methode="get", url="/health"):
        return getattr(self.c, methode)(url, headers={"Origin": o})

    def test_origines_autorisees(self):
        for o in ("https://saas-immobilier-git-refonte-design-immo-flow.vercel.app",
                  "https://saas-immobilier-f09d0l2op-immo-flow.vercel.app",
                  "https://saas-immobilier.vercel.app",
                  "https://saas-immobilier-immo-flow.vercel.app",
                  "https://saas-immobilier-d0g60o2i6-zelyro.vercel.app",
                  "https://saas-immobilier-git-securite-zelyro.vercel.app",
                  "https://saas-immobilier-zelyro.vercel.app",
                  "https://app.zelyro.fr", "http://localhost:3000"):
            r = self.origine(o)
            self.assertEqual(r.headers.get("Access-Control-Allow-Origin"), o, o)

    def test_origines_refusees(self):
        for o in ("https://evil.com",
                  "https://saas-immobilier-evil.vercel.app",
                  "https://saas-immobilier-x-immo-flow.vercel.app.evil.com",
                  "http://saas-immobilier.vercel.app",
                  "https://zelyro.fr.evil.com",
                  "https://saas-immobilier-x-zelyro.vercel.app.evil.com",
                  "https://saas-immobilier-zelyro.evil.com",
                  "https://autre-equipe-saas-immobilier-immo-flow.vercel.app"):
            r = self.origine(o)
            self.assertIsNone(r.headers.get("Access-Control-Allow-Origin"), o)

    def test_preflight(self):
        r = self.c.options("/api/v1/extract", headers={
            "Origin": "https://saas-immobilier.vercel.app",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization,content-type"})
        self.assertIn(r.status_code, (200, 204))
        self.assertEqual(r.headers.get("Access-Control-Allow-Origin"), "https://saas-immobilier.vercel.app")
        self.assertIn("POST", r.headers.get("Access-Control-Allow-Methods", ""))
        self.assertIn("authorization", r.headers.get("Access-Control-Allow-Headers", "").lower())

    def test_preflight_origine_refusee(self):
        r = self.c.options("/api/v1/extract", headers={
            "Origin": "https://evil.com", "Access-Control-Request-Method": "POST"})
        self.assertIsNone(r.headers.get("Access-Control-Allow-Origin"))


class TestEntetes(Base):
    def test_entetes_de_securite(self):
        r = self.c.get("/health")
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(r.headers["Cache-Control"], "no-store")
        self.assertIn("max-age", r.headers["Strict-Transport-Security"])
        self.assertIn("frame-ancestors 'none'", r.headers["Content-Security-Policy"])

    def test_404_json(self):
        r = self.c.get("/nimporte/quoi")
        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.get_json(), {"message": "Not found"})


class TestLimites(Base):
    def test_force_brute_sur_un_compte(self):
        self.inscrire("victime@x.fr")
        codes = []
        for i in range(12):
            r = self.c.post("/auth/login", json={"email": "victime@x.fr", "password": f"mauvais-{i}-mot-de-passe"},
                            environ_base={"REMOTE_ADDR": f"10.0.0.{i}"})  # IP différente à chaque essai
            codes.append(r.status_code)
        self.assertEqual(codes[:8], [401] * 8)
        self.assertIn(429, codes[8:])
        self.assertTrue(all(c == 429 for c in codes[8:]))
        # Le bon mot de passe est lui aussi bloqué pendant la fenêtre : c'est voulu.
        r = self.c.post("/auth/login", json={"email": "victime@x.fr", "password": PW})
        self.assertEqual(r.status_code, 429)
        self.assertIn("Trop de requêtes", r.get_json()["message"])

    def test_les_connexions_reussies_ne_comptent_pas(self):
        self.inscrire("assidu@x.fr")
        for _ in range(15):
            r = self.c.post("/auth/login", json={"email": "assidu@x.fr", "password": PW},
                            environ_base={"REMOTE_ADDR": "10.1.1.1"})
            self.assertEqual(r.status_code, 200)

    def test_un_autre_compte_n_est_pas_bloque(self):
        self.inscrire("victime2@x.fr"); self.inscrire("voisin@x.fr")
        for i in range(10):
            self.c.post("/auth/login", json={"email": "victime2@x.fr", "password": f"mauvais-{i}-mot-de-passe"},
                        environ_base={"REMOTE_ADDR": f"10.2.0.{i}"})
        r = self.c.post("/auth/login", json={"email": "voisin@x.fr", "password": PW}, environ_base={"REMOTE_ADDR": "10.2.9.9"})
        self.assertEqual(r.status_code, 200)

    def test_inscriptions_limitees_par_ip(self):
        codes = [self.inscrire(f"masse{i}@x.fr", environ_base={"REMOTE_ADDR": "10.3.3.3"}).status_code
                 if False else
                 self.c.post("/auth/register", json={"email": f"masse{i}@x.fr", "password": PW},
                             environ_base={"REMOTE_ADDR": "10.3.3.3"}).status_code
                 for i in range(13)]
        self.assertEqual(codes[:10], [201] * 10)
        self.assertEqual(codes[10:], [429] * 3)

    def test_health_non_limite(self):
        for _ in range(350):
            self.assertEqual(self.c.get("/health").status_code, 200)

    def test_limite_generale_par_ip(self):
        t = self.jeton("flood@x.fr")
        codes = [self.c.get("/api/v1/stats", headers=self.h(t), environ_base={"REMOTE_ADDR": "10.4.4.4"}).status_code
                 for _ in range(305)]
        self.assertEqual(codes[:300], [200] * 300)
        self.assertEqual(codes[300:], [429] * 5)


class TestExtraction(Base):
    def reponse_anthropic(self, statut=200, texte='{"nom":"Thomas Martin","telephone":"06 12 34 56 78","budget":"280 000","secteurs":["Lille"],"type_bien":"appartement","echeance":null,"financement":"approved"}'):
        m = mock.Mock()
        m.status_code = statut
        m.text = texte
        m.json.return_value = {"content": [{"type": "text", "text": texte}]}
        return m

    def test_extraction_normale(self):
        t = self.jeton("ext@x.fr")
        with mock.patch.object(backend.requests, "post", return_value=self.reponse_anthropic()) as p:
            r = self.c.post("/api/v1/extract", json={"message": "Bonjour, je cherche un T3 à Lille, 280000 euros"}, headers=self.h(t))
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        d = r.get_json()
        self.assertEqual((d["nom"], d["telephone"], d["budget"], d["type_bien"]), ("Thomas Martin", "0612345678", 280000, "Appartement"))
        self.assertEqual(p.call_args.kwargs["headers"]["x-api-key"], "sk-ant-api03-fake")

    def test_cle_avec_caractere_parasite(self):
        t = self.jeton("ext2@x.fr")
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "  sk-ant-api03-fake\n"}):
            with mock.patch.object(backend.requests, "post", return_value=self.reponse_anthropic()) as p:
                self.c.post("/api/v1/extract", json={"message": "Bonjour, je cherche un T3 à Lille"}, headers=self.h(t))
        self.assertEqual(p.call_args.kwargs["headers"]["x-api-key"], "sk-ant-api03-fake")

    def test_erreur_amont_conservee(self):
        t = self.jeton("ext3@x.fr")
        with mock.patch.object(backend.requests, "post", return_value=self.reponse_anthropic(401, '{"error":"invalid x-api-key"}')):
            r = self.c.post("/api/v1/extract", json={"message": "Bonjour, je cherche un T3 à Lille"}, headers=self.h(t))
        self.assertEqual(r.status_code, 502)
        self.assertIn("code 401", r.get_json()["message"])

    def test_limite_par_utilisateur(self):
        ta = self.jeton("quota-a@x.fr"); tb = self.jeton("quota-b@x.fr")
        with mock.patch.object(backend.requests, "post", return_value=self.reponse_anthropic()):
            codes = [self.c.post("/api/v1/extract", json={"message": "Bonjour, je cherche un T3 à Lille"},
                                 headers=self.h(ta), environ_base={"REMOTE_ADDR": f"10.5.0.{i}"}).status_code
                     for i in range(32)]
            self.assertEqual(codes[:30], [200] * 30)
            self.assertEqual(codes[30:], [429] * 2)
            # un autre utilisateur n'est pas concerné
            r = self.c.post("/api/v1/extract", json={"message": "Bonjour, je cherche un T3 à Lille"}, headers=self.h(tb))
            self.assertEqual(r.status_code, 200)

    def test_sans_jeton(self):
        r = self.c.post("/api/v1/extract", json={"message": "Bonjour, je cherche un T3 à Lille"})
        self.assertEqual(r.status_code, 401)

    def test_message_trop_court(self):
        t = self.jeton("ext4@x.fr")
        r = self.c.post("/api/v1/extract", json={"message": "court"}, headers=self.h(t))
        self.assertEqual(r.status_code, 400)


# ---------------------------------------------------------------- mots de passe
import re as _re
import threading as _th


class BaseMdp(Base):
    """Capture les e-mails au lieu de les envoyer, et exécute l'envoi sans thread."""

    def setUp(self):
        super().setUp()
        self.envoyes = []

        def faux(dest, sujet, texte, html):
            self.envoyes.append({"to": dest, "sujet": sujet, "texte": texte, "html": html})
            return True

        for p in (mock.patch.object(backend, "_envoyer_email", side_effect=faux),
                  mock.patch.object(backend, "_lancer_en_arriere_plan", side_effect=lambda f, *a: f(*a)),
                  mock.patch.dict(os.environ, {"FRONTEND_URL": "https://app.zelyro.fr/",
                                               "BREVO_API_KEY": "cle-de-test", "MAIL_FROM": "contact@zelyro.fr"})):
            p.start()
            self.addCleanup(p.stop)

    def ip(self, i):
        return {"REMOTE_ADDR": f"10.9.0.{i}"}

    def oubli(self, email, i=1):
        return self.c.post("/auth/forgot-password", json={"email": email}, environ_base=self.ip(i))

    def lien_recu(self):
        m = _re.search(r"#token=([\w-]+)", self.envoyes[-1]["texte"])
        self.assertTrue(m, "aucun lien dans le dernier e-mail")
        return m.group(1)

    def connexion(self, email, pw):
        return self.c.post("/auth/login", json={"email": email, "password": pw})

    def profil(self, tok):
        return self.c.get("/auth/profile", headers=self.h(tok)).status_code


class TestChangementMdp(BaseMdp):
    NOUVEAU = "un-autre-mot-de-passe-solide"

    def changer(self, tok, actuel=PW, nouveau=NOUVEAU):
        return self.c.post("/auth/change-password", headers=self.h(tok),
                           json={"current_password": actuel, "new_password": nouveau})

    def test_exige_une_connexion(self):
        r = self.c.post("/auth/change-password", json={"current_password": PW, "new_password": self.NOUVEAU})
        self.assertEqual(r.status_code, 401)

    def test_mauvais_mot_de_passe_actuel_renvoie_400_pas_401(self):
        tok = self.jeton("cm1@x.fr")
        r = self.changer(tok, actuel="pas-le-bon-mot-de-passe")
        self.assertEqual(r.status_code, 400)          # 401 déconnecterait l'utilisateur dans le site
        self.assertEqual(self.connexion("cm1@x.fr", PW).status_code, 200)
        self.assertEqual(self.profil(tok), 200)

    def test_succes(self):
        tok = self.jeton("cm2@x.fr")
        r = self.changer(tok)
        self.assertEqual(r.status_code, 200)
        neuf = r.get_json()["token"]
        self.assertEqual(self.connexion("cm2@x.fr", self.NOUVEAU).status_code, 200)
        self.assertEqual(self.connexion("cm2@x.fr", PW).status_code, 401)
        self.assertEqual(self.profil(tok), 401)        # l'ancienne session est coupée
        self.assertEqual(self.profil(neuf), 200)       # la session courante continue
        self.assertEqual([m["to"] for m in self.envoyes], ["cm2@x.fr"])
        self.assertIn("modifié", self.envoyes[0]["sujet"])

    def test_autre_session_ouverte_avant_est_coupee(self):
        self.inscrire("cm3@x.fr")
        s1 = self.connexion("cm3@x.fr", PW).get_json()["token"]
        s2 = self.connexion("cm3@x.fr", PW).get_json()["token"]
        self.assertEqual(self.changer(s1).status_code, 200)
        self.assertEqual(self.profil(s2), 401)

    def test_regles_du_nouveau_mot_de_passe(self):
        tok = self.jeton("cm4@x.fr")
        self.assertEqual(self.changer(tok, nouveau="court").status_code, 400)
        self.assertEqual(self.changer(tok, nouveau="x" * 200).status_code, 400)
        self.assertEqual(self.changer(tok, nouveau=PW).status_code, 400)          # identique à l'ancien
        self.assertEqual(self.c.post("/auth/change-password", headers=self.h(tok), json={}).status_code, 400)
        self.assertEqual(self.c.post("/auth/change-password", headers=self.h(tok),
                                     json={"current_password": 123, "new_password": ["a"]}).status_code, 400)
        self.assertEqual(self.connexion("cm4@x.fr", PW).status_code, 200)         # rien n'a changé

    def test_devinette_du_mot_de_passe_actuel_limitee(self):
        tok = self.jeton("cm5@x.fr")
        codes = [self.changer(tok, actuel=f"mauvais-mot-de-passe-{i}").status_code for i in range(7)]
        self.assertEqual(codes[:5], [400] * 5)
        self.assertEqual(codes[5:], [429] * 2)
        self.assertEqual(self.changer(tok).status_code, 429)   # même avec le bon mot de passe

    def test_les_succes_ne_sont_pas_comptes(self):
        tok = self.jeton("cm6@x.fr")
        mdp = PW
        for i in range(7):
            suivant = f"mot-de-passe-numero-{i}-solide"
            r = self.changer(tok, actuel=mdp, nouveau=suivant)
            self.assertEqual(r.status_code, 200, i)
            tok, mdp = r.get_json()["token"], suivant


class TestOubliMdp(BaseMdp):
    def test_meme_reponse_compte_connu_ou_non(self):
        self.inscrire("ou1@x.fr")
        a = self.oubli("ou1@x.fr", 1)
        b = self.oubli("inconnu-total@x.fr", 2)
        self.assertEqual(a.status_code, 200)
        self.assertEqual(b.status_code, 200)
        self.assertEqual(a.get_json(), b.get_json())
        self.assertEqual([m["to"] for m in self.envoyes], ["ou1@x.fr"])      # rien pour l'inconnu

    def test_adresse_invalide(self):
        self.assertEqual(self.oubli("pas-un-email").status_code, 400)
        self.assertEqual(self.c.post("/auth/forgot-password", json={}).status_code, 400)
        self.assertEqual(self.c.post("/auth/forgot-password", data="x", content_type="text/plain").status_code, 400)

    def test_lien_bien_forme_et_jamais_stocke_en_clair(self):
        self.inscrire("Ou2@X.fr")
        self.oubli("OU2@x.fr")
        mail = self.envoyes[-1]
        self.assertEqual(mail["to"], "Ou2@x.fr".lower())        # adresse de la base, en minuscules
        self.assertIn("https://app.zelyro.fr/reset-password.html#token=", mail["texte"])   # sans double //
        self.assertNotIn("//reset-password", mail["texte"])
        jeton = self.lien_recu()
        self.assertGreaterEqual(len(jeton), 40)
        conn = backend.get_db_connection(); cur = conn.cursor()
        cur.execute("SELECT token_hash, expires_at, used_at FROM password_resets ORDER BY id DESC LIMIT 1")
        h, expire, utilise = cur.fetchone()
        cur.execute("SELECT count(*) FROM password_resets WHERE token_hash = %s", (jeton,))
        en_clair = cur.fetchone()[0]
        conn.close()
        self.assertEqual(h, backend._hash_jeton(jeton))
        self.assertEqual(en_clair, 0)
        self.assertIsNone(utilise)
        delta = (expire - backend._maintenant()).total_seconds()
        self.assertTrue(28 * 60 < delta <= 30 * 60, delta)

    def test_l_adresse_du_lien_ne_vient_jamais_de_la_requete(self):
        self.inscrire("ou3@x.fr")
        self.c.post("/auth/forgot-password", json={"email": "ou3@x.fr"},
                    headers={"Host": "evil.com", "Origin": "https://evil.com", "X-Forwarded-Host": "evil.com"})
        self.assertNotIn("evil.com", self.envoyes[-1]["texte"] + self.envoyes[-1]["html"])

    def test_nouvelle_demande_annule_la_precedente(self):
        self.inscrire("ou4@x.fr")
        self.oubli("ou4@x.fr", 1); premier = self.lien_recu()
        self.oubli("ou4@x.fr", 2); second = self.lien_recu()
        self.assertNotEqual(premier, second)
        r1 = self.c.post("/auth/reset-password", json={"token": premier, "new_password": "nouveau-mot-de-passe-1"})
        self.assertEqual(r1.status_code, 400)
        r2 = self.c.post("/auth/reset-password", json={"token": second, "new_password": "nouveau-mot-de-passe-1"})
        self.assertEqual(r2.status_code, 200)

    def test_limite_par_adresse(self):
        self.inscrire("ou5@x.fr")
        codes = [self.oubli("ou5@x.fr", i).status_code for i in range(1, 6)]
        self.assertEqual(codes, [200, 200, 200, 429, 429])
        self.assertEqual(len(self.envoyes), 3)

    def test_limite_par_ip(self):
        codes = [self.oubli(f"quelquun{i}@x.fr", 7).status_code for i in range(7)]
        self.assertEqual(codes, [200] * 5 + [429] * 2)

    def test_sans_configuration_d_envoi_on_le_dit(self):
        """Pas de faux « e-mail envoyé » : 503, identique pour tous les comptes."""
        self.inscrire("ou6@x.fr")
        for manquant in ("FRONTEND_URL", "BREVO_API_KEY", "MAIL_FROM"):
            with mock.patch.dict(os.environ, {manquant: ""}):
                a = self.oubli("ou6@x.fr", 1)
                b = self.oubli("inconnu-ou6@x.fr", 2)
            self.assertEqual((a.status_code, b.status_code), (503, 503), manquant)
            self.assertEqual(a.get_json(), b.get_json())
        self.assertEqual(self.envoyes, [])

    def test_lien_sans_adresse_du_site_ne_plante_pas(self):
        """Protection en profondeur : si _traiter_oubli tourne sans FRONTEND_URL, rien n'est envoyé."""
        self.inscrire("ou7@x.fr")
        with mock.patch.dict(os.environ, {"FRONTEND_URL": ""}):
            backend._traiter_oubli("ou7@x.fr")
        self.assertEqual(self.envoyes, [])


class TestEnvoiBrevo(unittest.TestCase):
    """_envoyer_email lui-même, avec un faux serveur Brevo."""

    def rep(self, code, texte="{}"):
        r = mock.Mock(); r.status_code = code; r.text = texte
        return r

    def env(self, **kw):
        base = {"BREVO_API_KEY": " cle-brevo-test \n", "MAIL_FROM": "contact@zelyro.fr", "MAIL_FROM_NAME": "Zelyro"}
        base.update(kw)
        return mock.patch.dict(os.environ, base)

    def test_requete_envoyee(self):
        with self.env(), mock.patch.object(backend.requests, "post", return_value=self.rep(201)) as post:
            ok = backend._envoyer_email("client@agence.fr", "Sujet", "texte", "<p>html</p>")
        self.assertTrue(ok)
        args, kw = post.call_args
        self.assertEqual(args[0], "https://api.brevo.com/v3/smtp/email")
        self.assertEqual(kw["headers"]["api-key"], "cle-brevo-test")        # espaces retirés
        self.assertEqual(kw["json"]["sender"], {"name": "Zelyro", "email": "contact@zelyro.fr"})
        self.assertEqual(kw["json"]["to"], [{"email": "client@agence.fr"}])
        self.assertEqual(kw["json"]["subject"], "Sujet")
        self.assertIn("timeout", kw)

    def test_refus_de_brevo(self):
        with self.env(), mock.patch.object(backend.requests, "post", return_value=self.rep(401, '{"message":"Key not found"}')):
            self.assertFalse(backend._envoyer_email("a@b.fr", "s", "t", "h"))

    def test_reseau_coupe(self):
        with self.env(), mock.patch.object(backend.requests, "post", side_effect=backend.requests.ConnectionError("boum")):
            self.assertFalse(backend._envoyer_email("a@b.fr", "s", "t", "h"))

    def test_non_configure(self):
        with self.env(BREVO_API_KEY="", MAIL_FROM=""), mock.patch.object(backend.requests, "post") as post:
            self.assertFalse(backend._envoyer_email("a@b.fr", "s", "t", "h"))
            post.assert_not_called()

    def test_gabarit_echappe_le_html(self):
        texte, html = backend._gabarit_email("Titre <b>", ["<script>alert(1)</script>"], ("Go", 'https://x.fr/#a="b'))
        self.assertNotIn("<script>", html)
        self.assertNotIn("<b>", html)
        self.assertIn("&quot;b", html)                 # le guillemet du lien est neutralisé
        self.assertNotIn('a="b', html)


class TestReinitialisation(BaseMdp):
    NOUVEAU = "mot-de-passe-tout-neuf-42"

    def reinit(self, jeton, mdp=NOUVEAU, i=1):
        return self.c.post("/auth/reset-password", json={"token": jeton, "new_password": mdp}, environ_base=self.ip(i))

    def demander(self, email):
        self.inscrire(email)
        self.oubli(email)
        return self.lien_recu()

    def test_parcours_complet(self):
        self.inscrire("re1@x.fr")
        ancienne_session = self.connexion("re1@x.fr", PW).get_json()["token"]
        self.oubli("re1@x.fr")
        jeton = self.lien_recu()
        r = self.reinit(jeton)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.connexion("re1@x.fr", self.NOUVEAU).status_code, 200)
        self.assertEqual(self.connexion("re1@x.fr", PW).status_code, 401)
        self.assertEqual(self.profil(ancienne_session), 401)
        self.assertIn("modifié", self.envoyes[-1]["sujet"])

    def test_lien_a_usage_unique(self):
        jeton = self.demander("re2@x.fr")
        self.assertEqual(self.reinit(jeton).status_code, 200)
        r = self.reinit(jeton, "encore-un-autre-mot-de-passe")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.connexion("re2@x.fr", self.NOUVEAU).status_code, 200)

    def test_mot_de_passe_refuse_ne_consomme_pas_le_lien(self):
        jeton = self.demander("re3@x.fr")
        self.assertEqual(self.reinit(jeton, "court").status_code, 400)
        self.assertEqual(self.reinit(jeton, "x" * 200).status_code, 400)
        self.assertEqual(self.reinit(jeton).status_code, 200)

    def test_liens_invalides(self):
        self.demander("re4@x.fr")
        messages = set()
        for mauvais in ("", "court", "a" * 43, "../../etc/passwd" + "a" * 30, None, 12345, ["x"], "a" * 500):
            r = self.reinit(mauvais)
            self.assertEqual(r.status_code, 400, mauvais)
            messages.add(r.get_json()["message"])
        self.assertEqual(len(messages), 1)             # même réponse partout

    def test_lien_expire(self):
        jeton = self.demander("re5@x.fr")
        conn = backend.get_db_connection(); cur = conn.cursor()
        cur.execute("UPDATE password_resets SET expires_at = %s", (backend._maintenant() - backend.timedelta(seconds=1),))
        conn.commit(); conn.close()
        self.assertEqual(self.reinit(jeton).status_code, 400)
        self.assertEqual(self.connexion("re5@x.fr", PW).status_code, 200)

    def test_le_lien_d_un_compte_ne_change_pas_un_autre(self):
        jeton = self.demander("re6a@x.fr")
        self.inscrire("re6b@x.fr")
        self.assertEqual(self.reinit(jeton).status_code, 200)
        self.assertEqual(self.connexion("re6b@x.fr", PW).status_code, 200)

    def test_compte_supprime_pendant_la_validite(self):
        jeton = self.demander("re7@x.fr")
        conn = backend.get_db_connection(); cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE email = 're7@x.fr'")      # les liens partent avec (ON DELETE CASCADE)
        conn.commit(); conn.close()
        self.assertEqual(self.reinit(jeton).status_code, 400)

    def test_limite(self):
        codes = [self.reinit("a" * 43, i=3).status_code for i in range(12)]
        self.assertEqual(codes[:10], [400] * 10)
        self.assertEqual(codes[10:], [429] * 2)

    def test_reset_puis_deux_reinitialisations_simultanees(self):
        """Deux requêtes en même temps avec le même lien : une seule doit réussir."""
        jeton = self.demander("re8@x.fr")
        resultats = []

        def tirer(n):
            c = backend.app.test_client()
            r = c.post("/auth/reset-password", json={"token": jeton, "new_password": f"mot-de-passe-concurrent-{n}"},
                       environ_base=self.ip(20 + n))
            resultats.append(r.status_code)

        fils = [_th.Thread(target=tirer, args=(n,)) for n in range(4)]
        [f.start() for f in fils]; [f.join() for f in fils]
        self.assertEqual(sorted(resultats), [200, 400, 400, 400])


class TestSessionEtSchema(BaseMdp):
    def test_jeton_d_un_compte_supprime_refuse(self):
        tok = self.jeton("ss1@x.fr")
        self.assertEqual(self.profil(tok), 200)
        conn = backend.get_db_connection(); cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE email = 'ss1@x.fr'")
        conn.commit(); conn.close()
        self.assertEqual(self.profil(tok), 401)
        self.assertEqual(self.c.get("/api/v1/leads", headers=self.h(tok)).status_code, 401)

    def test_jeton_emis_avant_la_mise_a_jour_reste_valable(self):
        """Un jeton sans champ de version (émis par l'ancien backend) vaut version 0."""
        tok = self.jeton("ss2@x.fr")
        conn = backend.get_db_connection(); cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email='ss2@x.fr'")
        uid = cur.fetchone()[0]; conn.close()
        ancien = backend.jwt.encode({"id": uid, "email": "ss2@x.fr",
                                     "exp": backend.datetime.utcnow() + backend.timedelta(hours=1),
                                     "iat": backend.datetime.utcnow()}, backend.SECRET_KEY, algorithm="HS256")
        self.assertEqual(self.profil(ancien), 200)

    def test_base_existante_sans_les_nouveaux_elements(self):
        """Base de production avant déploiement : colonne et table créées toutes seules,
        même si plusieurs processus démarrent en même temps."""
        self.inscrire("ss3@x.fr")
        conn = backend.get_db_connection(); cur = conn.cursor()
        cur.execute("DROP TABLE IF EXISTS password_resets")
        cur.execute("ALTER TABLE users DROP COLUMN IF EXISTS token_version")
        conn.commit(); conn.close()
        backend._schema_pret = False
        erreurs = []

        def go():
            try:
                backend._assurer_schema()
            except Exception as e:      # noqa: BLE001
                erreurs.append(repr(e))

        go()
        self.assertEqual(erreurs, [])
        self.assertEqual(self.connexion("ss3@x.fr", PW).status_code, 200)
        self.assertEqual(self.oubli("ss3@x.fr").status_code, 200)
        self.assertEqual(len(self.envoyes), 1)

    def test_creation_simultanee_par_plusieurs_connexions(self):
        conn = backend.get_db_connection(); cur = conn.cursor()
        cur.execute("DROP TABLE IF EXISTS password_resets")
        cur.execute("ALTER TABLE users DROP COLUMN IF EXISTS token_version")
        conn.commit(); conn.close()
        erreurs = []

        def processus():
            # chaque « processus » a son propre drapeau : on rejoue la fonction avec un verrou de threads neuf
            try:
                ns = dict(backend._assurer_schema.__globals__)
                ns["_schema_pret"] = False
                ns["_schema_verrou"] = _th.Lock()
                exec_fn = type(backend._assurer_schema)(backend._assurer_schema.__code__, ns)
                exec_fn()
            except Exception as e:      # noqa: BLE001
                erreurs.append(repr(e))

        fils = [_th.Thread(target=processus) for _ in range(6)]
        [f.start() for f in fils]; [f.join() for f in fils]
        self.assertEqual(erreurs, [])
        backend._schema_pret = False
        backend._assurer_schema()


class TestCaptureMail(Base):
    """Adresse e-mail personnelle de réception des leads LeBonCoin/SeLoger."""

    def test_adresse_creee_au_premier_appel_et_stable(self):
        t = self.jeton("mailcap1@x.fr")
        r1 = self.c.get("/api/v1/mail-capture", headers=self.h(t))
        self.assertEqual(r1.status_code, 200)
        d1 = r1.get_json()
        self.assertTrue(d1["address"].endswith("@leads.zelyro.fr"))
        self.assertTrue(d1["address"].startswith(d1["token"]))
        r2 = self.c.get("/api/v1/mail-capture", headers=self.h(t))
        self.assertEqual(r2.get_json()["token"], d1["token"])

    def test_deux_comptes_ont_des_adresses_differentes(self):
        ta = self.jeton("mailcap2@x.fr"); tb = self.jeton("mailcap3@x.fr")
        da = self.c.get("/api/v1/mail-capture", headers=self.h(ta)).get_json()
        db = self.c.get("/api/v1/mail-capture", headers=self.h(tb)).get_json()
        self.assertNotEqual(da["token"], db["token"])

    def test_regeneration_change_l_adresse(self):
        t = self.jeton("mailcap4@x.fr")
        avant = self.c.get("/api/v1/mail-capture", headers=self.h(t)).get_json()
        apres = self.c.post("/api/v1/mail-capture/regenerate", headers=self.h(t)).get_json()
        self.assertNotEqual(avant["token"], apres["token"])

    def test_sans_jeton_refuse(self):
        self.assertEqual(self.c.get("/api/v1/mail-capture").status_code, 401)


class BaseInbound(Base):
    """Webhook Brevo (Inbound Parsing) : e-mails LeBonCoin/SeLoger transférés."""

    SECRET = "wh-secret-de-test"

    def setUp(self):
        super().setUp()
        p = mock.patch.dict(os.environ, {"EMAIL_INBOUND_SECRET": self.SECRET})
        p.start()
        self.addCleanup(p.stop)
        p2 = mock.patch.object(backend, "_lancer_en_arriere_plan", side_effect=lambda f, *a: None)
        p2.start()
        self.addCleanup(p2.stop)

    def adresse(self, email):
        t = self.jeton(email)
        return self.c.get("/api/v1/mail-capture", headers=self.h(t)).get_json()["address"], t

    def poster(self, items, cle=None):
        return self.c.post(f"/webhooks/email-inbound?cle={self.SECRET if cle is None else cle}",
                            json={"items": items})

    def item(self, adresse, expediteur="notifications@leboncoin.fr", message_id=None,
              sujet="Nouveau contact pour votre annonce", texte="Bonjour, je suis intéressé."):
        return {
            "MessageId": message_id or f"<{secrets.token_hex(8)}@mail.example>",
            "From": {"Address": expediteur, "Name": "portail"},
            "To": [{"Address": adresse}],
            "Subject": sujet,
            "RawTextBody": texte,
        }

    def reponse_anthropic(self, texte='{"nom":"Thomas Martin","telephone":"0612345678","email":null,'
                                       '"budget":null,"secteurs":[],"type_bien":null,"echeance":null,'
                                       '"financement":null,"notes":"Intéressé par le T3 rue de la Paix."}'):
        m = mock.Mock()
        m.status_code = 200
        m.text = texte
        m.json.return_value = {"content": [{"type": "text", "text": texte}]}
        return m


class TestEmailInbound(BaseInbound):
    def test_mauvais_secret_refuse(self):
        adresse, _ = self.adresse("inb1@x.fr")
        r = self.poster([self.item(adresse)], cle="faux")
        self.assertEqual(r.status_code, 404)

    def test_secret_absent_cote_serveur_refuse(self):
        with mock.patch.dict(os.environ, {"EMAIL_INBOUND_SECRET": ""}):
            r = self.c.post("/webhooks/email-inbound?cle=", json={"items": []})
        self.assertEqual(r.status_code, 404)

    def test_lead_cree_avec_extraction(self):
        adresse, t = self.adresse("inb2@x.fr")
        with mock.patch.object(backend.requests, "post", return_value=self.reponse_anthropic()):
            r = self.poster([self.item(adresse, texte="Bonjour, je suis intéressé par le T3. "
                                                        "Mon numéro : 06 12 34 56 78.")])
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["processed"], 1)
        leads = self.c.get("/api/v1/leads", headers=self.h(t)).get_json()
        self.assertEqual(len(leads), 1)
        self.assertEqual(leads[0]["name"], "Thomas Martin")
        self.assertEqual(leads[0]["phone"], "0612345678")
        self.assertEqual(leads[0]["source"], "leboncoin")

    def test_source_seloger_reconnue(self):
        adresse, t = self.adresse("inb3@x.fr")
        with mock.patch.object(backend.requests, "post", return_value=self.reponse_anthropic()):
            r = self.poster([self.item(adresse, expediteur="notifications@seloger.com")])
        self.assertEqual(r.status_code, 200)
        leads = self.c.get("/api/v1/leads", headers=self.h(t)).get_json()
        self.assertEqual(leads[0]["source"], "seloger")

    def test_extraction_indisponible_cree_quand_meme_un_lead(self):
        """Panne de l'IA (ou clé absente) : le contact n'est pas perdu, la
        fiche est créée avec ce qu'on peut déduire sans elle."""
        adresse, t = self.adresse("inb4@x.fr")
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": ""}):
            r = self.poster([self.item(adresse, expediteur="jean.dupont@leboncoin.fr",
                                        texte="Bonjour, ce bien m'intéresse, merci de me rappeler.")])
        self.assertEqual(r.status_code, 200)
        leads = self.c.get("/api/v1/leads", headers=self.h(t)).get_json()
        self.assertEqual(len(leads), 1)
        self.assertEqual(leads[0]["source"], "leboncoin")
        notes = self.c.get(f"/api/v1/leads/{leads[0]['id']}/notes", headers=self.h(t)).get_json()
        self.assertTrue(any("intéresse" in (n["body"] or "") for n in notes))

    def test_meme_message_id_pas_de_doublon(self):
        adresse, t = self.adresse("inb5@x.fr")
        mid = "<unique-1@mail.example>"
        with mock.patch.object(backend.requests, "post", return_value=self.reponse_anthropic()):
            self.poster([self.item(adresse, message_id=mid)])
            self.poster([self.item(adresse, message_id=mid)])
        leads = self.c.get("/api/v1/leads", headers=self.h(t)).get_json()
        self.assertEqual(len(leads), 1)

    def test_adresse_inconnue_ignoree_sans_erreur(self):
        r = self.poster([self.item("jeton-invente-xyz@leads.zelyro.fr")])
        self.assertEqual(r.status_code, 200)

    def test_agence_suspendue_ignoree(self):
        adresse, t = self.adresse("inb6@x.fr")
        with backend._base() as (conn, cur):
            cur.execute("UPDATE users SET is_active = FALSE WHERE email = 'inb6@x.fr'")
            conn.commit()
        with mock.patch.object(backend.requests, "post", return_value=self.reponse_anthropic()):
            r = self.poster([self.item(adresse)])
        self.assertEqual(r.status_code, 200)
        with backend._base() as (conn, cur):
            cur.execute("SELECT count(*) AS n FROM leads l JOIN users u ON u.id = l.user_id "
                        "WHERE u.email = 'inb6@x.fr'")
            self.assertEqual(cur.fetchone()["n"], 0)

    def test_quota_leads_plein_pas_de_creation(self):
        adresse, t = self.adresse("inb7@x.fr")
        with mock.patch.object(backend, "_forfait",
                                side_effect=lambda cur, uid: {"code": "essentiel", "label": "Essentiel",
                                                              "limits": {"leads": 0, "properties": 100,
                                                                         "mails": 200, "extractions": 100}}):
            with mock.patch.object(backend.requests, "post", return_value=self.reponse_anthropic()):
                r = self.poster([self.item(adresse)])
        self.assertEqual(r.status_code, 200)
        leads = self.c.get("/api/v1/leads", headers=self.h(t)).get_json()
        self.assertEqual(len(leads), 0)


# ---------------------------------------------------------------- import des biens
class TestImportBiens(Base):
    URL = "/api/v1/properties/import"

    def importer(self, tok, rows, **kw):
        return self.c.post(self.URL, json={"rows": rows, **kw}, headers=self.h(tok))

    def biens(self, tok):
        return self.c.get("/api/v1/properties", headers=self.h(tok)).get_json()

    def test_exige_une_connexion(self):
        self.assertEqual(self.c.post(self.URL, json={"rows": [{"title": "x"}]}).status_code, 401)

    def test_cree_les_biens_et_lit_les_formats_francais(self):
        t = self.jeton("imp-formats@x.fr")
        r = self.importer(t, [
            {"reference": "DP-1", "title": "Maison Senlis", "address": "Senlis 60300", "price": "395 000 €",
             "size": "118,5 m²", "rooms": "5", "property_type": "Pavillon"},
            {"reference": "DP-2", "address": "Chantilly", "price": "245.000", "rooms": "3", "property_type": "T3"},
        ])
        self.assertEqual(r.status_code, 200, r.get_json())
        d = r.get_json()
        self.assertEqual((d["imported"], d["updated"], d["duplicates"], d["invalid_count"]), (2, 0, 0, 0))
        b = {x["reference"]: x for x in self.biens(t)}
        self.assertEqual(b["DP-1"]["price"], 395000)
        self.assertEqual(b["DP-1"]["size"], 118)
        self.assertEqual(b["DP-1"]["property_type"], "Maison")
        self.assertEqual(b["DP-2"]["price"], 245000)
        self.assertEqual(b["DP-2"]["property_type"], "Appartement")
        self.assertEqual(b["DP-2"]["title"], "Appartement 3 pièces — Chantilly")

    def test_reimporter_met_a_jour_sans_dupliquer(self):
        t = self.jeton("imp-maj@x.fr")
        self.importer(t, [{"reference": "ABC-1", "title": "T2 centre", "address": "Lille", "price": 150000}])
        r = self.importer(t, [{"reference": "abc-1", "price": "140 000", "description": "Baisse de prix"}])
        d = r.get_json()
        self.assertEqual((d["imported"], d["updated"]), (0, 1))
        biens = self.biens(t)
        self.assertEqual(len(biens), 1)
        self.assertEqual(biens[0]["price"], 140000)
        self.assertEqual(biens[0]["title"], "T2 centre")          # une cellule vide n'efface rien
        self.assertEqual(biens[0]["address"], "Lille")
        self.assertEqual(biens[0]["description"], "Baisse de prix")

    def test_donne_sa_reference_a_un_bien_saisi_a_la_main(self):
        t = self.jeton("imp-main@x.fr")
        self.c.post("/api/v1/properties", json={"title": "Villa du port", "address": "Nice"}, headers=self.h(t))
        r = self.importer(t, [{"reference": "V-9", "title": "Villa du port", "address": "Nice", "price": 900000}])
        d = r.get_json()
        self.assertEqual((d["imported"], d["updated"]), (0, 1))
        biens = self.biens(t)
        self.assertEqual(len(biens), 1)
        self.assertEqual((biens[0]["reference"], biens[0]["price"]), ("V-9", 900000))

    def test_sans_reference_un_meme_bien_est_ignore(self):
        t = self.jeton("imp-doublon@x.fr")
        ligne = {"title": "Studio gare", "address": "Lille", "price": 90000}
        self.importer(t, [ligne])
        d = self.importer(t, [ligne, {**ligne, "title": "Studio gare bis"}]).get_json()
        self.assertEqual((d["imported"], d["duplicates"]), (1, 1))
        self.assertEqual(len(self.biens(t)), 2)

    def test_une_reference_est_propre_a_chaque_agence(self):
        ta, tb = self.jeton("imp-iso-a@x.fr"), self.jeton("imp-iso-b@x.fr")
        self.importer(ta, [{"reference": "R-1", "title": "Bien de A", "price": 100000}])
        d = self.importer(tb, [{"reference": "R-1", "title": "Bien de B", "price": 200000}]).get_json()
        self.assertEqual((d["imported"], d["updated"]), (1, 0))
        self.assertEqual(self.biens(ta)[0]["price"], 100000)
        self.assertEqual(self.biens(tb)[0]["price"], 200000)

    def test_saisie_manuelle_refuse_une_reference_deja_prise(self):
        t = self.jeton("imp-manuel@x.fr")
        self.assertEqual(self.c.post("/api/v1/properties", json={"title": "A", "reference": "M-1"}, headers=self.h(t)).status_code, 201)
        self.assertEqual(self.c.post("/api/v1/properties", json={"title": "B", "reference": "m-1"}, headers=self.h(t)).status_code, 409)

    def test_lignes_invalides_signalees(self):
        t = self.jeton("imp-invalides@x.fr")
        d = self.importer(t, [{"title": "Bon bien", "address": "Paris"}, {"price": 100}, "texte", {"title": "Autre", "address": "Lyon"}],
                          offset=10).get_json()
        self.assertEqual(d["imported"], 2)
        self.assertEqual(d["invalid_count"], 2)
        self.assertEqual([l["ligne"] for l in d["invalid"]], [12, 13])

    def test_avertit_des_types_inconnus_et_des_adresses_manquantes(self):
        t = self.jeton("imp-avert@x.fr")
        d = self.importer(t, [{"title": "Péniche", "address": "Lille", "property_type": "Péniche"},
                              {"title": "Sans adresse", "property_type": "Maison"}]).get_json()
        self.assertEqual(d["unknown_types"], ["Péniche"])
        self.assertEqual((d["without_address"], d["without_type"]), (1, 1))

    def test_refuse_les_envois_mal_formes(self):
        t = self.jeton("imp-forme@x.fr")
        self.assertEqual(self.c.post(self.URL, json={}, headers=self.h(t)).status_code, 400)
        self.assertEqual(self.c.post(self.URL, json={"rows": []}, headers=self.h(t)).status_code, 400)
        self.assertEqual(self.c.post(self.URL, json={"rows": "x"}, headers=self.h(t)).status_code, 400)
        trop = [{"title": f"Bien {i}"} for i in range(backend.MAX_LIGNES_IMPORT + 1)]
        self.assertEqual(self.importer(t, trop).status_code, 400)

    def test_limite_du_forfait_et_mises_a_jour_toujours_possibles(self):
        t = self.jeton("imp-quota@x.fr")           # forfait Essentiel : 100 biens
        lignes = [{"reference": f"Q-{i}", "title": f"Bien {i}", "address": "Lille"} for i in range(101)]
        d = self.importer(t, lignes).get_json()
        self.assertEqual((d["imported"], d["over_quota"]), (100, 1))
        self.assertIn("Essentiel", d["quota_message"])
        self.assertEqual(len(self.biens(t)), 100)
        d = self.importer(t, [{"reference": "Q-3", "price": 123000}, {"reference": "Q-new", "title": "Un de trop"}]).get_json()
        self.assertEqual((d["imported"], d["updated"], d["over_quota"]), (0, 1, 1))

    def test_donnees_lues_en_texte_pas_en_sql(self):
        t = self.jeton("imp-sql@x.fr")
        d = self.importer(t, [{"title": "x'); DROP TABLE properties;--", "address": "Lille"}]).get_json()
        self.assertEqual(d["imported"], 1)
        self.assertEqual(len(self.biens(t)), 1)

    def test_conversion_des_nombres_et_des_types(self):
        f = backend._entier_souple
        for brut, attendu in (("249 000 €", 249000), ("249000,00", 249000), ("1.250.000", 1250000), ("1.250,00", 1250),
                              ("68,5", 68), ("  72 m² ", 72), (3, 3), (12.0, 12), ("", None), ("abc", None), (None, None),
                              (True, None), ("99999999999999", None)):
            self.assertEqual(f(brut), attendu, brut)
        g = backend._type_bien
        for brut, attendu in (("appartement", "Appartement"), ("Appart", "Appartement"), ("T3", "Appartement"), ("F2", "Appartement"),
                              ("Pavillon", "Maison"), ("Maison de ville", "Maison"), ("Villa", "Villa"), ("Studio", "Studio"),
                              ("Penthouse", "Penthouse"), ("Terrain à bâtir", "Terrain"), ("Local commercial", "Local commercial"),
                              ("Boutique", "Local commercial"), ("Local", "Local commercial"), ("Bureaux", "Bureau"),
                              ("Plateau de bureaux", "Bureau"), ("Local professionnel", "Bureau"), ("Garage", None), ("", None)):
            self.assertEqual(g(brut), attendu, brut)

    def test_locaux_commerciaux_et_bureaux(self):
        t = self.jeton("imp-pro@x.fr")
        r = self.importer(t, [
            {"reference": "PRO-1", "title": "Boutique centre-ville", "address": "Senlis 60300", "price": "180000", "property_type": "Boutique"},
            {"reference": "PRO-2", "title": "Plateau de bureaux", "address": "Chantilly 60500", "price": "320000", "property_type": "Bureaux"},
            {"reference": "PRO-3", "title": "Terrain constructible", "address": "Creil 60100", "price": "90000", "property_type": "Terrain"},
        ])
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual(r.get_json()["unknown_types"], [])
        b = {x["reference"]: x["property_type"] for x in self.biens(t)}
        self.assertEqual(b, {"PRO-1": "Local commercial", "PRO-2": "Bureau", "PRO-3": "Terrain"})

    def test_correspondance_local_commercial_et_bureau(self):
        # le détail du barème est dans TestScoringPro ; ici : même type > type voisin > autre type
        prospect = {"property_type": "Bureau", "budget": 300000, "location": "Senlis"}
        bien = lambda t: {"property_type": t, "price": 300000, "address": "Senlis 60300", "title": "x"}
        meme = backend.calculate_lead_score(prospect, bien("Bureau"))
        voisin = backend.calculate_lead_score(prospect, bien("Local commercial"))
        autre = backend.calculate_lead_score(prospect, bien("Maison"))
        self.assertEqual(meme - voisin, 10)
        self.assertGreater(voisin, autre)
        self.assertLessEqual(autre, backend.PLAFOND_TYPE_DIFFERENT)

    def test_l_extraction_ia_connait_les_nouveaux_types(self):
        self.assertIn("Local commercial", backend.TYPES_BIEN)
        self.assertIn("Bureau", backend.TYPES_BIEN)
        self.assertIn("Terrain", backend.TYPES_BIEN)


# ---------------------------------------------------------------- modifier la fiche d'un prospect
class TestModifierProspect(Base):
    def creer(self, tok, nom="Alice Martin", **kw):
        r = self.c.post("/api/v1/leads", json={"name": nom, **kw}, headers=self.h(tok))
        self.assertEqual(r.status_code, 201)
        return r.get_json()["id"]

    def lire(self, tok, lead_id):
        return self.c.get(f"/api/v1/leads/{lead_id}", headers=self.h(tok)).get_json()

    def modifier(self, tok, lead_id, **corps):
        return self.c.put(f"/api/v1/leads/{lead_id}", json=corps, headers=self.h(tok))

    def test_change_le_telephone_l_email_et_le_nom(self):
        t = self.jeton("edit-base@x.fr")
        i = self.creer(t, phone="06 01 02 03 04", email="alice@x.fr", budget=300000)
        r = self.modifier(t, i, name="Alice Martin-Durand", phone="+33 6 05 06 07 08", email="Alice.Nouvelle@X.fr", budget=320000)
        self.assertEqual(r.status_code, 200, r.get_json())
        f = self.lire(t, i)
        self.assertEqual((f["name"], f["phone"], f["email"], f["budget"]),
                         ("Alice Martin-Durand", "+33 6 05 06 07 08", "alice.nouvelle@x.fr", 320000))

    def test_l_ancienne_route_laisse_les_coordonnees_intactes(self):
        t = self.jeton("edit-ancienne@x.fr")
        i = self.creer(t, phone="0601020304", email="alice@x.fr")
        r = self.c.put(f"/api/v1/leads/{i}/update-financing", json={"budget": 250000}, headers=self.h(t))
        self.assertEqual(r.status_code, 200)
        f = self.lire(t, i)
        self.assertEqual((f["name"], f["phone"], f["email"], f["budget"]), ("Alice Martin", "0601020304", "alice@x.fr", 250000))

    def test_vider_l_email_ou_le_telephone(self):
        t = self.jeton("edit-vider@x.fr")
        i = self.creer(t, phone="0601020304", email="alice@x.fr")
        self.assertEqual(self.modifier(t, i, email="", phone=None).status_code, 200)
        f = self.lire(t, i)
        self.assertEqual((f["email"], f["phone"]), (None, None))

    def test_refuse_les_valeurs_invalides(self):
        t = self.jeton("edit-invalide@x.fr")
        i = self.creer(t, phone="0601020304", email="alice@x.fr")
        for corps in ({"name": "  "}, {"email": "pas-un-email"}, {"phone": "abc"}, {"phone": "12"}, {"phone": "0" * 25}):
            self.assertEqual(self.modifier(t, i, **corps).status_code, 400, corps)
        f = self.lire(t, i)
        self.assertEqual((f["name"], f["phone"], f["email"]), ("Alice Martin", "0601020304", "alice@x.fr"))

    def test_signale_un_numero_ou_un_email_deja_utilise(self):
        t = self.jeton("edit-doublon@x.fr")
        i = self.creer(t, phone="0601020304", email="alice@x.fr")
        self.creer(t, nom="Bob Durand", phone="06 99 99 99 99", email="bob@x.fr")
        r = self.modifier(t, i, phone="0699999999")
        self.assertEqual(r.status_code, 409)
        self.assertIn("Bob Durand", r.get_json()["message"])
        self.assertEqual(self.modifier(t, i, email="BOB@x.fr").status_code, 409)
        self.assertEqual(self.lire(t, i)["phone"], "0601020304")
        # l'agent confirme : c'est bien le même prospect saisi deux fois
        self.assertEqual(self.modifier(t, i, phone="0699999999", confirm_duplicate=True).status_code, 200)
        self.assertEqual(self.lire(t, i)["phone"], "0699999999")

    def test_reenvoyer_ses_propres_coordonnees_n_est_pas_un_doublon(self):
        t = self.jeton("edit-meme@x.fr")
        i = self.creer(t, phone="06 01 02 03 04", email="alice@x.fr")
        self.assertEqual(self.modifier(t, i, phone="06 01 02 03 04", email="alice@x.fr", notes="Rappeler lundi").status_code, 200)

    def test_une_agence_ne_modifie_pas_le_prospect_d_une_autre(self):
        ta, tb = self.jeton("edit-iso-a@x.fr"), self.jeton("edit-iso-b@x.fr")
        i = self.creer(ta, phone="0601020304")
        self.assertEqual(self.modifier(tb, i, name="Intrus", phone="0611111111").status_code, 404)
        f = self.lire(ta, i)
        self.assertEqual((f["name"], f["phone"]), ("Alice Martin", "0601020304"))

    def test_les_doublons_ne_se_comparent_qu_au_sein_de_l_agence(self):
        ta, tb = self.jeton("edit-sep-a@x.fr"), self.jeton("edit-sep-b@x.fr")
        self.creer(ta, nom="Chez A", phone="0602030405")
        i = self.creer(tb, nom="Chez B")
        self.assertEqual(self.modifier(tb, i, phone="0602030405").status_code, 200)

    def test_exige_une_connexion(self):
        self.assertEqual(self.c.put("/api/v1/leads/1", json={"phone": "0601020304"}).status_code, 401)


# ---------------------------------------------------------------- scoring des locaux commerciaux et bureaux
class TestScoringPro(unittest.TestCase):
    PROSPECT = {"property_type": "Bureau", "budget": 300000, "location": "Senlis", "surface_min": 100,
                "financing_status": "approved", "purchase_urgency": "immediate"}

    def bien(self, **kw):
        return {"property_type": "Bureau", "price": 300000, "size": 120, "address": "10 rue Nationale 60300 Senlis",
                "title": "Plateau", **kw}

    def score(self, lead=None, **kw):
        return backend._detail_score({**self.PROSPECT, **(lead or {})}, self.bien(**kw))

    def test_correspondance_parfaite_sur_100(self):
        score, raisons = self.score()
        self.assertEqual(score, 100)
        self.assertIn("Surface adaptée : 120 m² pour 100 m² recherchés", raisons)
        self.assertIn("Emplacement recherché : Senlis", raisons)

    def test_la_surface_pese_dans_le_calcul(self):
        base = self.score()[0]
        trop_petit = self.score(size=60)
        self.assertEqual(base - trop_petit[0], 15)
        self.assertTrue(any(r.startswith("Surface insuffisante") for r in trop_petit[1]))
        for taille, points in ((100, 15), (150, 15), (151, 11), (250, 11), (251, 5), (90, 11), (75, 5), (74, 0)):
            self.assertEqual(base - self.score(size=taille)[0], 15 - points, taille)

    def test_surface_inconnue_ni_bonus_ni_elimination(self):
        sans_besoin, r1 = self.score({"surface_min": None})
        sans_taille, r2 = self.score(size=None)
        self.assertEqual(sans_besoin, 92)
        self.assertEqual(sans_taille, 92)
        self.assertIn("Surface souhaitée non précisée", r1)
        self.assertIn("Surface du bien non renseignée", r2)

    def test_les_pieces_ne_comptent_pas(self):
        self.assertEqual(self.score(rooms=1)[0], self.score(rooms=9)[0])

    def test_bureau_et_local_commercial_sont_voisins(self):
        score, raisons = self.score(property_type="Local commercial")
        self.assertEqual(score, 90)
        self.assertIn("Type voisin (local commercial ou bureau)", raisons)

    def test_un_logement_n_est_pas_propose_a_une_recherche_de_bureau(self):
        for type_bien in ("Maison", "Appartement", "Terrain"):
            score, raisons = self.score(property_type=type_bien)
            self.assertLessEqual(score, backend.PLAFOND_TYPE_DIFFERENT, type_bien)
            self.assertLess(score, backend.PROPOSITION_SCORE_MIN, type_bien)
            self.assertLess(score, backend.ALERTE_SCORE_MIN, type_bien)
            self.assertTrue(any(r.startswith("Type de bien différent") for r in raisons))
        # et l'inverse : un prospect « maison » face à un bureau
        score, _ = backend._detail_score({**self.PROSPECT, "property_type": "Maison"}, self.bien())
        self.assertLess(score, backend.PROPOSITION_SCORE_MIN)

    def test_autre_ville_elimine(self):
        score, raisons = self.score(address="3 rue de la Paix 75002 Paris")
        self.assertEqual((score, raisons), (0, ["Hors du secteur recherché"]))

    def test_type_non_precise_n_elimine_pas(self):
        score, raisons = self.score({"property_type": None})
        self.assertEqual(score, 88)
        self.assertIn("Type de bien non précisé", raisons)

    def test_l_emplacement_pese_plus_que_pour_un_logement(self):
        # sans secteur : 10 points sur 25 pour un bureau (8 sur 20 pour un logement)
        self.assertEqual(self.score({"location": None})[0], 100 - 25 + 10)

    def test_le_calcul_des_logements_est_inchange(self):
        maison = {"property_type": "Maison", "budget": 300000, "location": "Senlis",
                  "financing_status": "approved", "purchase_urgency": "immediate", "surface_min": 100}
        score, _ = backend._detail_score(maison, {"property_type": "Maison", "price": 300000, "size": 5,
                                                  "address": "Senlis 60300", "title": "x"})
        self.assertEqual(score, 100)       # 20 + 30 + 20 + 20 + 15 = 105, plafonné
        voisin, _ = backend._detail_score({**maison, "property_type": "Appartement"},
                                          {"property_type": "Maison", "price": 300000, "address": "Senlis", "title": "x"})
        self.assertEqual(voisin, 90)       # type voisin 15 au lieu de 30


class TestSurfaceProspect(Base):
    def test_surface_enregistree_creation_fiche_et_modification(self):
        t = self.jeton("surf-1@x.fr")
        r = self.c.post("/api/v1/leads", json={"name": "Société Dupont", "property_type": "Bureau", "surface_min": "120"},
                        headers=self.h(t))
        self.assertEqual(r.status_code, 201, r.get_json())
        self.assertEqual(r.get_json()["surface_min"], 120)
        i = r.get_json()["id"]
        fiche = self.c.get(f"/api/v1/leads/{i}", headers=self.h(t)).get_json()
        self.assertEqual(fiche["surface_min"], 120)
        # une modification sans la clé la laisse intacte
        self.assertEqual(self.c.put(f"/api/v1/leads/{i}", json={"notes": "rappeler"}, headers=self.h(t)).status_code, 200)
        self.assertEqual(self.c.get(f"/api/v1/leads/{i}", headers=self.h(t)).get_json()["surface_min"], 120)
        # avec la clé, elle change ; vide ou illisible, elle s'efface
        self.c.put(f"/api/v1/leads/{i}", json={"surface_min": 200}, headers=self.h(t))
        self.assertEqual(self.c.get(f"/api/v1/leads/{i}", headers=self.h(t)).get_json()["surface_min"], 200)
        self.c.put(f"/api/v1/leads/{i}", json={"surface_min": ""}, headers=self.h(t))
        self.assertIsNone(self.c.get(f"/api/v1/leads/{i}", headers=self.h(t)).get_json()["surface_min"])
        self.c.put(f"/api/v1/leads/{i}", json={"surface_min": -5}, headers=self.h(t))
        self.assertIsNone(self.c.get(f"/api/v1/leads/{i}", headers=self.h(t)).get_json()["surface_min"])

    def test_surface_dans_la_liste_et_les_correspondances(self):
        t = self.jeton("surf-2@x.fr")
        self.c.post("/api/v1/leads", json={"name": "Cabinet Martin", "property_type": "Bureau", "budget": 300000,
                                           "location": "Senlis", "surface_min": 100}, headers=self.h(t))
        self.c.post("/api/v1/properties", json={"title": "Plateau", "address": "Senlis 60300", "price": 300000,
                                                "size": 120, "property_type": "Bureau"}, headers=self.h(t))
        self.c.post("/api/v1/properties", json={"title": "Petit bureau", "address": "Senlis 60300", "price": 300000,
                                                "size": 40, "property_type": "Bureau"}, headers=self.h(t))
        liste = self.c.get("/api/v1/leads", headers=self.h(t)).get_json()
        self.assertEqual(liste[0]["surface_min"], 100)
        d = self.c.get("/api/v1/improved-matches", headers=self.h(t)).get_json()
        scores = {m["title"]: m["score"] for m in d[0]["matches"]}
        self.assertGreater(scores["Plateau"], scores["Petit bureau"])
        self.assertTrue(any("Surface" in r for m in d[0]["matches"] for r in m["reasons"]))


    def test_surface_via_import_csv_et_formulaire_public(self):
        t = self.jeton("surf-3@x.fr")
        r = self.c.post("/api/v1/leads/import", headers=self.h(t), json={"rows": [
            {"name": "Cabinet A", "email": "a@cabinet.fr", "property_type": "Bureau", "surface_min": "120 m²"},
            {"name": "Cabinet B", "email": "b@cabinet.fr", "property_type": "Bureau", "surface_min": "abc"},
            {"name": "Cabinet C", "email": "c@cabinet.fr", "property_type": "Bureau"}]})
        self.assertEqual(r.status_code, 200, r.get_json())
        par_nom = {l["name"]: l["surface_min"] for l in self.c.get("/api/v1/leads", headers=self.h(t)).get_json()}
        self.assertEqual(par_nom, {"Cabinet A": 120, "Cabinet B": None, "Cabinet C": None})
        jeton = self.c.get("/api/v1/capture-link", headers=self.h(t)).get_json()["token"]
        r = self.c.post(f"/public/capture/{jeton}", json={"name": "Boutique Léa", "email": "lea@boutique.fr",
                                                          "property_type": "Local commercial", "surface_min": 45,
                                                          "consent": True})
        self.assertEqual(r.status_code, 201, r.get_json())
        par_nom = {l["name"]: l["surface_min"] for l in self.c.get("/api/v1/leads", headers=self.h(t)).get_json()}
        self.assertEqual(par_nom["Boutique Léa"], 45)


# ---------------------------------------------------------------- activités autorisées et extraction d'air
class TestActivites(Base):
    PROSPECT = {"property_type": "Local commercial", "budget": 300000, "location": "Senlis",
                "financing_status": "approved", "purchase_urgency": "immediate", "surface_min": None}

    def score(self, activite=None, **bien):
        lead = {**self.PROSPECT, "activite": activite}
        local = {"property_type": "Local commercial", "price": 300000, "size": 80, "title": "Local",
                 "address": "10 rue Nationale 60300 Senlis", **bien}
        return backend._detail_score(lead, local)

    def test_lecture_des_activites(self):
        f = backend._activite
        for brut, attendu in (("restauration", "restauration"), ("Restaurant", "restauration"), ("pizzeria", "restauration"),
                              ("Profession libérale", "services"), ("cabinet médical", "services"), ("Bureaux", "bureau"),
                              ("atelier", "artisanat"), ("Boutique", "commerce"), ("autre", "autre"),
                              ("", None), ("n'importe quoi", None), (None, None), (True, None)):
            self.assertEqual(f(brut), attendu, brut)
        g = backend._activites_liste
        self.assertEqual(g(["commerce", "restauration", "commerce"]), ["commerce", "restauration"])
        self.assertEqual(g("Restaurant, boutique ; bureaux"), ["commerce", "restauration", "bureau"])
        self.assertIsNone(g([]))
        self.assertIsNone(g("n'importe quoi"))
        self.assertIsNone(g(None))
        b = backend._booleen_souple
        for brut, attendu in ((True, True), (False, False), ("oui", True), ("Non", False), ("présente", True), ("absente", False),
                              ("", None), (None, None), ("peut-être", None), (0, False), (1, True)):
            self.assertEqual(b(brut), attendu, brut)

    def test_restauration_exige_une_extraction_d_air(self):
        sans_info = self.score("restauration")
        avec = self.score("restauration", extraction_air=True)
        sans = self.score("restauration", extraction_air=False)
        self.assertIn("Extraction d'air non renseignée : à vérifier pour une cuisine", sans_info[1])
        self.assertIn("Extraction d'air présente : cuisine de restaurant possible", avec[1])
        self.assertIn("Pas d'extraction d'air : cuisine de restaurant impossible", sans[1])
        self.assertEqual(avec[0] - sans_info[0], backend.BONUS_ACTIVITE_CONFIRMEE)
        self.assertLessEqual(sans[0], backend.PLAFOND_ACTIVITE_INCOMPATIBLE)
        self.assertLess(sans[0], backend.PROPOSITION_SCORE_MIN)
        self.assertLess(sans[0], backend.ALERTE_SCORE_MIN)

    def test_activites_autorisees(self):
        base = self.score("commerce")[0]
        ok, raisons = self.score("commerce", activites_autorisees=["commerce", "services"])
        self.assertEqual(ok - base, backend.BONUS_ACTIVITE_CONFIRMEE)
        self.assertIn("Activité autorisée : Commerce de détail", raisons)
        non, raisons = self.score("restauration", activites_autorisees=["commerce", "services"], extraction_air=True)
        self.assertLessEqual(non, backend.PLAFOND_ACTIVITE_INCOMPATIBLE)
        self.assertIn("Activité non autorisée dans ce local : Restauration", raisons)
        auto, raisons = self.score("restauration", activites_autorisees=["restauration"])
        self.assertIn("Restauration autorisée (extraction d'air non renseignée : à vérifier)", raisons)
        self.assertGreater(auto, self.score("restauration")[0])

    def test_sans_activite_rien_ne_change(self):
        # un prospect qui n'a pas dit ce qu'il veut y faire n'est pas pénalisé, même si le bien n'a pas d'extraction
        self.assertEqual(self.score(None, extraction_air=False)[0], self.score(None)[0])
        self.assertEqual(self.score(None, activites_autorisees=["commerce"])[0], self.score(None)[0])

    def test_ne_s_applique_pas_a_un_autre_type_de_bien(self):
        score, raisons = backend._detail_score({**self.PROSPECT, "activite": "restauration"},
                                               {"property_type": "Maison", "price": 300000, "address": "Senlis 60300",
                                                "title": "x", "extraction_air": False})
        self.assertFalse(any("xtraction" in r for r in raisons))
        self.assertLessEqual(score, backend.PLAFOND_TYPE_DIFFERENT)

    def test_le_calcul_des_logements_ignore_l_activite(self):
        lead = {"property_type": "Maison", "budget": 300000, "location": "Senlis", "activite": "restauration"}
        bien = {"property_type": "Maison", "price": 300000, "address": "Senlis 60300", "title": "x", "extraction_air": False}
        a = backend._detail_score(lead, bien)[0]
        b = backend._detail_score({**lead, "activite": None}, bien)[0]
        self.assertEqual(a, b)

    def test_validation_de_l_extraction_ia(self):
        v = backend._valider({"surface_min": "120 m²", "activite": "Restaurant", "type_bien": "bureau"})
        self.assertEqual((v["surface_min"], v["activite"], v["type_bien"]), (120, "restauration", "Bureau"))
        v = backend._valider({"surface_min": "énorme", "activite": "danser"})
        self.assertEqual((v["surface_min"], v["activite"]), (None, None))

    def test_biens_api_creation_modification_et_import(self):
        t = self.jeton("act-1@x.fr")
        r = self.c.post("/api/v1/properties", headers=self.h(t), json={
            "title": "Local avec extraction", "address": "Senlis 60300", "price": 250000, "size": 90,
            "property_type": "Local commercial", "activites_autorisees": ["restauration", "commerce", "n'importe quoi"],
            "extraction_air": "oui"})
        self.assertEqual(r.status_code, 201, r.get_json())
        b = r.get_json()
        self.assertEqual((b["activites_autorisees"], b["extraction_air"]), (["commerce", "restauration"], True))
        i = b["id"]
        # modification partielle : ne touche pas à ce qu'on n'envoie pas
        r = self.c.put(f"/api/v1/properties/{i}", headers=self.h(t), json={"price": 240000})
        self.assertEqual((r.get_json()["activites_autorisees"], r.get_json()["extraction_air"]), (["commerce", "restauration"], True))
        r = self.c.put(f"/api/v1/properties/{i}", headers=self.h(t), json={"extraction_air": False, "activites_autorisees": ["commerce"]})
        self.assertEqual((r.get_json()["activites_autorisees"], r.get_json()["extraction_air"]), (["commerce"], False))
        r = self.c.put(f"/api/v1/properties/{i}", headers=self.h(t), json={"extraction_air": None, "activites_autorisees": []})
        self.assertEqual((r.get_json()["activites_autorisees"], r.get_json()["extraction_air"]), (None, None))
        # import (tableur) : colonnes facultatives, une mise à jour sans la colonne ne les efface pas
        r = self.c.post("/api/v1/properties/import", headers=self.h(t), json={"rows": [
            {"reference": "L-1", "title": "Boutique", "address": "Chantilly 60500", "price": "180000",
             "property_type": "Boutique", "activites_autorisees": "commerce, restaurant", "extraction_air": "Oui"}]})
        self.assertEqual(r.status_code, 200, r.get_json())
        r = self.c.post("/api/v1/properties/import", headers=self.h(t), json={"rows": [
            {"reference": "L-1", "title": "Boutique", "price": "175000"}]})
        biens = {x["reference"]: x for x in self.c.get("/api/v1/properties", headers=self.h(t)).get_json()}
        self.assertEqual((biens["L-1"]["activites_autorisees"], biens["L-1"]["extraction_air"], biens["L-1"]["price"]),
                         (["commerce", "restauration"], True, 175000))

    def test_prospect_activite_creation_modification_import_et_formulaire(self):
        t = self.jeton("act-2@x.fr")
        r = self.c.post("/api/v1/leads", headers=self.h(t), json={"name": "Chez Léa", "property_type": "Local commercial",
                                                                 "activite": "restauration"})
        self.assertEqual(r.get_json()["activite"], "restauration")
        i = r.get_json()["id"]
        self.assertEqual(self.c.get(f"/api/v1/leads/{i}", headers=self.h(t)).get_json()["activite"], "restauration")
        self.c.put(f"/api/v1/leads/{i}", headers=self.h(t), json={"notes": "x"})
        self.assertEqual(self.c.get(f"/api/v1/leads/{i}", headers=self.h(t)).get_json()["activite"], "restauration")
        self.c.put(f"/api/v1/leads/{i}", headers=self.h(t), json={"activite": "commerce"})
        self.assertEqual(self.c.get(f"/api/v1/leads/{i}", headers=self.h(t)).get_json()["activite"], "commerce")
        self.c.put(f"/api/v1/leads/{i}", headers=self.h(t), json={"activite": ""})
        self.assertIsNone(self.c.get(f"/api/v1/leads/{i}", headers=self.h(t)).get_json()["activite"])
        self.c.post("/api/v1/leads/import", headers=self.h(t), json={"rows": [
            {"name": "Pizza Roma", "email": "p@roma.fr", "property_type": "Local commercial", "activite": "Pizzeria"}]})
        jeton = self.c.get("/api/v1/capture-link", headers=self.h(t)).get_json()["token"]
        self.c.post(f"/public/capture/{jeton}", json={"name": "Cabinet Dr X", "email": "dr@x.fr", "consent": True,
                                                      "property_type": "Bureau", "activite": "services"})
        par_nom = {l["name"]: l["activite"] for l in self.c.get("/api/v1/leads", headers=self.h(t)).get_json()}
        self.assertEqual((par_nom["Pizza Roma"], par_nom["Cabinet Dr X"]), ("restauration", "services"))

    def test_correspondance_complete_restaurant(self):
        t = self.jeton("act-3@x.fr")
        self.c.post("/api/v1/leads", headers=self.h(t), json={"name": "Chez Léa", "property_type": "Local commercial",
                                                             "location": "Senlis", "budget": 250000, "activite": "restauration"})
        for titre, extraction in (("Avec extraction", True), ("Sans extraction", False), ("Extraction inconnue", None)):
            self.c.post("/api/v1/properties", headers=self.h(t), json={
                "title": titre, "address": "Senlis 60300", "price": 250000, "size": 80,
                "property_type": "Local commercial", "extraction_air": extraction})
        m = self.c.get("/api/v1/improved-matches", headers=self.h(t)).get_json()[0]["matches"]
        scores = {x["title"]: x["score"] for x in m}
        self.assertGreater(scores["Avec extraction"], scores["Extraction inconnue"])
        self.assertGreater(scores["Extraction inconnue"], scores["Sans extraction"])
        self.assertLessEqual(scores["Sans extraction"], backend.PLAFOND_ACTIVITE_INCOMPATIBLE)


# ---------------------------------------------------------------- modifier un bien
class TestModifierBien(Base):
    URL = "/api/v1/properties/{}"

    def creer(self, tok, **kw):
        r = self.c.post("/api/v1/properties", json={"title": "Maison Senlis", "address": "Senlis 60300", "price": 395000,
                                                    "size": 120, "rooms": 5, "property_type": "Maison",
                                                    "description": "Jardin", **kw}, headers=self.h(tok))
        self.assertEqual(r.status_code, 201, r.get_json())
        return r.get_json()["id"]

    def lire(self, tok, bien_id):
        return next(b for b in self.c.get("/api/v1/properties", headers=self.h(tok)).get_json() if b["id"] == bien_id)

    def modifier(self, tok, bien_id, **kw):
        return self.c.put(self.URL.format(bien_id), json=kw, headers=self.h(tok))

    def test_exige_une_connexion(self):
        self.assertEqual(self.c.put(self.URL.format(1), json={"title": "x"}).status_code, 401)

    def test_modification_partielle_laisse_le_reste_intact(self):
        t = self.jeton("mod-bien-1@x.fr")
        i = self.creer(t)
        r = self.modifier(t, i, price=380000, description="Jardin et garage")
        self.assertEqual(r.status_code, 200, r.get_json())
        b = self.lire(t, i)
        self.assertEqual((b["price"], b["description"]), (380000, "Jardin et garage"))
        self.assertEqual((b["title"], b["address"], b["size"], b["rooms"], b["property_type"]),
                         ("Maison Senlis", "Senlis 60300", 120, 5, "Maison"))
        self.assertEqual(r.get_json()["price"], 380000)

    def test_changer_le_type_et_vider_un_champ(self):
        t = self.jeton("mod-bien-2@x.fr")
        i = self.creer(t)
        r = self.modifier(t, i, property_type="Bureau", rooms=None, size="")
        self.assertEqual(r.status_code, 200)
        b = self.lire(t, i)
        self.assertEqual(b["property_type"], "Bureau")
        self.assertIsNone(b["rooms"])
        self.assertIsNone(b["size"])

    def test_titre_obligatoire_et_rien_a_modifier(self):
        t = self.jeton("mod-bien-3@x.fr")
        i = self.creer(t)
        self.assertEqual(self.modifier(t, i, title="   ").status_code, 400)
        self.assertEqual(self.modifier(t, i, title=None).status_code, 400)
        self.assertEqual(self.c.put(self.URL.format(i), json={}, headers=self.h(t)).status_code, 400)
        self.assertEqual(self.modifier(t, i, inconnu="x").status_code, 400)       # clés ignorées
        self.assertEqual(self.lire(t, i)["title"], "Maison Senlis")

    def test_un_bien_d_une_autre_agence_est_introuvable(self):
        a, b = self.jeton("mod-bien-4a@x.fr"), self.jeton("mod-bien-4b@x.fr")
        i = self.creer(a)
        self.assertEqual(self.modifier(b, i, title="Piraté").status_code, 404)
        self.assertEqual(self.modifier(b, 999999, title="x").status_code, 404)
        self.assertEqual(self.lire(a, i)["title"], "Maison Senlis")
        # user_id / agency dans le corps : ignorés
        r = self.modifier(a, i, title="Renommé", user_id=1)
        self.assertEqual(r.status_code, 200)

    def test_reference_unique_dans_l_agence(self):
        t = self.jeton("mod-bien-5@x.fr")
        i1, i2 = self.creer(t, reference="DP-1"), self.creer(t, reference="DP-2")
        self.assertEqual(self.modifier(t, i2, reference="dp-1").status_code, 409)          # casse ignorée
        self.assertEqual(self.lire(t, i2)["reference"], "DP-2")
        self.assertEqual(self.modifier(t, i1, reference="DP-1", title="Même référence, même bien").status_code, 200)
        self.assertEqual(self.modifier(t, i2, reference="DP-3").status_code, 200)
        self.assertEqual(self.modifier(t, i2, reference="").status_code, 200)              # on peut la retirer
        self.assertIsNone(self.lire(t, i2)["reference"])
        # une autre agence peut réutiliser la même référence
        autre = self.jeton("mod-bien-5b@x.fr")
        j = self.creer(autre, reference="X-1")
        self.assertEqual(self.modifier(autre, j, reference="DP-1").status_code, 200)

    def test_recalcule_les_correspondances(self):
        t = self.jeton("mod-bien-6@x.fr")
        i = self.creer(t)
        with mock.patch.object(backend, "_lancer_en_arriere_plan") as lance:
            self.assertEqual(self.modifier(t, i, price=300000).status_code, 200)
        args = lance.call_args[0]
        self.assertIs(args[0], backend._alertes_matching)
        self.assertEqual(args[2:], (None, [i]))
        with mock.patch.object(backend, "_lancer_en_arriere_plan") as lance:
            self.modifier(t, i, title="")                     # refusé : rien n'est relancé
        lance.assert_not_called()

    def test_valeurs_hors_limites_traitees_comme_vides(self):
        t = self.jeton("mod-bien-7@x.fr")
        i = self.creer(t)
        self.assertEqual(self.modifier(t, i, price=99999999999999).status_code, 200)
        self.assertIsNone(self.lire(t, i)["price"])
        self.assertEqual(self.modifier(t, i, title="x" * 400, description="d" * 6000).status_code, 200)
        b = self.lire(t, i)
        self.assertEqual(len(b["title"]), 255)


class TestLocationScoring(unittest.TestCase):
    """Barème d'un locataire : loyer, secteur, dossier (revenus, garants), échéance, situation, meublé."""
    LOC = {"transaction": "location", "property_type": "Appartement", "budget": 900, "location": "Senlis",
           "revenus": 3000, "garants": 0, "situation_pro": "cdi", "purchase_urgency": "immediate",
           "meuble_souhaite": None, "email": "camille@example.fr", "phone": "06 12 34 56 78"}
    BIEN = {"transaction": "location", "property_type": "Appartement", "price": 850, "title": "T2",
            "address": "5 rue Vieille 60300 Senlis", "meuble": None}

    def score(self, lead=None, bien=None):
        return backend._detail_score({**self.LOC, **(lead or {})}, {**self.BIEN, **(bien or {})})

    def test_lecture_de_la_transaction(self):
        f = backend._transaction
        for brut, attendu in (("location", "location"), ("À louer", "location"), ("Locataire", "location"),
                              ("achat", "vente"), ("Vente", "vente"), ("acheteur", "vente"),
                              ("", None), ("autre chose", None), (None, None), (True, None)):
            self.assertEqual(f(brut), attendu, brut)
        self.assertEqual(f("???", "vente"), "vente")
        s = backend._situation_pro
        for brut, attendu in (("CDI", "cdi"), ("Fonctionnaire", "fonctionnaire"), ("intérim", "cdd"), ("étudiante", "etudiant"),
                              ("auto-entrepreneur", "independant"), ("retraité", "retraite"), ("", None), ("xyz", None)):
            self.assertEqual(s(brut), attendu, brut)

    def test_un_acheteur_ne_voit_pas_une_location_et_inversement(self):
        score, raisons = self.score({"transaction": "vente"})
        self.assertEqual(score, 0)
        self.assertIn("Vente et location ne correspondent pas", raisons)
        self.assertEqual(self.score(bien={"transaction": "vente"})[0], 0)
        # sans information, tout est de la vente : l'existant ne change pas
        self.assertGreater(backend._detail_score({"budget": 300000, "property_type": "Maison", "location": "Senlis"},
                                                 {"price": 300000, "property_type": "Maison", "address": "Senlis"})[0], 50)

    def test_dossier_ideal(self):
        score, raisons = self.score({"garants": 1})
        self.assertGreaterEqual(score, 90)
        self.assertIn("Loyer dans le budget : 850 €/mois pour 900 € maximum", raisons)
        self.assertTrue(any("fois le loyer" in r for r in raisons))

    def test_regle_des_trois_fois_le_loyer(self):
        ok = self.score({"revenus": 2550})[0]          # 3,0 fois 850
        limite = self.score({"revenus": 2200})[0]      # 2,6 fois
        faible = self.score({"revenus": 1700})[0]      # 2 fois
        tres_faible = self.score({"revenus": 1000})[0]
        self.assertGreater(ok, limite)
        self.assertGreater(limite, faible)
        self.assertGreater(faible, tres_faible)
        # le garant compense des revenus insuffisants
        self.assertGreater(self.score({"revenus": 1700, "garants": 1})[0], faible)
        self.assertLess(self.score({"revenus": 1700, "garants": 1})[0], self.score({"revenus": 2550, "garants": 1})[0])

    def test_loyer_au_dessus_du_budget(self):
        dedans = self.score(bien={"price": 900})[0]
        un_peu = self.score(bien={"price": 940})[0]
        trop = self.score(bien={"price": 1200})[0]
        self.assertGreater(dedans, un_peu)
        self.assertGreater(un_peu, trop)
        # un loyer bien en dessous du plafond convient aussi
        self.assertGreaterEqual(self.score(bien={"price": 500})[0], dedans)

    def test_meuble(self):
        sans_avis = self.score()[0]
        ok = self.score({"meuble_souhaite": True}, {"meuble": True})
        non = self.score({"meuble_souhaite": True}, {"meuble": False})
        self.assertGreater(ok[0], sans_avis)
        self.assertLessEqual(non[0], backend.PLAFOND_MEUBLE_DIFFERENT)
        self.assertLess(non[0], backend.ALERTE_SCORE_MIN)
        self.assertGreaterEqual(non[0], 0)
        self.assertIn("Bien non meublé alors que le prospect cherche du meublé", non[1])
        # information manquante d'un côté : pas de pénalité
        self.assertEqual(self.score({"meuble_souhaite": True}, {"meuble": None})[0], sans_avis)

    def test_situation_professionnelle(self):
        cdi = self.score({"situation_pro": "cdi"})[0]
        cdd = self.score({"situation_pro": "cdd"})[0]
        self.assertGreater(cdi, cdd)
        self.assertEqual(self.score({"situation_pro": None})[0], self.score({"situation_pro": "xxx"})[0])

    def test_autre_ville_elimine(self):
        self.assertEqual(self.score(bien={"address": "3 rue de la Paix 75002 Paris"})[0], 0)

    def test_type_voisin_et_type_different(self):
        maison = self.score(bien={"property_type": "Maison"})[0]
        self.assertLess(maison, self.score()[0])
        self.assertGreater(maison, self.score(bien={"property_type": "Terrain"})[0])

    def test_qualite_du_locataire(self):
        q = backend.derive_lead_quality
        self.assertEqual(q({**self.LOC, "garants": 1}), "hot")
        self.assertEqual(q({"transaction": "location"}), "cold")
        self.assertEqual(q({**self.LOC, "revenus": 800, "garants": 0, "situation_pro": "autre",
                            "purchase_urgency": "6plus_months"}), "cold")
        # un dossier moyen et un emménagement lointain restent tièdes
        self.assertEqual(q({**self.LOC, "purchase_urgency": "3-6_months", "situation_pro": "cdd"}), "warm")
        # un acheteur n'est pas jugé sur les revenus
        self.assertEqual(q({"revenus": 9000, "garants": 3, "situation_pro": "cdi"}), "cold")

    def test_local_commercial_en_location(self):
        lead = {"transaction": "location", "property_type": "Local commercial", "budget": 2000, "location": "Senlis",
                "revenus": 7000, "garants": 0, "purchase_urgency": "immediate", "surface_min": 60, "activite": None}
        bien = {"transaction": "location", "property_type": "Local commercial", "price": 1900, "size": 70,
                "address": "Senlis 60300", "title": "Boutique"}
        score, raisons = backend._detail_score(lead, bien)
        self.assertGreater(score, 70)
        self.assertIn("Loyer dans le budget : 1900 €/mois pour 2000 € maximum", raisons)
        self.assertIn("Emménagement immédiat", raisons)
        trop_cher = backend._detail_score(lead, {**bien, "price": 3000})[0]
        self.assertLess(trop_cher, score)
        # une location de local ne se propose pas à un acquéreur de local
        self.assertEqual(backend._detail_score({**lead, "transaction": "vente"}, bien)[0], 0)
        # l'extraction d'air reste exigée pour une cuisine
        r = backend._detail_score({**lead, "activite": "restauration"}, {**bien, "extraction_air": False})
        self.assertLessEqual(r[0], backend.PLAFOND_ACTIVITE_INCOMPATIBLE)


class TestCoordonneesDansLaQualite(unittest.TestCase):
    """Les coordonnées de contact comptent dans la qualité d'un prospect."""
    ACHETEUR = {"financing_status": "approved", "purchase_urgency": "1-3_months", "budget": 300000,
                "location": "Senlis", "property_type": "Maison"}

    def test_points_coordonnees(self):
        f = backend._points_coordonnees
        self.assertEqual(f({"email": "a@b.fr", "phone": "06 12 34 56 78"}, 10), 10)
        self.assertEqual(f({"email": "a@b.fr"}, 10), 5)
        self.assertEqual(f({"phone": "+33 6 12 34 56 78"}, 10), 5)
        self.assertEqual(f({}, 10), 0)
        # une adresse ou un numéro invraisemblables ne rapportent rien
        self.assertEqual(f({"email": "pas-un-mail", "phone": "123"}, 10), 0)
        self.assertEqual(f({"email": None, "phone": None}, 8), 0)
        self.assertEqual(f({"email": "a@b.fr", "phone": "0612345678"}, 8), 8)

    def test_acheteur_sans_coordonnees_perd_de_la_qualite(self):
        q = backend.derive_lead_quality
        complet = {**self.ACHETEUR, "email": "a@b.fr", "phone": "0612345678"}
        self.assertEqual(q(complet), "hot")                     # 36 + 25 + 12 + 8 = 81
        # le même dossier, injoignable ou à moitié joignable, n'est plus chaud
        self.assertEqual(q({**self.ACHETEUR, "email": "a@b.fr"}), "warm")
        self.assertEqual(q(self.ACHETEUR), "warm")
        # l'engagement du prospect peut rattraper : ouvrir son formulaire (+2) puis les annonces (+3)
        self.assertEqual(q({**self.ACHETEUR, "email": "a@b.fr", "engagement": 5}), "hot")

    def test_bareme_total_cent(self):
        # dossier le plus complet sans engagement : 88 ; l'engagement ajoute 12 au plus, jusqu'à 100
        max_dossier = {"financing_status": "approved", "purchase_urgency": "immediate", "budget": 1,
                       "location": "x", "property_type": "Maison", "email": "a@b.fr", "phone": "0612345678"}
        self.assertEqual(backend.points_qualite(max_dossier), 88)
        self.assertEqual(backend.points_qualite({**max_dossier, "engagement": 12}), 100)
        self.assertEqual(backend.points_qualite({**max_dossier, "engagement": 99}), 100)   # plafonné
        locataire = {"transaction": "location", "budget": 900, "revenus": 3000, "garants": 1, "situation_pro": "cdi",
                     "purchase_urgency": "immediate", "location": "x", "property_type": "Appartement",
                     "email": "a@b.fr", "phone": "0612345678"}
        self.assertEqual(backend.points_qualite(locataire), 88)
        self.assertEqual(backend.points_qualite({**locataire, "engagement": 12}), 100)

    def test_locataire_coordonnees(self):
        q = backend.derive_lead_quality
        base = {"transaction": "location", "property_type": "Appartement", "budget": 900, "location": "Senlis",
                "revenus": 2300, "garants": 0, "situation_pro": "cdi", "purchase_urgency": "1-3_months"}
        avec = q({**base, "email": "a@b.fr", "phone": "0612345678"})
        sans = q(base)
        ordre = {"hot": 2, "warm": 1, "cold": 0}
        self.assertGreaterEqual(ordre[avec], ordre[sans])
        self.assertEqual(sans, "warm")


class TestScoreQualiteExpose(Base):
    """Le score /100 affiché est celui qui fixe le niveau, et l'API le renvoie."""

    def test_points_et_niveau_coherents(self):
        for lead in (
            {"financing_status": "approved", "purchase_urgency": "immediate", "budget": 1, "location": "x",
             "property_type": "Maison", "email": "a@b.fr", "phone": "0612345678"},
            {"financing_status": "in_progress", "purchase_urgency": "3-6_months", "email": "a@b.fr"},
            {}, {"transaction": "location", "budget": 900, "revenus": 3000, "email": "a@b.fr", "phone": "0612345678",
                 "situation_pro": "cdi", "purchase_urgency": "immediate", "location": "x", "property_type": "Appartement"},
        ):
            pts = backend.points_qualite(lead)
            self.assertTrue(0 <= pts <= 100)
            attendu = "hot" if pts >= 80 else "warm" if pts >= 45 else "cold"
            self.assertEqual(backend.derive_lead_quality(lead), attendu)
        self.assertEqual(backend.points_qualite({}), 0)
        self.assertEqual(backend.points_qualite({"email": "a@b.fr", "phone": "0612345678"}), 8)

    def test_api_renvoie_quality_score(self):
        t = self.jeton("score-1@x.fr")
        r = self.c.post("/api/v1/leads", json={"name": "Julie Martin", "email": "julie@example.fr",
                        "phone": "06 12 34 56 78", "budget": 300000, "location": "Senlis", "property_type": "Maison",
                        "financing_status": "approved", "purchase_urgency": "1-3_months"}, headers=self.h(t))
        self.assertEqual(r.status_code, 201, r.get_json())
        cree = r.get_json()
        # 36 + 25 + 8 (coordonnées) + 5 + 4 + 3
        self.assertEqual(cree["quality_score"], 81)
        self.assertEqual(cree["lead_quality"], "hot")
        liste = self.c.get("/api/v1/leads", headers=self.h(t)).get_json()
        self.assertEqual(liste[0]["quality_score"], 81)
        detail = self.c.get(f"/api/v1/leads/{cree['id']}", headers=self.h(t)).get_json()
        self.assertEqual((detail["quality_score"], detail["lead_quality"]), (81, "hot"))
        # sans téléphone, le même prospect perd 5 points et n'est plus chaud
        r2 = self.c.put(f"/api/v1/leads/{cree['id']}", json={"budget": 300000, "location": "Senlis",
                        "property_type": "Maison", "financing_status": "approved",
                        "purchase_urgency": "1-3_months", "phone": None}, headers=self.h(t))
        self.assertEqual(r2.status_code, 200, r2.get_json())
        detail = self.c.get(f"/api/v1/leads/{cree['id']}", headers=self.h(t)).get_json()
        self.assertEqual((detail["quality_score"], detail["lead_quality"]), (77, "warm"))
        par_niveau = self.c.get("/api/v1/leads/quality/warm", headers=self.h(t)).get_json()
        self.assertEqual([x["id"] for x in par_niveau], [cree["id"]])
        self.assertEqual(par_niveau[0]["quality_score"], 77)


class TestActiviteProspects(Base):
    """Ouverture des liens par le prospect : formulaire, annonces, flux de l'agent."""

    NAVIGATEUR = {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1"}

    def setUp(self):
        super().setUp()
        self.envoyes = []

        def faux(dest, sujet, texte, html, **kw):
            self.envoyes.append({"to": dest, "sujet": sujet, "texte": texte, "html": html})
            return True

        for p in (mock.patch.object(backend, "_envoyer_email", side_effect=faux),
                  mock.patch.object(backend, "_lancer_en_arriere_plan", side_effect=lambda f, *a: f(*a)),
                  mock.patch.dict(os.environ, {"BREVO_API_KEY": "cle-de-test", "MAIL_FROM": "contact@zelyro.fr",
                                               "FRONTEND_URL": "https://app.zelyro.fr"})):
            p.start()
            self.addCleanup(p.stop)

    def preparer(self, email):
        t = self.jeton(email)
        l = self.c.post("/api/v1/leads", json={"name": "Camille Martin", "email": "camille@exemple.fr",
                                               "budget": 300000, "location": "Senlis"}, headers=self.h(t)).get_json()
        b = self.c.post("/api/v1/properties", json={"title": "Maison Senlis", "address": "5 rue Vieille 60300 Senlis",
                                                    "property_type": "Maison", "price": 290000, "rooms": 4, "size": 95},
                        headers=self.h(t)).get_json()
        return t, l, b

    def lien(self, t, l):
        r = self.c.post(f"/api/v1/leads/{l['id']}/completion-link", headers=self.h(t))
        self.assertEqual(r.status_code, 200, r.get_json())
        return r.get_json()

    def evenements(self, t):
        return self.c.get("/api/v1/dashboard", headers=self.h(t)).get_json()["activity"]

    # lien à copier
    def test_lien_a_copier_stable_et_message_pret(self):
        t, l, _ = self.preparer("act-1@x.fr")
        a = self.lien(t, l)
        self.assertTrue(a["url"].startswith("https://app.zelyro.fr/completer.html?c="))
        self.assertIn(a["url"], a["message"])
        self.assertTrue(a["message"].startswith("Bonjour Camille,"))
        self.assertEqual(self.lien(t, l)["url"], a["url"])

    def test_lien_a_copier_nom_provisoire_et_acces(self):
        t, _, _ = self.preparer("act-2@x.fr")
        anonyme = self.c.post("/api/v1/leads", json={"name": "Contact LeBonCoin"}, headers=self.h(t)).get_json()
        self.assertTrue(self.lien(t, anonyme)["message"].startswith("Bonjour, merci"))
        autre = self.jeton("act-2b@x.fr")
        self.assertEqual(self.c.post(f"/api/v1/leads/{anonyme['id']}/completion-link",
                                     headers=self.h(autre)).status_code, 404)
        self.assertEqual(self.c.post(f"/api/v1/leads/{anonyme['id']}/completion-link").status_code, 401)
        with mock.patch.dict(os.environ, {"FRONTEND_URL": ""}):
            self.assertEqual(self.c.post(f"/api/v1/leads/{anonyme['id']}/completion-link",
                                         headers=self.h(t)).status_code, 503)

    # ouverture du formulaire
    def test_ouverture_du_formulaire_notee_une_fois(self):
        t, l, _ = self.preparer("act-3@x.fr")
        jeton = self.lien(t, l)["url"].split("c=")[1]
        self.assertEqual(self.evenements(t), [])
        for _ in range(3):
            r = self.c.get(f"/public/completer/{jeton}", headers=self.NAVIGATEUR)
            self.assertEqual(r.status_code, 200)
        ev = self.evenements(t)
        self.assertEqual(len(ev), 1)
        self.assertEqual((ev[0]["kind"], ev[0]["name"], ev[0]["lead_id"]), ("formulaire_ouvert", "Camille Martin", l["id"]))
        self.assertEqual(ev[0]["label"], "a ouvert son formulaire")

    def test_robots_ne_comptent_pas(self):
        t, l, _ = self.preparer("act-4@x.fr")
        jeton = self.lien(t, l)["url"].split("c=")[1]
        for ua in ("WhatsApp/2.23.20 A", "facebookexternalhit/1.1", "Slackbot-LinkExpanding 1.0",
                   "curl/8.4.0", "python-requests/2.31", "Googlebot/2.1", ""):
            r = self.c.get(f"/public/completer/{jeton}", headers={"User-Agent": ua})
            self.assertEqual(r.status_code, 200, ua)
        self.assertEqual(self.evenements(t), [])

    def test_formulaire_rempli_note_a_chaque_envoi(self):
        t, l, _ = self.preparer("act-5@x.fr")
        jeton = self.lien(t, l)["url"].split("c=")[1]
        for _ in range(2):
            r = self.c.post(f"/public/completer/{jeton}", json={"consent": True, "budget": 310000, "location": "Senlis"},
                            headers=self.NAVIGATEUR)
            self.assertEqual(r.status_code, 200, r.get_json())
        types = [e["kind"] for e in self.evenements(t)]
        self.assertEqual(types, ["formulaire_rempli", "formulaire_rempli"])
        # refus de consentement : rien n'est noté
        r = self.c.post(f"/public/completer/{jeton}", json={"budget": 1}, headers=self.NAVIGATEUR)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(len(self.evenements(t)), 2)

    def test_jeton_inconnu(self):
        self.assertEqual(self.c.get("/public/completer/" + "a" * 30, headers=self.NAVIGATEUR).status_code, 404)
        self.assertEqual(self.c.get("/public/annonces/" + "a" * 30, headers=self.NAVIGATEUR).status_code, 404)
        self.assertEqual(self.c.get("/public/annonces/court", headers=self.NAVIGATEUR).status_code, 404)

    # annonces
    def jeton_annonces(self, t, l, b, **kw):
        corps = {"subject": "Sélection de biens", "body": "Bonjour, voici une sélection de biens pour vous.",
                 "property_ids": [b["id"]], **kw}
        r = self.c.post(f"/api/v1/leads/{l['id']}/send-mail", json=corps, headers=self.h(t))
        self.assertEqual(r.status_code, 200, r.get_json())
        return r.get_json(), self.envoyes[-1]

    def test_mail_avec_lien_de_suivi_et_ouverture(self):
        t, l, b = self.preparer("act-6@x.fr")
        rep, mail = self.jeton_annonces(t, l, b)
        self.assertTrue(rep["tracked_link"])
        m = re.search(r"https://app\.zelyro\.fr/annonces\.html\?t=([A-Za-z0-9_-]+)", mail["texte"])
        self.assertIsNotNone(m, mail["texte"])
        self.assertIn(m.group(0), mail["html"])
        self.assertIn("Voir les annonces en ligne", mail["html"])
        r = self.c.get(f"/public/annonces/{m.group(1)}", headers=self.NAVIGATEUR)
        self.assertEqual(r.status_code, 200, r.get_json())
        d = r.get_json()
        self.assertEqual((d["prenom"], len(d["biens"]), d["biens"][0]["title"]), ("Camille", 1, "Maison Senlis"))
        self.assertNotIn("user_id", d["biens"][0])
        ev = self.evenements(t)
        self.assertEqual([e["kind"] for e in ev], ["annonces_ouvertes"])
        self.assertIn("1 bien", ev[0]["label"])
        self.assertNotIn("1 biens", ev[0]["label"])
        # une deuxième ouverture rapprochée ne double pas l'événement
        self.c.get(f"/public/annonces/{m.group(1)}", headers=self.NAVIGATEUR)
        self.assertEqual(len(self.evenements(t)), 1)
        # un robot n'ajoute rien
        self.c.get(f"/public/annonces/{m.group(1)}", headers={"User-Agent": "WhatsApp/2.0"})
        self.assertEqual(len(self.evenements(t)), 1)

    def test_mail_sans_lien_de_suivi(self):
        t, l, b = self.preparer("act-7@x.fr")
        rep, mail = self.jeton_annonces(t, l, b, tracked_link=False)
        self.assertFalse(rep["tracked_link"])
        self.assertNotIn("annonces.html", mail["texte"])
        self.assertNotIn("annonces.html", mail["html"])

    def test_mail_sans_adresse_du_site_part_sans_lien(self):
        t, l, b = self.preparer("act-8@x.fr")
        with mock.patch.dict(os.environ, {"FRONTEND_URL": ""}):
            rep, mail = self.jeton_annonces(t, l, b)
        self.assertFalse(rep["tracked_link"])
        self.assertNotIn("annonces.html", mail["texte"])

    def test_lien_annonces_expire_et_bien_supprime(self):
        t, l, b = self.preparer("act-9@x.fr")
        _, mail = self.jeton_annonces(t, l, b)
        jeton = re.search(r"annonces\.html\?t=([A-Za-z0-9_-]+)", mail["texte"]).group(1)
        # bien supprimé depuis l'envoi : page vide, aucun événement
        conn = backend.get_db_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM properties WHERE id = %s", (b["id"],))
        conn.commit(); conn.close()
        r = self.c.get(f"/public/annonces/{jeton}", headers=self.NAVIGATEUR)
        self.assertEqual((r.status_code, r.get_json()["biens"]), (200, []))
        self.assertEqual(self.evenements(t), [])
        # lien trop ancien
        conn = backend.get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE lead_mails SET sent_at = sent_at - interval '100 days' WHERE suivi_token = %s", (jeton,))
        conn.commit(); conn.close()
        self.assertEqual(self.c.get(f"/public/annonces/{jeton}", headers=self.NAVIGATEUR).status_code, 410)

    # fil de la fiche et isolement
    def test_historique_de_la_fiche_et_isolement(self):
        t, l, _ = self.preparer("act-10@x.fr")
        jeton = self.lien(t, l)["url"].split("c=")[1]
        self.c.get(f"/public/completer/{jeton}", headers=self.NAVIGATEUR)
        notes = self.c.get(f"/api/v1/leads/{l['id']}/notes", headers=self.h(t)).get_json()
        act = [n for n in notes if n["kind"] == "activite"]
        self.assertEqual(len(act), 1)
        self.assertEqual(act[0]["body"], "Le prospect a ouvert son formulaire")
        self.assertTrue(str(act[0]["id"]).startswith("e"))
        autre = self.jeton("act-10b@x.fr")
        self.assertEqual(self.evenements(autre), [])

    # ---- demande de visite
    def jeton_page_annonces(self, t, l, b):
        _, mail = self.jeton_annonces(t, l, b)
        return re.search(r"annonces\.html\?t=([A-Za-z0-9_-]+)", mail["texte"]).group(1)

    def test_annonces_donnent_un_rang_et_pas_l_identifiant(self):
        t, l, b = self.preparer("int-1@x.fr")
        jeton = self.jeton_page_annonces(t, l, b)
        d = self.c.get(f"/public/annonces/{jeton}", headers=self.NAVIGATEUR).get_json()
        self.assertEqual((d["biens"][0]["ref"], d["biens"][0]["interesse"]), (0, False))
        self.assertNotIn("id", d["biens"][0])

    def test_demande_de_visite(self):
        t, l, b = self.preparer("int-2@x.fr")
        jeton = self.jeton_page_annonces(t, l, b)
        avant = len(self.envoyes)
        r = self.c.post(f"/public/annonces/{jeton}/interet", json={"ref": 0}, headers=self.NAVIGATEUR)
        self.assertEqual(r.status_code, 200, r.get_json())
        ev = self.evenements(t)
        self.assertEqual((ev[0]["kind"], ev[0]["label"]), ("interet_bien", "souhaite visiter « Maison Senlis »"))
        # l'agent reçoit un e-mail
        alertes = [m for m in self.envoyes[avant:] if "souhaite visiter" in m["sujet"]]
        self.assertEqual(len(alertes), 1)
        self.assertIn("Camille Martin", alertes[0]["sujet"])
        self.assertIn(f"/leads-profile.html?id={l['id']}", alertes[0]["texte"])
        # deuxième clic : ni nouvel événement ni nouvel e-mail
        self.c.post(f"/public/annonces/{jeton}/interet", json={"ref": 0}, headers=self.NAVIGATEUR)
        self.assertEqual(len([e for e in self.evenements(t) if e["kind"] == "interet_bien"]), 1)
        self.assertEqual(len([m for m in self.envoyes[avant:] if "souhaite visiter" in m["sujet"]]), 1)
        # la page se souvient du choix
        d = self.c.get(f"/public/annonces/{jeton}", headers=self.NAVIGATEUR).get_json()
        self.assertTrue(d["biens"][0]["interesse"])

    def test_demande_de_visite_refus(self):
        t, l, b = self.preparer("int-3@x.fr")
        jeton = self.jeton_page_annonces(t, l, b)
        for corps in ({}, {"ref": -1}, {"ref": 5}, {"ref": "0"}, {"ref": True}, {"ref": 1.5}):
            r = self.c.post(f"/public/annonces/{jeton}/interet", json=corps, headers=self.NAVIGATEUR)
            self.assertEqual(r.status_code, 400, corps)
        self.assertEqual(self.c.post("/public/annonces/" + "a" * 30 + "/interet", json={"ref": 0}).status_code, 404)
        self.assertEqual(self.c.post("/public/annonces/court/interet", json={"ref": 0}).status_code, 404)
        self.assertEqual([e for e in self.evenements(t) if e["kind"] == "interet_bien"], [])
        conn = backend.get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE lead_mails SET sent_at = sent_at - interval '100 days' WHERE suivi_token = %s", (jeton,))
        conn.commit(); conn.close()
        self.assertEqual(self.c.post(f"/public/annonces/{jeton}/interet", json={"ref": 0}).status_code, 410)

    def test_demande_de_visite_sans_alerte_si_coupee(self):
        t, l, b = self.preparer("int-4@x.fr")
        jeton = self.jeton_page_annonces(t, l, b)
        self.assertEqual(self.c.put("/auth/preferences", json={"alerts_enabled": False}, headers=self.h(t)).status_code, 200)
        avant = len(self.envoyes)
        self.c.post(f"/public/annonces/{jeton}/interet", json={"ref": 0}, headers=self.NAVIGATEUR)
        self.assertEqual([e["kind"] for e in self.evenements(t)], ["interet_bien"])   # l'événement est noté, l'e-mail non
        self.assertEqual([m for m in self.envoyes[avant:] if "souhaite visiter" in m["sujet"]], [])

    # ---- engagement dans le score
    def test_engagement_fait_monter_le_score(self):
        t, l, b = self.preparer("eng-1@x.fr")
        jeton_form = self.lien(t, l)["url"].split("c=")[1]
        base = self.c.get(f"/api/v1/leads/{l['id']}", headers=self.h(t)).get_json()
        self.assertEqual((base["engagement"], base["engagement_lignes"]), (0, []))
        self.c.get(f"/public/completer/{jeton_form}", headers=self.NAVIGATEUR)          # +2
        jeton = self.jeton_page_annonces(t, l, b)
        self.c.get(f"/public/annonces/{jeton}", headers=self.NAVIGATEUR)                 # +3
        self.c.post(f"/public/annonces/{jeton}/interet", json={"ref": 0}, headers=self.NAVIGATEUR)   # +6 : 11 au total (plafond 12)
        apres = self.c.get(f"/api/v1/leads/{l['id']}", headers=self.h(t)).get_json()
        self.assertEqual(apres["engagement"], 11)
        self.assertEqual(sorted(x[0] for x in apres["engagement_lignes"]), [2, 3, 6])
        self.assertEqual(apres["quality_score"] - base["quality_score"], 11)
        # la liste et le tableau de bord utilisent le même score
        liste = {x["id"]: x for x in self.c.get("/api/v1/leads", headers=self.h(t)).get_json()}
        self.assertEqual(liste[l["id"]]["quality_score"], apres["quality_score"])

    # ---- export CSV
    def test_export_csv(self):
        t, l, _ = self.preparer("csv-1@x.fr")
        self.c.post("/api/v1/leads", json={"name": "=HYPERLINK(\"http://x\")", "phone": "+33 6 12 34 56 78",
                                           "location": "@Senlis"}, headers=self.h(t))
        self.c.post(f"/api/v1/leads/{l['id']}/notes", json={"body": "note privée très confidentielle"}, headers=self.h(t))
        r = self.c.get("/api/v1/leads/export", headers=self.h(t))
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.headers["Content-Type"].startswith("text/csv"))
        self.assertIn("attachment; filename=\"prospects-zelyro-", r.headers["Content-Disposition"])
        corps = r.get_data(as_text=True)
        self.assertTrue(corps.startswith("\ufeffNom;E-mail;Téléphone;"))
        lignes = corps.strip().split("\r\n")
        self.assertEqual(len(lignes), 3)
        self.assertIn("Camille Martin;camille@exemple.fr;", lignes[1])
        self.assertIn("'=HYPERLINK", lignes[2])               # formule neutralisée
        self.assertIn(";0033 6 12 34 56 78;", lignes[2])       # « + » remplacé
        self.assertIn(";'@Senlis;", lignes[2])
        self.assertNotIn("confidentielle", corps)               # les notes privées ne sortent pas

    def test_export_csv_isole_par_agence_et_protege(self):
        t, _, _ = self.preparer("csv-2@x.fr")
        autre = self.jeton("csv-2b@x.fr")
        corps = self.c.get("/api/v1/leads/export", headers=self.h(autre)).get_data(as_text=True)
        self.assertEqual(len(corps.strip().split("\r\n")), 1)    # seulement les en-têtes
        self.assertEqual(self.c.get("/api/v1/leads/export").status_code, 401)

    def test_suppression_du_prospect_efface_son_activite(self):
        t, l, _ = self.preparer("act-11@x.fr")
        jeton = self.lien(t, l)["url"].split("c=")[1]
        self.c.get(f"/public/completer/{jeton}", headers=self.NAVIGATEUR)
        self.assertEqual(self.c.delete(f"/api/v1/leads/{l['id']}", headers=self.h(t)).status_code, 200)
        conn = backend.get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM lead_events WHERE lead_id = %s", (l["id"],))
        self.assertEqual(cur.fetchone()[0], 0)
        conn.close()


class TestLocationApi(Base):
    def lead(self, tok, **kw):
        r = self.c.post("/api/v1/leads", json={"name": "Camille Martin", **kw}, headers=self.h(tok))
        self.assertEqual(r.status_code, 201, r.get_json())
        return r.get_json()

    def bien(self, tok, **kw):
        r = self.c.post("/api/v1/properties", json={"title": "T2 Senlis", "address": "5 rue Vieille 60300 Senlis",
                                                    "property_type": "Appartement", **kw}, headers=self.h(tok))
        self.assertEqual(r.status_code, 201, r.get_json())
        return r.get_json()

    def test_valeurs_par_defaut_et_creation(self):
        t = self.jeton("loc-1@x.fr")
        v = self.lead(t, name="Acheteur")
        self.assertEqual((v["transaction"], v["revenus"], v["garants"], v["situation_pro"], v["meuble_souhaite"]),
                         ("vente", None, None, None, None))
        l = self.lead(t, transaction="location", budget=900, revenus="3 000", garants=1, situation_pro="CDI",
                      meuble_souhaite="oui")
        self.assertEqual((l["transaction"], l["budget"], l["garants"], l["situation_pro"], l["meuble_souhaite"]),
                         ("location", 900, 1, "cdi", True))
        self.assertEqual(l["revenus"], 3000)
        b = self.bien(t)
        self.assertEqual((b["transaction"], b["meuble"]), ("vente", None))
        b2 = self.bien(t, title="T3", transaction="Location", meuble=True, price=850)
        self.assertEqual((b2["transaction"], b2["meuble"], b2["price"]), ("location", True, 850))
        # valeurs fantaisistes : ramenées à la vente / inconnu
        b3 = self.bien(t, title="T4", transaction="n'importe quoi", meuble="peut-être")
        self.assertEqual((b3["transaction"], b3["meuble"]), ("vente", None))

    def test_liste_et_detail_exposent_les_champs(self):
        t = self.jeton("loc-2@x.fr")
        l = self.lead(t, transaction="location", budget=900, revenus=3000, garants=2, situation_pro="cdi")
        liste = self.c.get("/api/v1/leads", headers=self.h(t)).get_json()
        x = next(i for i in liste if i["id"] == l["id"])
        self.assertEqual((x["transaction"], x["revenus"], x["garants"], x["situation_pro"]), ("location", 3000, 2, "cdi"))
        d = self.c.get(f"/api/v1/leads/{l['id']}", headers=self.h(t)).get_json()
        self.assertEqual((d["transaction"], d["revenus"], d["garants"], d["situation_pro"]), ("location", 3000, 2, "cdi"))
        self.assertIn(x["lead_quality"], ("hot", "warm", "cold"))

    def test_modifier_un_prospect_vers_la_location(self):
        t = self.jeton("loc-3@x.fr")
        l = self.lead(t, budget=250000)
        r = self.c.put(f"/api/v1/leads/{l['id']}", json={"budget": 900, "transaction": "location", "revenus": 2800,
                                                        "garants": 1, "situation_pro": "cdd", "meuble_souhaite": False},
                       headers=self.h(t))
        self.assertEqual(r.status_code, 200, r.get_json())
        d = self.c.get(f"/api/v1/leads/{l['id']}", headers=self.h(t)).get_json()
        self.assertEqual((d["transaction"], d["revenus"], d["garants"], d["situation_pro"], d["meuble_souhaite"]),
                         ("location", 2800, 1, "cdd", False))
        # un envoi sans ces clés ne les touche pas (anciennes pages)
        self.c.put(f"/api/v1/leads/{l['id']}", json={"budget": 950}, headers=self.h(t))
        d = self.c.get(f"/api/v1/leads/{l['id']}", headers=self.h(t)).get_json()
        self.assertEqual((d["transaction"], d["revenus"], d["garants"], d["budget"]), ("location", 2800, 1, 950))

    def test_modifier_un_bien_vente_location(self):
        t = self.jeton("loc-4@x.fr")
        b = self.bien(t, price=300000)
        r = self.c.put(f"/api/v1/properties/{b['id']}", json={"transaction": "location", "price": 900, "meuble": True},
                       headers=self.h(t))
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual((r.get_json()["transaction"], r.get_json()["price"], r.get_json()["meuble"]), ("location", 900, True))
        r = self.c.put(f"/api/v1/properties/{b['id']}", json={"price": 880}, headers=self.h(t))
        self.assertEqual(r.get_json()["transaction"], "location")

    def test_matching_separe_vente_et_location(self):
        t = self.jeton("loc-5@x.fr")
        locataire = self.lead(t, name="Locataire", transaction="location", budget=900, location="Senlis",
                              property_type="Appartement", revenus=3000, situation_pro="cdi", purchase_urgency="immediate",
                              email="locataire@exemple.fr", phone="0612345678")
        acheteur = self.lead(t, name="Acheteur", transaction="vente", budget=300000, location="Senlis",
                             property_type="Appartement", financing_status="approved", purchase_urgency="immediate")
        a_louer = self.bien(t, title="À louer", transaction="location", price=850)
        a_vendre = self.bien(t, title="À vendre", transaction="vente", price=300000)
        res = {r["name"]: r for r in self.c.get("/api/v1/improved-matches", headers=self.h(t)).get_json()}
        self.assertEqual([m["property_id"] for m in res["Locataire"]["matches"]], [a_louer["id"]])
        self.assertEqual([m["property_id"] for m in res["Acheteur"]["matches"]], [a_vendre["id"]])
        self.assertEqual(res["Locataire"]["matches"][0]["transaction"], "location")
        self.assertEqual(res["Locataire"]["transaction"], "location")
        self.assertEqual(res["Locataire"]["lead_quality"], "hot")
        self.assertTrue(any("fois le loyer" in r for r in res["Locataire"]["matches"][0]["reasons"]))

    def test_import_de_prospects_en_location(self):
        t = self.jeton("loc-6@x.fr")
        r = self.c.post("/api/v1/leads/import", headers=self.h(t), json={"rows": [
            {"name": "Loc Un", "email": "un@x.fr", "budget": "850 €", "transaction": "Location", "revenus": "2 700 €",
             "garants": "1", "situation_pro": "CDI", "meuble_souhaite": "oui"},
            {"name": "Loc Deux", "email": "deux@x.fr", "budget": 700},
            {"name": "Acheteur", "email": "tr@x.fr", "budget": 200000, "transaction": "achat"}]})
        self.assertEqual(r.get_json()["imported"], 3, r.get_json())
        liste = {l["name"]: l for l in self.c.get("/api/v1/leads", headers=self.h(t)).get_json()}
        self.assertEqual((liste["Loc Un"]["transaction"], liste["Loc Un"]["revenus"], liste["Loc Un"]["garants"],
                          liste["Loc Un"]["situation_pro"], liste["Loc Un"]["meuble_souhaite"]), ("location", 2700, 1, "cdi", True))
        self.assertEqual(liste["Loc Deux"]["transaction"], "vente")
        self.assertEqual(liste["Acheteur"]["transaction"], "vente")
        # choix fait sur la page : tout le fichier est de la location
        r = self.c.post("/api/v1/leads/import", headers=self.h(t), json={"default_transaction": "location", "rows": [
            {"name": "Loc Trois", "email": "trois@x.fr"},
            {"name": "Vendeur", "email": "v@x.fr", "transaction": "vente"}]})
        self.assertEqual(r.get_json()["imported"], 2)
        liste = {l["name"]: l for l in self.c.get("/api/v1/leads", headers=self.h(t)).get_json()}
        self.assertEqual((liste["Loc Trois"]["transaction"], liste["Vendeur"]["transaction"]), ("location", "vente"))

    def test_import_de_biens_en_location(self):
        t = self.jeton("loc-7@x.fr")
        r = self.c.post("/api/v1/properties/import", headers=self.h(t), json={"default_transaction": "location", "rows": [
            {"reference": "L1", "title": "Studio", "address": "Senlis", "price": "620 €", "property_type": "Studio", "meuble": "oui"},
            {"reference": "V1", "title": "Maison", "address": "Senlis", "price": 300000, "transaction": "Vente"}]})
        self.assertEqual(r.get_json()["imported"], 2, r.get_json())
        biens = {b["reference"]: b for b in self.c.get("/api/v1/properties", headers=self.h(t)).get_json()}
        self.assertEqual((biens["L1"]["transaction"], biens["L1"]["meuble"], biens["L1"]["price"]), ("location", True, 620))
        self.assertEqual(biens["V1"]["transaction"], "vente")
        # réimport sans colonne ni choix : la transaction déjà enregistrée est conservée
        r = self.c.post("/api/v1/properties/import", headers=self.h(t), json={"rows": [
            {"reference": "L1", "title": "Studio", "price": 640}]})
        self.assertEqual(r.get_json()["updated"], 1)
        biens = {b["reference"]: b for b in self.c.get("/api/v1/properties", headers=self.h(t)).get_json()}
        self.assertEqual((biens["L1"]["transaction"], biens["L1"]["price"]), ("location", 640))

    def test_formulaire_public_et_completion(self):
        t = self.jeton("loc-8@x.fr")
        jeton = self.c.get("/api/v1/capture-link", headers=self.h(t)).get_json()["token"]
        r = self.c.post(f"/public/capture/{jeton}", json={"name": "Visiteur", "email": "v@x.fr", "consent": True,
                                                         "transaction": "location", "budget": 800, "revenus": 2600,
                                                         "garants": 1, "situation_pro": "etudiant", "meuble_souhaite": True})
        self.assertEqual(r.status_code, 201, r.get_json())
        v = next(l for l in self.c.get("/api/v1/leads", headers=self.h(t)).get_json() if l["name"] == "Visiteur")
        self.assertEqual((v["transaction"], v["revenus"], v["garants"], v["situation_pro"], v["meuble_souhaite"]),
                         ("location", 2600, 1, "etudiant", True))
        # sans le champ : vente
        self.c.post(f"/public/capture/{jeton}", json={"name": "Autre", "email": "a@x.fr", "consent": True})
        a = next(l for l in self.c.get("/api/v1/leads", headers=self.h(t)).get_json() if l["name"] == "Autre")
        self.assertEqual(a["transaction"], "vente")

    def test_extraction_ia_lit_le_dossier_locataire(self):
        brut = {"transaction": "location", "budget": 850, "revenus": "2 900 €", "garants": 1, "profession": "CDI",
                "meuble": "oui"}
        champs = backend._valider(brut)
        self.assertEqual((champs["transaction"], champs["revenus"], champs["situation_pro"], champs["meuble"], champs["garants"]),
                         ("location", 2900, "cdi", True, 1))
        vide = backend._valider({})
        self.assertEqual((vide["revenus"], vide["situation_pro"], vide["meuble"]), (None, None, None))
        self.assertIn("revenus", backend.CONSIGNE)
        self.assertIn("meuble", backend.CONSIGNE_PORTAIL)

    def test_page_de_completion_preselectionne_et_enregistre_la_location(self):
        t = self.jeton("loc-11@x.fr")
        l = self.lead(t, name="Contact Annonce", transaction="location")
        jeton = "tok-" + "a" * 30
        conn = backend.get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE leads SET completion_token = %s WHERE id = %s", (jeton, l["id"]))
        conn.commit()
        conn.close()
        info = self.c.get(f"/public/completer/{jeton}").get_json()
        self.assertEqual(info["transaction"], "location")
        r = self.c.post(f"/public/completer/{jeton}", json={"consent": True, "budget": 750, "revenus": 2400, "garants": 1,
                                                          "situation_pro": "cdi", "meuble_souhaite": True,
                                                          "transaction": "location"})
        self.assertEqual(r.status_code, 200, r.get_json())
        d = self.c.get(f"/api/v1/leads/{l['id']}", headers=self.h(t)).get_json()
        self.assertEqual((d["transaction"], d["budget"], d["revenus"], d["garants"], d["situation_pro"], d["meuble_souhaite"]),
                         ("location", 750, 2400, 1, "cdi", True))
        # une complétion qui ne parle pas de location ne change pas le type de recherche
        self.c.post(f"/public/completer/{jeton}", json={"consent": True, "location": "Senlis"})
        self.assertEqual(self.c.get(f"/api/v1/leads/{l['id']}", headers=self.h(t)).get_json()["transaction"], "location")

    def test_alerte_mail_pour_un_nouveau_locataire(self):
        t = self.jeton("loc-12@x.fr")
        self.lead(t, name="Locataire Alerte", transaction="location", budget=800, location="Senlis",
                  property_type="Appartement", revenus=2800, situation_pro="cdi", purchase_urgency="immediate")
        self.bien(t, title="T2 à louer", transaction="location", price=750, meuble=None)
        self.bien(t, title="Maison à vendre", transaction="vente", price=300000)
        envoyes = []
        with mock.patch.object(backend, "_envoi_configure", return_value=True), \
                mock.patch.object(backend, "_envoyer_email", side_effect=lambda *a, **k: envoyes.append(a) or True):
            uid = pyjwt.decode(t, SECRET, algorithms=["HS256"])["id"]
            backend._alertes_matching(uid, None, None, None)
            ids = [l["id"] for l in self.c.get("/api/v1/leads", headers=self.h(t)).get_json()]
            backend._alertes_matching(uid, ids, None, None)
        textes = " ".join(str(a[2]) for a in envoyes)
        self.assertIn("T2 à louer", textes)
        self.assertNotIn("Maison à vendre", textes)

    def test_isolation_entre_agences(self):
        a, b = self.jeton("loc-9a@x.fr"), self.jeton("loc-9b@x.fr")
        l = self.lead(a, transaction="location")
        r = self.c.put(f"/api/v1/leads/{l['id']}", json={"transaction": "vente", "revenus": 1}, headers=self.h(b))
        self.assertEqual(r.status_code, 404)
        d = self.c.get(f"/api/v1/leads/{l['id']}", headers=self.h(a)).get_json()
        self.assertEqual(d["transaction"], "location")

    def test_tableau_de_bord_compte_la_location(self):
        t = self.jeton("loc-10@x.fr")
        self.lead(t, transaction="location")
        self.lead(t, name="Autre")
        self.bien(t, transaction="location", price=700)
        self.bien(t, title="Vente", price=100000)
        d = self.c.get("/api/v1/dashboard", headers=self.h(t)).get_json()
        self.assertEqual((d["total_leads"], d["leads_location"], d["total_properties"], d["properties_location"]), (2, 1, 2, 1))


class TestGarantsLocauxPro(Base):
    """Un local commercial ou un bureau se loue à un professionnel : aucun garant personnel."""

    def lead(self, tok, **kw):
        r = self.c.post("/api/v1/leads", json={"name": "Camille Martin", **kw}, headers=self.h(tok))
        self.assertEqual(r.status_code, 201, r.get_json())
        return r.get_json()

    def test_points_solvabilite_sans_garants(self):
        lead = {"revenus": 2000, "garants": 2}
        avec, _ = backend._points_solvabilite(lead, 1000)
        sans, phrase = backend._points_solvabilite(lead, 1000, avec_garants=False)
        self.assertGreater(avec, sans)
        self.assertNotIn("garant", phrase)
        self.assertEqual(backend._points_solvabilite({"revenus": 2000}, 1000), (sans, phrase))
        # sans revenus : un garant ne remplace pas un dossier pour un professionnel
        self.assertEqual(backend._points_solvabilite({"garants": 1}, 1000, avec_garants=False), (8, None))

    def test_score_location_pro_ignore_les_garants(self):
        local = {"property_type": "Local commercial", "price": 1000, "size": 60, "transaction": "location",
                 "address": "5 rue Vieille 60300 Senlis"}
        base = {"transaction": "location", "property_type": "Local commercial", "budget": 1100, "revenus": 2500,
                "location": "Senlis", "surface_min": 50}
        s1, r1 = backend._detail_score({**base, "garants": 2}, local)
        s0, r0 = backend._detail_score({**base, "garants": 0}, local)
        self.assertEqual(s1, s0)
        self.assertFalse(any("garant" in x.lower() for x in r1))

    def test_score_location_logement_compte_toujours_les_garants(self):
        bien = {"property_type": "Appartement", "price": 1000, "size": 40, "transaction": "location",
                "address": "5 rue Vieille 60300 Senlis"}
        base = {"transaction": "location", "property_type": "Appartement", "budget": 1100, "revenus": 2300,
                "location": "Senlis"}
        s1, r1 = backend._detail_score({**base, "garants": 1}, bien)
        s0, _ = backend._detail_score({**base, "garants": 0}, bien)
        self.assertGreater(s1, s0)
        self.assertTrue(any("garant" in x.lower() for x in r1))

    def test_qualite_pro_ignore_les_garants(self):
        base = {"transaction": "location", "budget": 1000, "revenus": 2500, "situation_pro": "cdi",
                "purchase_urgency": "1-3_months", "location": "Senlis",
                "email": "a@example.fr", "phone": "0612345678"}
        self.assertEqual(backend.derive_lead_quality({**base, "property_type": "Appartement", "garants": 1}), "hot")
        self.assertEqual(backend.derive_lead_quality({**base, "property_type": "Local commercial", "garants": 1}), "warm")
        self.assertEqual(backend.derive_lead_quality({**base, "property_type": "Bureau", "garants": 1}), "warm")

    def test_garants_pour(self):
        self.assertEqual(backend._garants_pour("Appartement", 2), 2)
        self.assertEqual(backend._garants_pour("Maison", "2", souple=True), 2)
        self.assertIsNone(backend._garants_pour("Local commercial", 2))
        self.assertIsNone(backend._garants_pour("Bureau", "2", souple=True))
        self.assertIsNone(backend._garants_pour(None, None))

    def test_creation_pro_ne_garde_aucun_garant(self):
        t = self.jeton("gar-1@x.fr")
        pro = self.lead(t, transaction="location", property_type="Local commercial", budget=1200, revenus=3000, garants=2)
        self.assertIsNone(pro["garants"])
        self.assertEqual(pro["revenus"], 3000)
        logement = self.lead(t, name="Locataire", transaction="location", property_type="Appartement", budget=900, garants=2)
        self.assertEqual(logement["garants"], 2)

    def test_modification_vers_un_local_efface_les_garants(self):
        t = self.jeton("gar-2@x.fr")
        l = self.lead(t, transaction="location", property_type="Appartement", budget=900, garants=2)
        r = self.c.put(f"/api/v1/leads/{l['id']}", json={"property_type": "Bureau", "garants": 2, "budget": 1500},
                       headers=self.h(t))
        self.assertEqual(r.status_code, 200, r.get_json())
        d = self.c.get(f"/api/v1/leads/{l['id']}", headers=self.h(t)).get_json()
        self.assertIsNone(d["garants"])
        # retour à un logement : on peut de nouveau renseigner un garant
        self.c.put(f"/api/v1/leads/{l['id']}", json={"property_type": "Appartement", "garants": 1, "budget": 900},
                   headers=self.h(t))
        d = self.c.get(f"/api/v1/leads/{l['id']}", headers=self.h(t)).get_json()
        self.assertEqual(d["garants"], 1)

    def test_import_ignore_les_garants_des_locaux(self):
        t = self.jeton("gar-3@x.fr")
        r = self.c.post("/api/v1/leads/import", headers=self.h(t), json={"rows": [
            {"name": "Boulangerie Dupont", "property_type": "Local commercial", "transaction": "location",
             "budget": 1500, "garants": 2},
            {"name": "Locataire Lambda", "property_type": "Appartement", "transaction": "location",
             "budget": 800, "garants": 1}]})
        self.assertIn(r.status_code, (200, 201), r.get_json())
        liste = {x["name"]: x for x in self.c.get("/api/v1/leads", headers=self.h(t)).get_json()}
        self.assertIsNone(liste["Boulangerie Dupont"]["garants"])
        self.assertEqual(liste["Locataire Lambda"]["garants"], 1)


class TestPiecesJointes(Base):
    """Annonces en PDF jointes aux e-mails de proposition."""

    PDF = b"%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n"

    @staticmethod
    def pj(nom, octets):
        import base64 as b64
        return {"name": nom, "content": b64.b64encode(octets).decode("ascii")}

    def setUp(self):
        super().setUp()
        self.envoyes = []

        def faux(dest, sujet, texte, html, **kw):
            self.envoyes.append({"to": dest, "sujet": sujet, "kw": kw})
            return True

        for p in (mock.patch.object(backend, "_envoyer_email", side_effect=faux),
                  mock.patch.dict(os.environ, {"BREVO_API_KEY": "cle-de-test", "MAIL_FROM": "contact@zelyro.fr"})):
            p.start()
            self.addCleanup(p.stop)

    def preparer(self, email):
        t = self.jeton(email)
        l = self.c.post("/api/v1/leads", json={"name": "Camille Martin", "email": "camille@exemple.fr", "budget": 300000,
                                               "location": "Senlis"}, headers=self.h(t)).get_json()
        b = self.c.post("/api/v1/properties", json={"title": "Maison Senlis", "address": "5 rue Vieille 60300 Senlis",
                                                    "property_type": "Maison", "price": 290000}, headers=self.h(t)).get_json()
        return t, l, b

    def envoyer(self, t, l, b, **kw):
        corps = {"subject": "Sélection de biens", "body": "Bonjour, voici une sélection de biens pour vous.",
                 "property_ids": [b["id"]], **kw}
        return self.c.post(f"/api/v1/leads/{l['id']}/send-mail", json=corps, headers=self.h(t))

    # lecteur
    def test_lecteur_accepte_un_pdf(self):
        pieces, err = backend._lire_pieces_jointes([self.pj("Annonce maison.pdf", self.PDF)])
        self.assertIsNone(err)
        self.assertEqual(pieces, [("Annonce maison.pdf", self.PDF)])

    def test_lecteur_vide(self):
        self.assertEqual(backend._lire_pieces_jointes(None), ([], None))
        self.assertEqual(backend._lire_pieces_jointes([]), ([], None))

    def test_lecteur_refuse_un_faux_pdf(self):
        _, err = backend._lire_pieces_jointes([self.pj("virus.pdf", b"MZ\x90\x00 un executable")])
        self.assertIn("n'est pas un fichier PDF", err)

    def test_lecteur_refuse_le_base64_invalide(self):
        _, err = backend._lire_pieces_jointes([{"name": "a.pdf", "content": "pas du base64 !!"}])
        self.assertIn("n'a pas pu être lu", err)

    def test_lecteur_refuse_les_formes_inattendues(self):
        for brut in ("texte", {"a": 1}, [1], [{"name": "a.pdf"}], [{"content": "AAAA"}], [{"name": 3, "content": "AAAA"}]):
            self.assertIsNotNone(backend._lire_pieces_jointes(brut)[1], brut)

    def test_lecteur_limites(self):
        gros = self.PDF + b"0" * backend.PJ_MAX_OCTETS
        self.assertIn("dépasse", backend._lire_pieces_jointes([self.pj("gros.pdf", gros)])[1])
        trop = [self.pj(f"a{i}.pdf", self.PDF) for i in range(backend.PJ_MAX_FICHIERS + 1)]
        self.assertIn("au maximum", backend._lire_pieces_jointes(trop)[1])
        moyen = self.PDF + b"0" * (backend.PJ_MAX_OCTETS - 100)
        quatre = [self.pj(f"m{i}.pdf", moyen) for i in range(4)]
        self.assertIn("au total", backend._lire_pieces_jointes(quatre)[1])

    def test_lecteur_nettoie_les_noms(self):
        pieces, err = backend._lire_pieces_jointes([
            self.pj("../../etc/passwd.pdf", self.PDF),
            self.pj("C:\\Users\\Moi\\Annonce \"1\"\r\nBcc: x@y.fr.PDF", self.PDF),
            self.pj("annonce.pdf", self.PDF), self.pj("annonce.pdf", self.PDF), self.pj("", self.PDF)])
        self.assertIsNone(err)
        noms = [n for n, _ in pieces]
        self.assertEqual(len(set(n.lower() for n in noms)), len(noms))
        for n in noms:
            self.assertTrue(n.endswith(".pdf"))
            self.assertFalse(any(c in n for c in '/\\"\r\n:'), n)
        self.assertEqual(noms[0], "passwd.pdf")
        self.assertIn("annonce.pdf", noms)
        self.assertIn("annonce-2.pdf", noms)

    # route
    def test_envoi_sans_pdf_inchange(self):
        t, l, b = self.preparer("pj-1@x.fr")
        r = self.envoyer(t, l, b)
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual(r.get_json()["attachments"], 0)
        self.assertFalse(self.envoyes[0]["kw"].get("pieces_jointes"))

    def test_envoi_avec_pdf(self):
        t, l, b = self.preparer("pj-2@x.fr")
        r = self.envoyer(t, l, b, attachments=[self.pj("Annonce maison.pdf", self.PDF), self.pj("Plan.pdf", self.PDF)])
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual(r.get_json()["attachments"], 2)
        self.assertEqual(self.envoyes[0]["kw"]["pieces_jointes"],
                         [("Annonce maison.pdf", self.PDF), ("Plan.pdf", self.PDF)])
        notes = self.c.get(f"/api/v1/leads/{l['id']}/notes", headers=self.h(t))
        if notes.status_code == 200:
            self.assertIn("Annonce maison.pdf", str(notes.get_json()))

    def test_envoi_accepte_un_pdf_de_plus_de_128_ko(self):
        t, l, b = self.preparer("pj-3@x.fr")
        pdf = self.PDF + b"0" * (1024 * 1024)       # 1 Mo : le plafond général de 128 Ko ne doit pas le bloquer
        r = self.envoyer(t, l, b, attachments=[self.pj("Gros.pdf", pdf)])
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True)[:200])
        self.assertEqual(len(self.envoyes[0]["kw"]["pieces_jointes"][0][1]), len(pdf))

    def test_plafond_general_inchange_ailleurs(self):
        t = self.jeton("pj-4@x.fr")
        r = self.c.post("/api/v1/leads", json={"name": "X", "notes": "a" * 300_000}, headers=self.h(t))
        self.assertEqual(r.status_code, 413)

    def test_envoi_refuse_un_faux_pdf_sans_envoyer(self):
        t, l, b = self.preparer("pj-5@x.fr")
        r = self.envoyer(t, l, b, attachments=[self.pj("a.pdf", b"pas un pdf")])
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.envoyes, [])
        # le prospect n'est pas verrouillé par l'échec : un envoi correct passe ensuite
        self.assertEqual(self.envoyer(t, l, b).status_code, 200)

    def test_requete_au_dela_du_plafond_refusee(self):
        t, l, b = self.preparer("pj-6@x.fr")
        enorme = "A" * (backend.PJ_REQUETE_MAX + 1000)
        r = self.envoyer(t, l, b, attachments=[{"name": "a.pdf", "content": enorme}])
        self.assertEqual(r.status_code, 413)
        self.assertEqual(self.envoyes, [])

    def test_envoi_brevo_recoit_les_pieces_en_base64(self):
        import base64 as b64
        capture = {}

        class Rep:
            status_code = 201
            text = ""

        def faux_post(url, headers=None, json=None, timeout=None):
            capture["json"], capture["timeout"] = json, timeout
            return Rep()

        # appel direct de la vraie fonction (le test de classe l'a remplacée par un faux)
        reel = self._vraie_envoyer_email
        with mock.patch.object(backend.requests, "post", side_effect=faux_post):
            ok = reel("a@b.fr", "Sujet", "texte", "<p>texte</p>", pieces_jointes=[("Annonce.pdf", self.PDF)])
        self.assertTrue(ok)
        self.assertEqual(capture["json"]["attachment"], [{"name": "Annonce.pdf",
                                                          "content": b64.b64encode(self.PDF).decode("ascii")}])
        self.assertGreaterEqual(capture["timeout"], 30)
        with mock.patch.object(backend.requests, "post", side_effect=faux_post):
            reel("a@b.fr", "Sujet", "texte", "<p>texte</p>")
        self.assertNotIn("attachment", capture["json"])

    _vraie_envoyer_email = staticmethod(backend._envoyer_email)


class TestEtape2(Base):
    """Responsables des prospects, e-mail du matin, prospects à réveiller, potentiel de commission."""

    CHAUD = {"name": "Camille Martin", "email": "camille@exemple.fr", "phone": "06 12 34 56 78", "budget": 300000,
             "location": "Senlis", "property_type": "Maison", "financing_status": "approved",
             "purchase_urgency": "immediate"}

    def setUp(self):
        super().setUp()
        self.envoyes = []

        def faux(dest, sujet, texte, html, **kw):
            self.envoyes.append({"to": dest, "sujet": sujet, "texte": texte, "html": html})
            return True

        for p in (mock.patch.object(backend, "_envoyer_email", side_effect=faux),
                  mock.patch.object(backend, "_lancer_en_arriere_plan", side_effect=lambda f, *a: f(*a)),
                  mock.patch.dict(os.environ, {"BREVO_API_KEY": "cle-de-test", "MAIL_FROM": "contact@zelyro.fr",
                                               "FRONTEND_URL": "https://app.zelyro.fr", "CRON_SECRET": "secret-cron"})):
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

    def agence(self, email, prenom="Directrice"):
        """Un directeur, un collaborateur actif ; renvoie (jeton directeur, id directeur, jeton collab, id collab)."""
        td = self.jeton(email)
        self.c.put("/auth/profile", json={}, headers=self.h(td))
        id_d = self.sql("SELECT id FROM users WHERE email = %s", (email,))[0][0]
        self.sql("UPDATE users SET first_name = %s WHERE id = %s", (prenom, id_d))
        mail_e = "collab-" + email
        self.sql("""INSERT INTO users (email, password_hash, first_name, role, agency_owner_id)
                    VALUES (%s, %s, 'Julien', 'employe', %s)""",
                 (mail_e, backend.generate_password_hash(PW, method='pbkdf2:sha256'), id_d))
        id_e = self.sql("SELECT id FROM users WHERE email = %s", (mail_e,))[0][0]
        te = self.c.post("/auth/login", json={"email": mail_e, "password": PW}).get_json()["token"]
        return td, id_d, te, id_e

    def lead(self, t, **kw):
        r = self.c.post("/api/v1/leads", json={**self.CHAUD, **kw}, headers=self.h(t))
        self.assertEqual(r.status_code, 201, r.get_json())
        return r.get_json()

    def detail(self, t, l):
        return self.c.get(f"/api/v1/leads/{l['id']}", headers=self.h(t)).get_json()

    def assigner(self, t, l, cible):
        return self.c.put(f"/api/v1/leads/{l['id']}/assign", json={"user_id": cible}, headers=self.h(t))

    # ---- responsable
    def test_createur_collaborateur_devient_responsable(self):
        td, id_d, te, id_e = self.agence("e2-1@x.fr")
        a = self.lead(te)
        self.assertEqual(a["assigned_to"], id_e)
        b = self.lead(td, name="Paul Durand")
        self.assertIsNone(b["assigned_to"])
        liste = {x["name"]: x["assigned_to"] for x in self.c.get("/api/v1/leads", headers=self.h(td)).get_json()}
        self.assertEqual(liste, {"Camille Martin": id_e, "Paul Durand": None})

    def test_liste_des_membres(self):
        td, id_d, te, id_e = self.agence("e2-2@x.fr")
        for t, moi in ((td, id_d), (te, id_e)):
            m = self.c.get("/api/v1/team/members", headers=self.h(t)).get_json()
            self.assertEqual([(x["id"], x["name"], x["role"]) for x in m],
                             [(id_d, "Directrice", "admin"), (id_e, "Julien", "employe")])
            self.assertEqual([x["id"] for x in m if x["is_me"]], [moi])
        autre = self.jeton("e2-2b@x.fr")
        self.assertEqual(len(self.c.get("/api/v1/team/members", headers=self.h(autre)).get_json()), 1)
        self.assertEqual(self.c.get("/api/v1/team/members").status_code, 401)

    def test_attribution_historique_et_alerte(self):
        td, id_d, te, id_e = self.agence("e2-3@x.fr")
        l = self.lead(td)
        r = self.assigner(td, l, id_e)
        self.assertEqual((r.status_code, r.get_json()), (200, {"assigned_to": id_e, "name": "Julien"}))
        self.assertEqual(self.detail(td, l)["assigned_to"], id_e)
        self.assertEqual(self.detail(te, l)["assigned_to"], id_e)
        notes = self.c.get(f"/api/v1/leads/{l['id']}/notes", headers=self.h(td)).get_json()
        self.assertIn(("attrib", "Responsable : Julien"), [(n["kind"], n["body"]) for n in notes])
        self.assertEqual([m["to"] for m in self.envoyes], ["collab-e2-3@x.fr"])
        self.assertIn("vous a été confié", self.envoyes[0]["texte"])
        self.assertIn(f"leads-profile.html?id={l['id']}", self.envoyes[0]["texte"])
        # même responsable : rien de nouveau (ni note, ni e-mail)
        self.assigner(td, l, id_e)
        self.assertEqual(len(self.envoyes), 1)
        self.assertEqual(len([n for n in self.c.get(f"/api/v1/leads/{l['id']}/notes", headers=self.h(td)).get_json()
                              if n["kind"] == "attrib"]), 1)
        # se l'attribuer à soi-même ne prévient personne ; retirer le responsable
        self.assigner(td, l, id_d)
        self.assertEqual(len(self.envoyes), 1)
        r = self.assigner(te, l, None)
        self.assertEqual(r.get_json(), {"assigned_to": None, "name": None})
        self.assertIsNone(self.detail(td, l)["assigned_to"])

    def test_attribution_refus(self):
        td, id_d, te, id_e = self.agence("e2-4@x.fr")
        autre = self.jeton("e2-4b@x.fr")
        id_autre = self.sql("SELECT id FROM users WHERE email = 'e2-4b@x.fr'")[0][0]
        l = self.lead(td)
        self.assertEqual(self.assigner(td, l, id_autre).status_code, 400)      # autre agence
        self.assertEqual(self.assigner(td, l, 999999).status_code, 400)
        for bad in ("1", True, 1.5, [1]):
            self.assertEqual(self.assigner(td, l, bad).status_code, 400, bad)
        self.assertEqual(self.c.put(f"/api/v1/leads/{l['id']}/assign", json={}, headers=self.h(td)).status_code, 400)
        self.assertEqual(self.assigner(autre, l, id_autre).status_code, 404)    # le prospect d'une autre agence
        self.assertEqual(self.assigner(td, {"id": 999999}, id_d).status_code, 404)
        self.assertEqual(self.c.put(f"/api/v1/leads/{l['id']}/assign", json={"user_id": id_d}).status_code, 401)
        self.assertIsNone(self.detail(td, l)["assigned_to"])
        self.assertEqual(self.envoyes, [])

    def test_collaborateur_retire_libere_ses_prospects(self):
        td, id_d, te, id_e = self.agence("e2-5@x.fr")
        l = self.lead(te)
        self.assertEqual(self.assigner(td, l, id_e).status_code, 200)
        self.assertEqual(self.c.delete(f"/api/v1/team/{id_e}", headers=self.h(td)).status_code, 200)
        self.assertIsNone(self.detail(td, l)["assigned_to"])
        self.assertEqual(self.assigner(td, l, id_e).status_code, 400)           # compte désactivé
        self.assertEqual([m["id"] for m in self.c.get("/api/v1/team/members", headers=self.h(td)).get_json()], [id_d])

    def test_export_csv_contient_le_responsable(self):
        td, id_d, te, id_e = self.agence("e2-6@x.fr")
        l = self.lead(te)
        self.lead(td, name="Paul Durand")
        corps = self.c.get("/api/v1/leads/export", headers=self.h(td)).get_data(as_text=True)
        lignes = [x.split(";") for x in corps.lstrip("﻿").strip().split("\r\n")]
        i = lignes[0].index("Responsable")
        self.assertEqual({x[0]: x[i] for x in lignes[1:]}, {"Camille Martin": "Julien", "Paul Durand": ""})

    def test_demande_de_visite_previent_aussi_le_responsable(self):
        td, id_d, te, id_e = self.agence("e2-7@x.fr")
        self.c.post("/api/v1/properties", json={"title": "Maison Senlis", "address": "5 rue Vieille 60300 Senlis",
                    "property_type": "Maison", "price": 290000, "rooms": 4, "size": 95}, headers=self.h(td))
        b = self.c.get("/api/v1/properties", headers=self.h(td)).get_json()[0]
        l = self.lead(td)
        self.assigner(td, l, id_e)
        self.envoyes.clear()
        self.c.post(f"/api/v1/leads/{l['id']}/send-mail", json={"subject": "Sélection", "body": "Bonjour, voici des biens.",
                    "property_ids": [b["id"]]}, headers=self.h(td))
        mail = self.envoyes[-1]
        jeton = re.search(r"annonces\.html\?t=([A-Za-z0-9_-]+)", mail["texte"]).group(1)
        self.envoyes.clear()
        nav = {"User-Agent": "Mozilla/5.0 (iPhone) Safari/604.1"}
        r = self.c.post(f"/public/annonces/{jeton}/interet", json={"ref": 0}, headers=nav)
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual(sorted(m["to"] for m in self.envoyes), sorted(["e2-7@x.fr", "collab-e2-7@x.fr"]))

    # ---- e-mail du matin
    def isoler(self, *ids):
        """La base est partagée entre tests : on marque les autres comptes comme déjà servis aujourd'hui."""
        self.sql("UPDATE users SET digest_sent_on = %s WHERE NOT (id = ANY(%s))", (backend._aujourdhui(), list(ids)))

    def declencher(self, cle="secret-cron"):
        return self.c.post("/internal/digest/send", headers={"X-Cron-Key": cle} if cle is not None else {})

    def test_digest_protege_par_la_cle(self):
        self.jeton("e2-8@x.fr")
        for cle in (None, "", "mauvaise"):
            self.assertEqual(self.declencher(cle).status_code, 404, cle)
        with mock.patch.dict(os.environ, {"CRON_SECRET": ""}):
            self.assertEqual(self.declencher("").status_code, 404)
        with mock.patch.dict(os.environ, {"BREVO_API_KEY": ""}):
            self.assertEqual(self.declencher().status_code, 503)
        self.assertEqual(self.envoyes, [])

    def test_digest_contenu_et_une_seule_fois_par_jour(self):
        td, id_d, te, id_e = self.agence("e2-9@x.fr")
        self.isoler(id_d, id_e)
        l = self.lead(td)
        self.sql("UPDATE leads SET created_at = NOW() - interval '50 hours' WHERE id = %s", (l["id"],))
        self.c.post(f"/api/v1/leads/{l['id']}/reminders", json={"due_date": backend._aujourdhui().isoformat(),
                    "label": "Rappeler pour la visite"}, headers=self.h(td))
        r = self.declencher()
        self.assertEqual((r.status_code, r.get_json()["envoyes"]), (200, 2))        # directrice + collaborateur (non attribué)
        mail = [m for m in self.envoyes if m["to"] == "e2-9@x.fr"][0]
        self.assertEqual(mail["sujet"], "Zelyro — 1 prospect à suivre ce matin")
        for attendu in ("Bonjour Directrice,", "Prospects chauds à appeler", "Camille Martin — 88/100 — 06 12 34 56 78 · Senlis",
                        "Relances à faire", "Rappeler pour la visite (Camille Martin)",
                        "Sans suite depuis plus de 24 h", "reçu il y a 2 j — sans responsable",
                        "https://app.zelyro.fr/dashboard.html", "Décochez « E-mail du matin »"):
            self.assertIn(attendu, mail["texte"])
        self.assertIn("<ul", mail["html"])
        self.envoyes.clear()
        self.assertEqual(self.declencher().get_json()["envoyes"], 0)                # déjà fait aujourd'hui
        self.assertEqual(self.envoyes, [])
        self.sql("UPDATE users SET digest_sent_on = %s WHERE id = ANY(%s)", (backend._aujourdhui() - timedelta(days=1), [id_d, id_e]))
        self.assertEqual(self.declencher().get_json()["envoyes"], 2)                # le lendemain, ça repart

    def test_digest_rien_a_signaler_et_desactive(self):
        td, id_d, te, id_e = self.agence("e2-10@x.fr")
        self.isoler(id_d, id_e)
        self.assertEqual(self.declencher().get_json()["envoyes"], 0)
        self.assertEqual(self.envoyes, [])
        # pas marqué comme envoyé : un prospect chaud arrivé plus tard déclenche bien l'e-mail
        self.assertIsNone(self.sql("SELECT digest_sent_on FROM users WHERE id = %s", (id_d,))[0][0])
        self.lead(td)
        self.assertEqual(self.c.put("/auth/preferences", json={"digest_enabled": False}, headers=self.h(td)).get_json(),
                         {"digest_enabled": False})
        self.assertEqual(self.declencher().get_json()["envoyes"], 1)                # seul le collaborateur
        self.assertEqual([m["to"] for m in self.envoyes], ["collab-e2-10@x.fr"])

    def test_digest_portee_du_collaborateur(self):
        td, id_d, te, id_e = self.agence("e2-11@x.fr")
        self.isoler(id_d, id_e)
        a = self.lead(td, name="Pour Julien")
        b = self.lead(td, name="Pour la directrice", phone="0611111111")
        c = self.lead(td, name="Sans responsable", phone="0622222222")
        self.assigner(td, a, id_e)
        self.assigner(td, b, id_d)
        self.envoyes.clear()
        self.declencher()
        collab = [m for m in self.envoyes if m["to"] == "collab-e2-11@x.fr"][0]["texte"]
        directeur = [m for m in self.envoyes if m["to"] == "e2-11@x.fr"][0]["texte"]
        self.assertIn("Pour Julien", collab); self.assertIn("Sans responsable", collab)
        self.assertNotIn("Pour la directrice", collab)
        for nom in ("Pour Julien", "Pour la directrice", "Sans responsable"):
            self.assertIn(nom, directeur)

    def test_digest_activite_du_prospect(self):
        t = self.jeton("e2-12@x.fr")
        self.isoler(self.sql("SELECT id FROM users WHERE email = 'e2-12@x.fr'")[0][0])
        l = self.lead(t, name="Zoe", email=None, phone=None, financing_status="unknown", purchase_urgency="unknown")
        self.sql("INSERT INTO lead_events (lead_id, user_id, kind) SELECT id, user_id, 'formulaire_ouvert' FROM leads WHERE id = %s", (l["id"],))
        self.sql("INSERT INTO lead_events (lead_id, user_id, kind, detail) SELECT id, user_id, 'interet_bien', 'Maison Senlis' FROM leads WHERE id = %s", (l["id"],))
        self.declencher()
        texte = self.envoyes[0]["texte"]
        self.assertIn("Ce que vos prospects ont fait depuis hier", texte)
        self.assertIn("Zoe souhaite visiter « Maison Senlis »", texte)
        self.assertIn("Zoe a ouvert son formulaire", texte)

    def test_digest_apercu_a_la_demande(self):
        t = self.jeton("e2-13@x.fr")
        r = self.c.post("/api/v1/digest/preview", headers=self.h(t))
        self.assertEqual((r.status_code, r.get_json()["sent"]), (200, False))
        self.assertEqual(self.envoyes, [])
        self.lead(t)
        r = self.c.post("/api/v1/digest/preview", headers=self.h(t))
        self.assertEqual((r.status_code, r.get_json()["sent"]), (200, True))
        self.assertEqual([m["to"] for m in self.envoyes], ["e2-13@x.fr"])
        self.assertEqual(self.c.post("/api/v1/digest/preview").status_code, 401)
        with mock.patch.dict(os.environ, {"BREVO_API_KEY": ""}):
            self.assertEqual(self.c.post("/api/v1/digest/preview", headers=self.h(t)).status_code, 503)

    def test_preferences_digest_et_profil(self):
        td, id_d, te, id_e = self.agence("e2-14@x.fr")
        self.assertTrue(self.c.get("/auth/profile", headers=self.h(td)).get_json()["digest_enabled"])
        self.c.put("/auth/preferences", json={"digest_enabled": False}, headers=self.h(te))
        self.assertFalse(self.c.get("/auth/profile", headers=self.h(te)).get_json()["digest_enabled"])
        self.assertTrue(self.c.get("/auth/profile", headers=self.h(td)).get_json()["digest_enabled"])   # réglage personnel
        self.assertEqual(self.c.put("/auth/preferences", json={"digest_enabled": "non"}, headers=self.h(td)).status_code, 400)
        self.assertEqual(self.c.put("/auth/preferences", json={}, headers=self.h(td)).status_code, 400)
        self.assertEqual(self.c.put("/auth/preferences", json={"alerts_enabled": False}, headers=self.h(td)).get_json(),
                         {"alerts_enabled": False})

    def test_digest_agence_desactivee_ignoree(self):
        td, id_d, te, id_e = self.agence("e2-15@x.fr")
        self.isoler(id_d, id_e)
        self.lead(td)
        self.sql("UPDATE users SET is_active = FALSE WHERE id = %s", (id_d,))
        self.assertEqual(self.declencher().get_json()["envoyes"], 0)
        self.assertEqual(self.envoyes, [])

    # ---- prospects à réveiller
    def bien(self, t, **kw):
        corps = {"title": "Maison Senlis", "address": "5 rue Vieille 60300 Senlis", "property_type": "Maison",
                 "price": 290000, "rooms": 4, "size": 95, **kw}
        r = self.c.post("/api/v1/properties", json=corps, headers=self.h(t))
        self.assertEqual(r.status_code, 201, r.get_json())
        return r.get_json()

    def test_dormants(self):
        t = self.jeton("e2-16@x.fr")
        self.bien(t)
        vieux = self.lead(t)
        recent = self.lead(t, name="Recent", email="recent@exemple.fr")
        clos = self.lead(t, name="Signé", email="signe@exemple.fr")
        incomplet = self.lead(t, name="Sans mail", email=None)
        self.c.put(f"/api/v1/leads/{clos['id']}/status", json={"status": "signe"}, headers=self.h(t))
        for x in (vieux, clos, incomplet):
            self.sql("UPDATE leads SET created_at = NOW() - interval '45 days', status_changed_at = NULL WHERE id = %s", (x["id"],))
        self.sql("DELETE FROM lead_notes WHERE lead_id IN (%s, %s)", (clos["id"], vieux["id"]))
        r = self.c.get("/api/v1/dormants", headers=self.h(t))
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertEqual((d["days"], d["total"]), (30, 1))
        e = d["dormants"][0]
        self.assertEqual((e["lead"]["name"], e["days_inactive"], e["lead_quality"], e["quality_score"]),
                         ("Camille Martin", 45, "hot", 88))
        self.assertEqual(e["biens"][0]["title"], "Maison Senlis")
        self.assertIn("score", e["biens"][0])
        # une note, un e-mail ou une action du prospect le sortent des dormants
        self.c.post(f"/api/v1/leads/{vieux['id']}/notes", json={"body": "Rappelé, répondeur"}, headers=self.h(t))
        self.assertEqual(self.c.get("/api/v1/dormants", headers=self.h(t)).get_json()["total"], 0)
        self.assertEqual(self.c.get("/api/v1/dormants?days=7", headers=self.h(t)).get_json()["total"], 0)
        self.assertEqual(self.c.get("/api/v1/dormants?days=1", headers=self.h(t)).get_json()["days"], 7)
        self.assertEqual(self.c.get("/api/v1/dormants?days=9999", headers=self.h(t)).get_json()["days"], 365)

    def test_dormants_sans_bien_ou_deja_propose_et_isolation(self):
        t = self.jeton("e2-17@x.fr")
        l = self.lead(t)
        self.sql("UPDATE leads SET created_at = NOW() - interval '60 days' WHERE id = %s", (l["id"],))
        self.assertEqual(self.c.get("/api/v1/dormants", headers=self.h(t)).get_json()["total"], 0)   # aucun bien
        b = self.bien(t)
        self.assertEqual(self.c.get("/api/v1/dormants", headers=self.h(t)).get_json()["total"], 1)
        autre = self.jeton("e2-17b@x.fr")
        self.assertEqual(self.c.get("/api/v1/dormants", headers=self.h(autre)).get_json()["total"], 0)
        self.assertEqual(self.c.get("/api/v1/dormants").status_code, 401)
        # bien déjà envoyé ce prospect : plus rien à lui proposer (et l'envoi le sort des dormants)
        self.sql("""INSERT INTO lead_mails (lead_id, user_id, subject, body, property_ids, sent_at)
                    SELECT id, user_id, 'x', 'y', ARRAY[%s], NOW() - interval '40 days' FROM leads WHERE id = %s""",
                 (b["id"], l["id"]))
        self.assertEqual(self.c.get("/api/v1/dormants", headers=self.h(t)).get_json()["total"], 0)

    # ---- potentiel de commission
    def test_commission(self):
        td, id_d, te, id_e = self.agence("e2-18@x.fr")
        self.lead(td)                                                                    # chaud 300 000
        self.lead(td, name="Tiède", email="t@exemple.fr", financing_status="in_progress",
                  purchase_urgency="3-6_months", budget=200000)                          # 22+14+8+12 = 56
        self.lead(td, name="Froid", email=None, phone=None, financing_status="unknown", purchase_urgency="unknown")
        self.lead(td, name="Locataire", transaction="location", budget=900, revenus=3000, garants=1, situation_pro="cdi")
        com = self.c.get("/api/v1/dashboard", headers=self.h(td)).get_json()["commission"]
        self.assertEqual(com["rate"], 4.0)
        self.assertEqual((com["hot"]["count"], com["hot"]["budget"], com["hot"]["commission"]), (1, 300000, 12000))
        self.assertEqual((com["warm"]["count"], com["warm"]["budget"], com["warm"]["commission"]), (1, 200000, 8000))
        self.assertEqual(com["total"], 20000)
        r = self.c.put("/api/v1/commission-rate", json={"rate": 2.5}, headers=self.h(td))
        self.assertEqual((r.status_code, r.get_json()), (200, {"rate": 2.5}))
        com = self.c.get("/api/v1/dashboard", headers=self.h(td)).get_json()["commission"]
        self.assertEqual((com["rate"], com["total"]), (2.5, 12500))
        # les collaborateurs ne voient pas le potentiel et ne règlent pas le taux
        self.assertIsNone(self.c.get("/api/v1/dashboard", headers=self.h(te)).get_json()["commission"])
        self.assertEqual(self.c.put("/api/v1/commission-rate", json={"rate": 9}, headers=self.h(te)).status_code, 403)
        for bad in (0, -1, 16, "4", None, True, [4]):
            self.assertEqual(self.c.put("/api/v1/commission-rate", json={"rate": bad}, headers=self.h(td)).status_code, 400, bad)
        self.assertEqual(self.c.put("/api/v1/commission-rate", json={"rate": 4}).status_code, 401)

    def test_commission_ignore_les_prospects_clos(self):
        t = self.jeton("e2-19@x.fr")
        l = self.lead(t)
        self.c.put(f"/api/v1/leads/{l['id']}/status", json={"status": "perdu"}, headers=self.h(t))
        com = self.c.get("/api/v1/dashboard", headers=self.h(t)).get_json()["commission"]
        self.assertEqual((com["hot"]["count"], com["total"]), (0, 0))

    # ---- sans suite
    def test_dashboard_prospects_sans_suite(self):
        td, id_d, te, id_e = self.agence("e2-20@x.fr")
        a = self.lead(td, name="Ancien")
        b = self.lead(td, name="Récent")
        self.assigner(td, a, id_e)
        self.sql("UPDATE leads SET created_at = NOW() - interval '30 hours' WHERE id = %s", (a["id"],))
        d = self.c.get("/api/v1/dashboard", headers=self.h(td)).get_json()["untreated"]
        self.assertEqual((d["hours"], d["count"]), (24, 1))
        self.assertEqual((d["items"][0]["name"], d["items"][0]["assigned_name"], d["items"][0]["hours"]), ("Ancien", "Julien", 30))
        self.c.put(f"/api/v1/leads/{a['id']}/status", json={"status": "contacte"}, headers=self.h(td))
        self.assertEqual(self.c.get("/api/v1/dashboard", headers=self.h(td)).get_json()["untreated"]["count"], 0)


class TestNotificationsPush(Base):
    """Appareils enregistrés et notifications envoyées quand un prospect agit."""

    NAVIGATEUR = TestActiviteProspects.NAVIGATEUR
    CHAUD = TestEtape2.CHAUD
    sql, agence, lead, assigner = TestEtape2.sql, TestEtape2.agence, TestEtape2.lead, TestEtape2.assigner

    def setUp(self):
        super().setUp()
        self.envoyes = []

        def faux_mail(dest, sujet, texte, html, **kw):
            self.envoyes.append({"to": dest, "sujet": sujet, "texte": texte, "html": html})
            return True

        for p in (mock.patch.object(backend, "_envoyer_email", side_effect=faux_mail),
                  mock.patch.object(backend, "_lancer_en_arriere_plan", side_effect=lambda f, *a: f(*a)),
                  mock.patch.dict(os.environ, {"BREVO_API_KEY": "cle-de-test", "MAIL_FROM": "contact@zelyro.fr",
                                               "FRONTEND_URL": "https://app.zelyro.fr"})):
            p.start()
            self.addCleanup(p.stop)
        pub, priv = backend._generer_cles_vapid()
        p = mock.patch.dict(os.environ, {"VAPID_PUBLIC_KEY": pub, "VAPID_PRIVATE_KEY": priv,
                                         "VAPID_SUBJECT": "mailto:contact@zelyro.fr"})
        p.start(); self.addCleanup(p.stop)
        self.pushs = []
        self.erreur = {}

        def faux(abonnement, charge):
            code = self.erreur.get(abonnement["endpoint"])
            if code:
                class R: status_code = code
                class E(Exception): response = R()
                raise E()
            self.pushs.append((abonnement["endpoint"], charge))

        p2 = mock.patch.object(backend, "_webpush_envoyer", side_effect=faux)
        p2.start(); self.addCleanup(p2.stop)

    @staticmethod
    def cles():
        import base64
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        pub = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        enc = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
        return {"p256dh": enc(pub), "auth": enc(os.urandom(16))}

    def abonner(self, t, nom="a", hote="fcm.googleapis.com"):
        endpoint = f"https://{hote}/fcm/send/{nom}"
        r = self.c.post("/api/v1/push/subscribe", json={"endpoint": endpoint, "keys": self.cles()}, headers=self.h(t))
        self.assertEqual(r.status_code, 201, r.get_json())
        return endpoint

    def test_configuration(self):
        t = self.jeton("push-1@x.fr")
        c = self.c.get("/api/v1/push/config", headers=self.h(t)).get_json()
        self.assertEqual((c["enabled"], c["public_key"]), (True, os.environ["VAPID_PUBLIC_KEY"]))
        self.assertEqual(self.c.get("/api/v1/push/config").status_code, 401)
        with mock.patch.dict(os.environ, {"VAPID_PRIVATE_KEY": ""}):
            c = self.c.get("/api/v1/push/config", headers=self.h(t)).get_json()
            self.assertEqual((c["enabled"], c["public_key"]), (False, None))
            r = self.c.post("/api/v1/push/subscribe", json={"endpoint": "https://fcm.googleapis.com/x", "keys": self.cles()},
                            headers=self.h(t))
            self.assertEqual(r.status_code, 503)

    def test_enregistrement_refus(self):
        t = self.jeton("push-2@x.fr")
        bonnes = self.cles()
        for endpoint in ("http://fcm.googleapis.com/x", "https://evil.example.com/x", "https://127.0.0.1/x",
                         "https://fcm.googleapis.com.evil.com/x", "https://user:pw@fcm.googleapis.com/x",
                         "https://fcm.googleapis.com:8443/x", "https://169.254.169.254/latest", "", None, 5,
                         "https://fcm.googleapis.com/" + "a" * 1100):
            r = self.c.post("/api/v1/push/subscribe", json={"endpoint": endpoint, "keys": bonnes}, headers=self.h(t))
            self.assertEqual(r.status_code, 400, endpoint)
        ok = "https://fcm.googleapis.com/x"
        for cles in ({}, None, {"p256dh": "abc", "auth": bonnes["auth"]}, {"p256dh": bonnes["p256dh"], "auth": "court"},
                     {"p256dh": bonnes["p256dh"], "auth": "!!!!"}, {"p256dh": 5, "auth": 6}):
            r = self.c.post("/api/v1/push/subscribe", json={"endpoint": ok, "keys": cles}, headers=self.h(t))
            self.assertEqual(r.status_code, 400, cles)
        self.assertEqual(self.c.post("/api/v1/push/subscribe", json={"endpoint": ok, "keys": bonnes}).status_code, 401)
        self.assertEqual(self.sql("SELECT COUNT(*) FROM push_subscriptions")[0][0],
                         self.sql("SELECT COUNT(*) FROM push_subscriptions")[0][0])
        hotes_ok = ("updates.push.services.mozilla.com", "web.push.apple.com", "wns2-par02p.notify.windows.com",
                    "fcm.googleapis.com")
        for i, h in enumerate(hotes_ok):
            self.abonner(t, f"h{i}", h)

    def test_limite_et_reattribution(self):
        t1, t2 = self.jeton("push-3@x.fr"), self.jeton("push-3b@x.fr")
        for i in range(10):
            self.abonner(t1, f"lim{i}")
        r = self.c.post("/api/v1/push/subscribe", json={"endpoint": "https://fcm.googleapis.com/de-trop", "keys": self.cles()},
                        headers=self.h(t1))
        self.assertEqual(r.status_code, 400)
        # un appareil déjà enregistré se met à jour sans compter en double
        self.assertEqual(self.c.post("/api/v1/push/subscribe", json={"endpoint": "https://fcm.googleapis.com/fcm/send/lim0",
                                     "keys": self.cles()}, headers=self.h(t1)).status_code, 201)
        # le même appareil, utilisé avec un autre compte, change de propriétaire
        self.abonner(t2, "lim0")
        proprio = self.sql("SELECT u.email FROM push_subscriptions s JOIN users u ON u.id = s.user_id WHERE s.endpoint = %s",
                           ("https://fcm.googleapis.com/fcm/send/lim0",))
        self.assertEqual(proprio, [("push-3b@x.fr",)])

    def test_desabonnement_limite_au_compte(self):
        t1, t2 = self.jeton("push-4@x.fr"), self.jeton("push-4b@x.fr")
        e = self.abonner(t1, "des")
        self.c.post("/api/v1/push/unsubscribe", json={"endpoint": e}, headers=self.h(t2))
        self.assertEqual(self.sql("SELECT COUNT(*) FROM push_subscriptions WHERE endpoint = %s", (e,))[0][0], 1)
        self.assertEqual(self.c.post("/api/v1/push/unsubscribe", json={"endpoint": e}, headers=self.h(t1)).status_code, 200)
        self.assertEqual(self.sql("SELECT COUNT(*) FROM push_subscriptions WHERE endpoint = %s", (e,))[0][0], 0)
        self.assertEqual(self.c.post("/api/v1/push/unsubscribe", json={}, headers=self.h(t1)).status_code, 400)

    def test_notification_a_l_ouverture_du_formulaire(self):
        td, id_d, te, id_e = self.agence("push-5@x.fr")
        ed, ee = self.abonner(td, "dir"), self.abonner(te, "emp")
        autre = self.jeton("push-5b@x.fr")
        ea = self.abonner(autre, "autre")
        l = self.lead(td, name="Camille Martin")
        self.assigner(td, l, id_e)
        self.pushs.clear()
        lien = self.c.post(f"/api/v1/leads/{l['id']}/completion-link", headers=self.h(td)).get_json()["url"].split("c=")[1]
        nav = {"User-Agent": "Mozilla/5.0 (iPhone) Safari/604.1"}
        self.c.get(f"/public/completer/{lien}", headers={"User-Agent": "WhatsApp/2.23"})        # robot : rien
        self.assertEqual(self.pushs, [])
        self.c.get(f"/public/completer/{lien}", headers=nav)
        self.c.get(f"/public/completer/{lien}", headers=nav)                                       # répété : une seule fois
        self.assertEqual(sorted(p[0] for p in self.pushs), sorted([ed, ee]))
        charge = self.pushs[0][1]
        self.assertEqual((charge["title"], charge["body"]), ("Camille Martin", "a ouvert son formulaire"))
        self.assertEqual(charge["url"], f"https://app.zelyro.fr/leads-profile.html?id={l['id']}")
        self.assertNotIn(ea, [p[0] for p in self.pushs])                                           # une autre agence n'est jamais prévenue

    def test_pas_de_notification_si_la_requete_echoue(self):
        t = self.jeton("push-6@x.fr")
        self.abonner(t, "x6")
        l = self.lead(t)
        lien = self.c.post(f"/api/v1/leads/{l['id']}/completion-link", headers=self.h(t)).get_json()["url"].split("c=")[1]
        self.pushs.clear()
        r = self.c.post(f"/public/completer/{lien}", json={"budget": 1}, headers=self.NAVIGATEUR)   # sans consentement
        self.assertGreaterEqual(r.status_code, 400)
        self.assertEqual(self.pushs, [])

    def test_demande_de_visite_notifiee(self):
        t = self.jeton("push-7@x.fr")
        e = self.abonner(t, "x7")
        self.c.post("/api/v1/properties", json={"title": "Maison Senlis", "address": "5 rue Vieille 60300 Senlis",
                    "property_type": "Maison", "price": 290000, "rooms": 4, "size": 95}, headers=self.h(t))
        b = self.c.get("/api/v1/properties", headers=self.h(t)).get_json()[0]
        l = self.lead(t)
        self.c.post(f"/api/v1/leads/{l['id']}/send-mail", json={"subject": "Sélection", "body": "Bonjour, voici des biens.",
                    "property_ids": [b["id"]]}, headers=self.h(t))
        jeton = re.search(r"annonces\.html\?t=([A-Za-z0-9_-]+)", self.envoyes[-1]["texte"]).group(1)
        self.pushs.clear()
        self.c.post(f"/public/annonces/{jeton}/interet", json={"ref": 0}, headers=self.NAVIGATEUR)
        self.assertEqual(len(self.pushs), 1)
        self.assertEqual(self.pushs[0][1]["title"], "Demande de visite")
        self.assertIn("Camille Martin souhaite visiter « Maison Senlis »", self.pushs[0][1]["body"])
        self.assertIn("à rappeler", self.pushs[0][1]["body"])

    def test_attribution_notifiee(self):
        td, id_d, te, id_e = self.agence("push-8@x.fr")
        ee = self.abonner(te, "emp8")
        l = self.lead(td)
        self.pushs.clear()
        self.assigner(td, l, id_e)
        self.assertEqual([(p[0], p[1]["title"], p[1]["body"]) for p in self.pushs],
                         [(ee, "Un prospect vous est confié", "Camille Martin")])

    def test_appareil_disparu_retire_et_autres_erreurs_conservees(self):
        t = self.jeton("push-9@x.fr")
        mort, lent = self.abonner(t, "mort"), self.abonner(t, "lent")
        vivant = self.abonner(t, "vivant")
        self.erreur[mort], self.erreur[lent] = 410, 503
        n = backend._pousser([self.sql("SELECT id FROM users WHERE email = 'push-9@x.fr'")[0][0]], "T", "C", "https://x/", "t")
        self.assertEqual(n, 1)
        restants = {r[0] for r in self.sql("SELECT endpoint FROM push_subscriptions WHERE endpoint LIKE '%%/fcm/send/%%'")}
        self.assertNotIn(mort, restants); self.assertIn(lent, restants); self.assertIn(vivant, restants)

    def test_notification_d_essai(self):
        t = self.jeton("push-10@x.fr")
        r = self.c.post("/api/v1/push/test", headers=self.h(t))
        self.assertEqual((r.status_code, r.get_json()["sent"]), (200, 0))
        self.abonner(t, "x10")
        r = self.c.post("/api/v1/push/test", headers=self.h(t))
        self.assertEqual((r.status_code, r.get_json()["sent"]), (200, 1))
        self.assertEqual(self.c.post("/api/v1/push/test").status_code, 401)
        with mock.patch.dict(os.environ, {"VAPID_PUBLIC_KEY": ""}):
            self.assertEqual(self.c.post("/api/v1/push/test", headers=self.h(t)).status_code, 503)

    def test_sans_cles_aucun_envoi(self):
        t = self.jeton("push-11@x.fr")
        self.abonner(t, "x11")
        l = self.lead(t)
        lien = self.c.post(f"/api/v1/leads/{l['id']}/completion-link", headers=self.h(t)).get_json()["url"].split("c=")[1]
        self.pushs.clear()
        with mock.patch.dict(os.environ, {"VAPID_SUBJECT": ""}):
            self.assertEqual(self.c.get(f"/public/completer/{lien}", headers=self.NAVIGATEUR).status_code, 200)
        self.assertEqual(self.pushs, [])


class TestWebPushReel(unittest.TestCase):
    """Un vrai appel à la bibliothèque pywebpush (chiffrement et signature), sans réseau."""

    def test_envoi_chiffre_et_signe(self):
        pub, priv = backend._generer_cles_vapid()
        cles = TestNotificationsPush.cles()
        reponse = mock.Mock(status_code=201, text="")
        with mock.patch.dict(os.environ, {"VAPID_PUBLIC_KEY": pub, "VAPID_PRIVATE_KEY": priv,
                                          "VAPID_SUBJECT": "mailto:contact@zelyro.fr"}), \
                mock.patch("requests.post", return_value=reponse) as post:
            backend._webpush_envoyer({"endpoint": "https://fcm.googleapis.com/fcm/send/abc", "keys": cles},
                                     {"title": "Zelyro", "body": "Essai accentué é", "url": "https://app.zelyro.fr/", "tag": "t"})
        args, kw = post.call_args
        self.assertEqual(args[0], "https://fcm.googleapis.com/fcm/send/abc")
        self.assertTrue(kw["headers"]["Authorization"].startswith("vapid t="))
        self.assertIn(f"k={pub}", kw["headers"]["Authorization"])
        self.assertEqual(kw["headers"]["Content-Encoding"], "aes128gcm")
        self.assertGreater(len(kw["data"]), 80)
        self.assertNotIn(b"Essai", kw["data"])                     # le contenu est bien chiffré


if __name__ == "__main__":
    unittest.main(verbosity=2)
