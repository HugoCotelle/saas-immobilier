"""Tests de sécurité du backend, contre une vraie base PostgreSQL."""
import os
import secrets
import subprocess
import sys
import time
import unittest
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
            r = self.poster([self.item(adresse)])
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
