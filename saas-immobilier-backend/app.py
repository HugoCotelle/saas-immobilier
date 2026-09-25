from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
import hashlib
import html as _html
import threading
import jwt
import requests
import os
import re
import sys
import secrets
import unicodedata
from functools import wraps
import psycopg2
import psycopg2.errors
from psycopg2.extras import RealDictCursor
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.exceptions import HTTPException
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# Un JSON de formulaire pèse quelques Ko : au-delà, la requête est refusée
# avant même d'être lue.
app.config['MAX_CONTENT_LENGTH'] = 128 * 1024

# Sur Render, l'application est derrière un proxy. Sans cette ligne, tous
# les visiteurs apparaîtraient avec la même adresse IP et les limites de
# requêtes ci-dessous s'appliqueraient à tout le monde à la fois.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=int(os.getenv("TRUSTED_PROXIES", "1")), x_proto=1)

# ===== CONFIGURATION =====

def _charger_secret():
    """La clé qui signe les connexions doit venir de l'environnement.

    Avec une valeur par défaut écrite dans le code, quiconque lit le dépôt
    peut fabriquer un jeton valide et se faire passer pour n'importe quel
    utilisateur. Mieux vaut que le serveur refuse de démarrer.
    """
    secret = os.getenv("SECRET_KEY") or os.getenv("JWT_SECRET") or ""
    if len(secret) < 32 or secret == "your-secret-key-change-in-production":
        raise RuntimeError(
            "SECRET_KEY absente ou trop courte (32 caractères minimum). "
            "Générez-en une avec : "
            "python3 -c \"import secrets; print(secrets.token_urlsafe(48))\""
        )
    return secret


SECRET_KEY = _charger_secret()
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://hugocotelle@localhost:5432/saas_immobilier")
PORT = int(os.getenv("PORT", 8888))
TOKEN_LIFETIME_HOURS = int(os.getenv("TOKEN_LIFETIME_HOURS", "24"))

# Sites autorisés à appeler l'API depuis un navigateur. Les motifs des
# équipes Vercel "immo-flow" et "zelyro" couvrent la production et les
# prévisualisations ; un domaine personnalisé s'ajoute avec la variable
# ALLOWED_ORIGINS (adresses complètes séparées par des virgules).
_ORIGINES_AUTORISEES = [
    r"^https://saas-immobilier(-[a-z0-9]+)*-(immo-flow|zelyro)\.vercel\.app$",
    r"^https://saas-immobilier\.vercel\.app$",
    r"^http://localhost(:\d+)?$",
    r"^http://127\.0\.0\.1(:\d+)?$",
]
_ORIGINES_AUTORISEES += [
    o.strip() for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o.strip()
]

CORS(
    app,
    origins=_ORIGINES_AUTORISEES,
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
    max_age=600,
)

# ===== LIMITES DE REQUÊTES =====

def _cle_utilisateur():
    """Clé de limitation : l'utilisateur connecté, à défaut l'adresse IP."""
    parties = request.headers.get('Authorization', '').split(' ')
    if len(parties) == 2:
        try:
            data = jwt.decode(parties[1], SECRET_KEY, algorithms=["HS256"])
            return f"u:{data['id']}"
        except Exception:
            pass
    return f"ip:{get_remote_address()}"


def _cle_email():
    """Clé de limitation d'une connexion : l'adresse visée, quelle que soit l'IP."""
    data = request.get_json(silent=True) or {}
    return "mail:" + str(data.get('email') or '').strip().lower()[:255]


# Le stockage en mémoire suffit pour démarrer ; chaque processus gunicorn
# compte séparément. Pour un compte global, définir RATELIMIT_STORAGE_URI
# (par exemple l'adresse d'un Redis).
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["300 per minute"],
    storage_uri=os.getenv("RATELIMIT_STORAGE_URI", "memory://"),
)


@app.errorhandler(429)
def trop_de_requetes(e):
    return jsonify({"message": "Trop de requêtes. Réessayez dans quelques minutes."}), 429


@app.errorhandler(413)
def requete_trop_grosse(e):
    return jsonify({"message": "Requête trop volumineuse"}), 413


@app.errorhandler(404)
def introuvable(e):
    return jsonify({"message": "Not found"}), 404


@app.errorhandler(405)
def methode_interdite(e):
    return jsonify({"message": "Method not allowed"}), 405


@app.after_request
def entetes_securite(reponse):
    """En-têtes de sécurité sur toutes les réponses de l'API."""
    reponse.headers.setdefault('X-Content-Type-Options', 'nosniff')
    reponse.headers.setdefault('Cache-Control', 'no-store')
    reponse.headers.setdefault('Referrer-Policy', 'no-referrer')
    reponse.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    reponse.headers.setdefault('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'")
    return reponse


def erreur_interne():
    """Réponse générique pour une erreur inattendue.

    Le détail (souvent un message de base de données avec des noms de
    tables et de colonnes) va dans les journaux du serveur, jamais dans la
    réponse envoyée au navigateur.
    """
    exc = sys.exc_info()[1]
    if isinstance(exc, HTTPException):
        # 413, 400... : ce ne sont pas des pannes, on laisse le gestionnaire
        # d'erreurs HTTP répondre avec le bon code.
        raise exc
    app.logger.exception("Erreur inattendue sur %s", request.path)
    return jsonify({"message": "Erreur interne du serveur"}), 500


# ===== VALIDATION DES ENTRÉES =====

FINANCING_VALUES = {'unknown', 'approved', 'in_progress', 'pending', 'rejected'}
URGENCY_VALUES = {'unknown', 'immediate', '1-3_months', '3-6_months', '6plus_months'}

# Étapes du suivi d'un prospect, dans l'ordre du parcours. Les valeurs sont
# celles de la colonne leads.status ; seuls les libellés sont en français.
STATUTS = ('nouveau', 'contacte', 'visite', 'offre', 'signe', 'perdu')
STATUTS_LIBELLES = {
    'nouveau': 'Nouveau', 'contacte': 'Contacté', 'visite': 'Visite',
    'offre': 'Offre', 'signe': 'Signé', 'perdu': 'Perdu',
}
STATUTS_CLOS = ('signe', 'perdu')
SOURCES = {'manuel', 'import', 'formulaire', 'extraction', 'leboncoin', 'seloger', 'portail'}
# Score à partir duquel un bien est signalé par e-mail à l'agent.
ALERTE_SCORE_MIN = int(os.getenv("ALERT_MIN_SCORE", "70"))


def _texte_court(v, maxlen):
    """Texte nettoyé et tronqué, ou None. Évite de dépasser la taille des colonnes."""
    if v is None:
        return None
    v = str(v).strip()
    return v[:maxlen] or None


def _entier_borne(v, maxi=2_000_000_000):
    """Entier entre 0 et maxi (limite d'une colonne INTEGER), sinon None."""
    if v in (None, ''):
        return None
    try:
        n = int(v)
    except (TypeError, ValueError):
        return None
    return n if 0 <= n <= maxi else None


def _choix(v, valeurs, defaut='unknown'):
    return v if v in valeurs else defaut


# ===== HELPERS =====

def create_access_token(identity, expires):
    """Créer un JWT token"""
    payload = {
        'id': identity['id'],
        'email': identity['email'],
        'v': identity.get('v', 0),
        'exp': datetime.utcnow() + expires,
        'iat': datetime.utcnow()
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token

def get_db_connection():
    """Obtenir une connexion à la base de données"""
    conn = psycopg2.connect(DATABASE_URL)
    return conn

# Ce que la gestion des mots de passe ajoute à la base. Exécuté au premier
# besoin de chaque processus (et par init-db) : IF NOT EXISTS le rend
# inoffensif s'il est rejoué, et le verrou évite que les 4 processus de
# gunicorn ne le lancent en même temps.
_DDL_COMPTES = (
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 0",
    """CREATE TABLE IF NOT EXISTS password_resets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash CHAR(64) UNIQUE NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        used_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT NOW()
    )""",
    "CREATE INDEX IF NOT EXISTS password_resets_user_idx ON password_resets (user_id)",
)

# Ce que le suivi des prospects ajoute : statuts, notes, relances, alertes
# de matching, source des prospects et adresse du formulaire de contact.
# Même principe que ci-dessus : tout est rejouable sans danger.
_DDL_SUIVI = (
    "ALTER TABLE leads ADD COLUMN IF NOT EXISTS source VARCHAR(30)",
    "ALTER TABLE leads ADD COLUMN IF NOT EXISTS first_contact_at TIMESTAMP",
    "ALTER TABLE leads ADD COLUMN IF NOT EXISTS status_changed_at TIMESTAMP",
    "ALTER TABLE leads ADD COLUMN IF NOT EXISTS consent_at TIMESTAMP",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS capture_token VARCHAR(64)",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS alerts_enabled BOOLEAN NOT NULL DEFAULT TRUE",
    "CREATE UNIQUE INDEX IF NOT EXISTS users_capture_token_idx ON users (capture_token) WHERE capture_token IS NOT NULL",
    """CREATE TABLE IF NOT EXISTS lead_notes (
        id SERIAL PRIMARY KEY,
        lead_id INTEGER NOT NULL REFERENCES leads(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        kind VARCHAR(10) NOT NULL DEFAULT 'note',
        body TEXT NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )""",
    "CREATE INDEX IF NOT EXISTS lead_notes_lead_idx ON lead_notes (lead_id)",
    """CREATE TABLE IF NOT EXISTS lead_reminders (
        id SERIAL PRIMARY KEY,
        lead_id INTEGER NOT NULL REFERENCES leads(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        due_date DATE NOT NULL,
        label VARCHAR(255) NOT NULL,
        done_at TIMESTAMP,
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )""",
    "CREATE INDEX IF NOT EXISTS lead_reminders_lead_idx ON lead_reminders (lead_id)",
    "CREATE INDEX IF NOT EXISTS lead_reminders_user_open_idx ON lead_reminders (user_id, due_date) WHERE done_at IS NULL",
    """CREATE TABLE IF NOT EXISTS match_alerts (
        lead_id INTEGER NOT NULL REFERENCES leads(id) ON DELETE CASCADE,
        property_id INTEGER NOT NULL REFERENCES properties(id) ON DELETE CASCADE,
        score INTEGER,
        sent_at TIMESTAMP NOT NULL DEFAULT NOW(),
        PRIMARY KEY (lead_id, property_id)
    )""",
    """CREATE TABLE IF NOT EXISTS lead_mails (
        id SERIAL PRIMARY KEY,
        lead_id INTEGER NOT NULL REFERENCES leads(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        subject VARCHAR(255) NOT NULL,
        body TEXT NOT NULL,
        property_ids INTEGER[] NOT NULL DEFAULT '{}',
        sent_at TIMESTAMP NOT NULL DEFAULT NOW()
    )""",
    "CREATE INDEX IF NOT EXISTS lead_mails_lead_idx ON lead_mails (lead_id, sent_at)",
)

# Réception automatique des leads LeBonCoin/SeLoger : une adresse de capture
# par agence, et le journal des e-mails déjà traités (Brevo peut renvoyer le
# même événement plusieurs fois ; le message_id évite les doublons).
_DDL_CAPTURE_MAIL = (
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS mail_capture_token VARCHAR(32)",
    "CREATE UNIQUE INDEX IF NOT EXISTS users_mail_capture_token_idx "
    "ON users (mail_capture_token) WHERE mail_capture_token IS NOT NULL",
    """CREATE TABLE IF NOT EXISTS inbound_emails (
        id SERIAL PRIMARY KEY,
        message_id VARCHAR(255) UNIQUE NOT NULL,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        source VARCHAR(20),
        lead_id INTEGER REFERENCES leads(id) ON DELETE SET NULL,
        received_at TIMESTAMP NOT NULL DEFAULT NOW()
    )""",
)

# Les forfaits : code, nom, prospects, biens, e-mails par mois, extractions IA
# par mois (None = illimité), ordre d'affichage. Ces valeurs ne servent qu'à
# remplir la table « plans » la première fois : ensuite, les limites se règlent
# depuis la page d'administration. « illimite » est réservé à l'équipe Zelyro.
PLANS_PAR_DEFAUT = (
    ('essentiel', 'Essentiel', 300, 100, 200, 100, 1),
    ('agence', 'Agence', 1500, 400, 1000, 500, 2),
    ('reseau', 'Réseau', 6000, 1500, 4000, 2000, 3),
    ('illimite', 'Illimité', None, None, None, None, 9),
)


def _sql_plan(p):
    def v(x):
        return 'NULL' if x is None else str(int(x))
    return ("INSERT INTO plans (code, label, max_leads, max_properties, max_mails_month, "
            "max_extractions_month, sort_order) VALUES ('%s', '%s', %s, %s, %s, %s, %s) "
            "ON CONFLICT (code) DO NOTHING" % (p[0], p[1], v(p[2]), v(p[3]), v(p[4]), v(p[5]), int(p[6])))


# Accès sur invitation, forfaits et administration. Les comptes qui existent
# déjà passent en « illimité » (ils appartiennent à l'équipe) ; les suivants
# reçoivent le forfait de leur invitation.
_DDL_ACCES = (
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS plan VARCHAR(20) NOT NULL DEFAULT 'illimite'",
    "ALTER TABLE users ALTER COLUMN plan SET DEFAULT 'essentiel'",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE",
    """CREATE TABLE IF NOT EXISTS plans (
        code VARCHAR(20) PRIMARY KEY,
        label VARCHAR(50) NOT NULL,
        max_leads INTEGER,
        max_properties INTEGER,
        max_mails_month INTEGER,
        max_extractions_month INTEGER,
        sort_order INTEGER NOT NULL DEFAULT 0
    )""",
) + tuple(_sql_plan(p) for p in PLANS_PAR_DEFAUT) + (
    """CREATE TABLE IF NOT EXISTS invitations (
        id SERIAL PRIMARY KEY,
        email VARCHAR(255),
        plan VARCHAR(20) NOT NULL,
        token_hash CHAR(64) UNIQUE NOT NULL,
        invited_by VARCHAR(255),
        created_at TIMESTAMP NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMP NOT NULL,
        used_at TIMESTAMP,
        revoked_at TIMESTAMP
    )""",
    "ALTER TABLE invitations ALTER COLUMN email DROP NOT NULL",
    "ALTER TABLE invitations ADD COLUMN IF NOT EXISTS label VARCHAR(120)",
    "ALTER TABLE invitations ADD COLUMN IF NOT EXISTS key_hint VARCHAR(8)",
    "ALTER TABLE invitations ADD COLUMN IF NOT EXISTS used_email VARCHAR(255)",
    "CREATE INDEX IF NOT EXISTS invitations_email_idx ON invitations (lower(email))",
    """CREATE TABLE IF NOT EXISTS usage_counters (
        user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        period CHAR(7) NOT NULL,
        metric VARCHAR(30) NOT NULL,
        n INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (user_id, period, metric)
    )""",
    """CREATE TABLE IF NOT EXISTS admin_log (
        id SERIAL PRIMARY KEY,
        admin_email VARCHAR(255) NOT NULL,
        action VARCHAR(40) NOT NULL,
        target VARCHAR(255),
        detail TEXT,
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
    )""",
)
_schema_pret = False
_schema_verrou = threading.Lock()


def _assurer_schema():
    global _schema_pret
    if _schema_pret:
        return
    with _schema_verrou:
        if _schema_pret:
            return
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            # Cas courant : tout est déjà là, on ne touche pas aux tables.
            cur.execute("""
                SELECT EXISTS (SELECT 1 FROM information_schema.columns
                               WHERE table_name = 'users' AND column_name = 'token_version'),
                       to_regclass('password_resets') IS NOT NULL,
                       EXISTS (SELECT 1 FROM information_schema.columns
                               WHERE table_name = 'users' AND column_name = 'alerts_enabled'),
                       EXISTS (SELECT 1 FROM information_schema.columns
                               WHERE table_name = 'leads' AND column_name = 'consent_at'),
                       to_regclass('lead_notes') IS NOT NULL,
                       to_regclass('lead_reminders') IS NOT NULL,
                       to_regclass('match_alerts') IS NOT NULL,
                       to_regclass('lead_mails') IS NOT NULL,
                       EXISTS (SELECT 1 FROM information_schema.columns
                               WHERE table_name = 'users' AND column_name = 'mail_capture_token'),
                       to_regclass('inbound_emails') IS NOT NULL,
                       EXISTS (SELECT 1 FROM information_schema.columns
                               WHERE table_name = 'users' AND column_name = 'plan'),
                       to_regclass('plans') IS NOT NULL,
                       to_regclass('invitations') IS NOT NULL,
                       EXISTS (SELECT 1 FROM information_schema.columns
                               WHERE table_name = 'invitations' AND column_name = 'key_hint'),
                       to_regclass('usage_counters') IS NOT NULL,
                       to_regclass('admin_log') IS NOT NULL
            """)
            if not all(cur.fetchone()):
                cur.execute("SELECT pg_advisory_xact_lock(727301)")
                for ddl in _DDL_COMPTES + _DDL_SUIVI + _DDL_CAPTURE_MAIL + _DDL_ACCES:
                    cur.execute(ddl)
            conn.commit()
            _schema_pret = True
        finally:
            conn.close()


def _maintenant():
    """Heure UTC sans fuseau, prise sur l'horloge de l'application (jamais
    celle de la base) pour la validité des liens de réinitialisation."""
    return datetime.utcnow()


def token_required(f):
    """Décorateur pour vérifier le token JWT"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({"message": "Invalid token format"}), 401
        if not token:
            return jsonify({"message": "Token is missing"}), 401
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"],
                              options={"require": ["exp", "id"]})
            current_user_id = data['id']
            request.user_id = current_user_id
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token"}), 401

        # Le compte doit toujours exister, et le jeton doit porter la version
        # actuelle du compte. Chaque changement de mot de passe l'incrémente :
        # une session volée ne survit donc pas à une réinitialisation.
        try:
            _assurer_schema()
            conn = get_db_connection()
            try:
                cur = conn.cursor()
                cur.execute("SELECT token_version, is_active, email FROM users WHERE id = %s", (current_user_id,))
                ligne = cur.fetchone()
            finally:
                conn.close()
        except Exception:
            return erreur_interne()
        if ligne is None:
            return jsonify({"message": "Invalid token"}), 401
        if int(data.get('v', 0)) != ligne[0] or not ligne[1]:
            return jsonify({"message": "Invalid token"}), 401
        request.user_email = ligne[2]
        return f(*args, **kwargs)
    return decorated


def _admins():
    """Les adresses des administrateurs (équipe Zelyro), fixées par la variable
    ADMIN_EMAILS de l'hébergeur : on ne devient pas administrateur depuis le site."""
    return {e.strip().lower() for e in (os.getenv("ADMIN_EMAILS") or "").split(",") if e.strip()}


def _est_admin(email):
    return (email or '').strip().lower() in _admins()


def admin_required(f):
    """Réservé aux administrateurs. Pour tous les autres, la page n'existe pas."""
    @wraps(f)
    def verifie(*args, **kwargs):
        if not _est_admin(getattr(request, 'user_email', '')):
            return jsonify({"message": "Not found"}), 404
        return f(*args, **kwargs)
    return token_required(verifie)

def init_database(demo=False):
    """Créer les tables qui n'existent pas encore.

    Cette fonction n'est plus appelable depuis le web. Elle se lance en
    ligne de commande (python app.py init-db) ou une fois au démarrage avec
    INIT_DB_ON_START=1. Les données de démonstration ne sont créées qu'avec
    l'option --demo, sur une base vide, avec un mot de passe tiré au hasard.
    """
    conn = get_db_connection()
    try:
        cursor = conn.cursor()

        # Table USERS
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                first_name VARCHAR(100),
                company_name VARCHAR(255),
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)

        # Table LEADS
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS leads (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                name VARCHAR(255) NOT NULL,
                email VARCHAR(255),
                phone VARCHAR(20),
                budget INTEGER,
                location VARCHAR(255),
                property_type VARCHAR(100),
                status VARCHAR(50) DEFAULT 'nouveau',
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)

        # Table PROPERTIES
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS properties (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                title VARCHAR(255) NOT NULL,
                address VARCHAR(255),
                price INTEGER,
                size INTEGER,
                rooms INTEGER,
                property_type VARCHAR(100),
                description TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            )
        """)

        # Colonnes ajoutées après la première version du schéma : sans elles,
        # une base neuve ne correspond pas à ce que le code interroge.
        for ddl in (
            "ALTER TABLE leads ADD COLUMN IF NOT EXISTS financing_status VARCHAR(50) DEFAULT 'unknown'",
            "ALTER TABLE leads ADD COLUMN IF NOT EXISTS purchase_urgency VARCHAR(50) DEFAULT 'unknown'",
            "ALTER TABLE leads ADD COLUMN IF NOT EXISTS lead_quality VARCHAR(20)",
            "ALTER TABLE leads ADD COLUMN IF NOT EXISTS financing_amount INTEGER",
            "ALTER TABLE leads ADD COLUMN IF NOT EXISTS notes TEXT",
            "CREATE INDEX IF NOT EXISTS leads_user_id_idx ON leads (user_id)",
            "CREATE INDEX IF NOT EXISTS properties_user_id_idx ON properties (user_id)",
        ):
            cursor.execute(ddl)
        for ddl in _DDL_COMPTES + _DDL_SUIVI + _DDL_CAPTURE_MAIL + _DDL_ACCES:
            cursor.execute(ddl)

        # Vérifier si vide
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]

        if demo and user_count == 0:
            # Compte de démonstration : mot de passe tiré au hasard, affiché
            # une seule fois. Jamais de mot de passe connu écrit dans le code.
            mot_de_passe_demo = os.getenv("DEMO_PASSWORD") or secrets.token_urlsafe(12)
            cursor.execute("""
                INSERT INTO users (email, password_hash, first_name, company_name)
                VALUES (%s, %s, %s, %s) RETURNING id
            """, ('demo@example.com',
                  generate_password_hash(mot_de_passe_demo, method='pbkdf2:sha256'),
                  'Demo', 'Demo Company'))
            demo_user_id = cursor.fetchone()[0]
            print(f"Compte de démonstration : demo@example.com / {mot_de_passe_demo}")

            # 33 leads
            leads_data = [
                ('Alice Dupont', 'alice@example.com', '0601020304', 250000, 'Paris 15', 'Appartement'),
                ('Bob Martin', 'bob@example.com', '0602030405', 350000, 'Lyon', 'Maison'),
                ('Claire Durand', 'claire@example.com', '0603040506', 450000, 'Marseille', 'Villa'),
                ('David Petit', 'david@example.com', '0604050607', 300000, 'Toulouse', 'Appartement'),
                ('Eva Leblanc', 'eva@example.com', '0605060708', 200000, 'Nice', 'Studio'),
                ('Franck Richard', 'franck@example.com', '0606070809', 500000, 'Bordeaux', 'Maison'),
                ('Gisele Lefevre', 'gisele@example.com', '0607080910', 275000, 'Lille', 'Appartement'),
                ('Hervé Mercier', 'herve@example.com', '0608091011', 400000, 'Nantes', 'Maison'),
                ('Isabelle Roux', 'isabelle@example.com', '0609101112', 320000, 'Strasbourg', 'Appartement'),
                ('Jacques Simon', 'jacques@example.com', '0610111213', 450000, 'Montpellier', 'Villa'),
                ('Karine Morel', 'karine@example.com', '0611121314', 280000, 'Toulouse', 'Appartement'),
                ('Laurent Girard', 'laurent@example.com', '0612131415', 380000, 'Bordeaux', 'Maison'),
                ('Monique Bertrand', 'monique@example.com', '0613141516', 320000, 'Marseille', 'Appartement'),
                ('Nicolas Blanc', 'nicolas@example.com', '0614151617', 420000, 'Lyon', 'Maison'),
                ('Odette Fabre', 'odette@example.com', '0615161718', 260000, 'Nantes', 'Appartement'),
                ('Pierre Garnier', 'pierre@example.com', '0616171819', 500000, 'Paris 6', 'Penthouse'),
                ('Quentin Hubert', 'quentin@example.com', '0617181920', 290000, 'Lille', 'Appartement'),
                ('Renee Jacquet', 'renee@example.com', '0618192021', 410000, 'Bordeaux', 'Maison'),
                ('Stephane Kerr', 'stephane@example.com', '0619202122', 340000, 'Nice', 'Appartement'),
                ('Therese Lachance', 'therese@example.com', '0620212223', 480000, 'Strasbourg', 'Villa'),
                ('Urbain Martin', 'urbain@example.com', '0621222324', 270000, 'Montpellier', 'Appartement'),
                ('Valerie Noel', 'valerie@example.com', '0622232425', 390000, 'Lyon', 'Maison'),
                ('William Olivier', 'william@example.com', '0623242526', 330000, 'Marseille', 'Appartement'),
                ('Yvette Perrin', 'yvette@example.com', '0624252627', 430000, 'Bordeaux', 'Maison'),
                ('Zacharie Quine', 'zacharie@example.com', '0625262728', 510000, 'Paris 8', 'Penthouse'),
                ('Amelie Renard', 'amelie@example.com', '0626272829', 295000, 'Nantes', 'Appartement'),
                ('Benoit Saulnier', 'benoit@example.com', '0627282930', 400000, 'Toulouse', 'Maison'),
                ('Camille Tetard', 'camille@example.com', '0628293031', 350000, 'Strasbourg', 'Appartement'),
                ('Dominique Uzan', 'dominique@example.com', '0629303132', 460000, 'Nice', 'Villa'),
                ('Emilie Verdin', 'emilie@example.com', '0630313233', 280000, 'Lille', 'Appartement'),
                ('Fabien Walden', 'fabien@example.com', '0631323334', 385000, 'Bordeaux', 'Maison'),
                ('Genevieve Xavier', 'genevieve@example.com', '0632333435', 325000, 'Lyon', 'Appartement'),
                ('Henri Yates', 'henri@example.com', '0633343536', 440000, 'Paris 12', 'Maison'),
            ]

            for name, email, phone, budget, location, property_type in leads_data:
                cursor.execute("""
                    INSERT INTO leads (user_id, name, email, phone, budget, location, property_type, status)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, 'nouveau')
                """, (demo_user_id, name, email, phone, budget, location, property_type))

        conn.commit()
        cursor.close()
        print("✅ Base de données initialisée!")

    except Exception as e:
        print(f"❌ Erreur: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()


if os.getenv("INIT_DB_ON_START") == "1":
    # Pour les hébergements sans terminal : à activer le temps d'un
    # déploiement, puis à retirer.
    try:
        init_database()
    except Exception:
        app.logger.exception("Initialisation de la base impossible")

# ===== ROUTES HEALTH & INIT =====

@app.route('/health', methods=['GET'])
@limiter.exempt
def health():
    """Vérifier que le backend répond"""
    return jsonify({"status": "OK"}), 200

# ===== ROUTES AUTHENTICATION =====

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Sert à consommer le même temps de calcul quand l'adresse est inconnue :
# sans cela, la vitesse de la réponse révèle quelles adresses ont un compte.
_HASH_FACTICE = generate_password_hash(secrets.token_urlsafe(16), method='pbkdf2:sha256')


MESSAGE_INVITATION = ("Une clé d'activation est nécessaire pour créer un compte. "
                      "Écrivez à contact@zelyro.fr pour en obtenir une.")
LIEN_INVITATION_INVALIDE = ("Clé d'activation invalide ou expirée. Vérifiez-la, ou demandez-en une nouvelle "
                            "à l'équipe Zelyro.")
MESSAGE_CLE_AUTRE_ADRESSE = "Cette clé d'activation est réservée à une autre adresse e-mail."

# Clé d'activation : ZLY-XXXX-XXXX-XXXX. L'alphabet exclut I, O, 0 et 1, qu'on
# confond à la lecture ou au téléphone ; 12 caractères tirés au hasard font
# 60 bits, hors de portée d'un essai systématique (l'inscription est limitée
# à 10 essais par heure et par adresse IP).
ALPHABET_CLE = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def _nouvelle_cle():
    brut = ''.join(secrets.choice(ALPHABET_CLE) for _ in range(12))
    return f"ZLY-{brut[0:4]}-{brut[4:8]}-{brut[8:12]}"


def _empreinte_cle(saisie):
    """L'empreinte à chercher en base pour ce que la personne a saisi :
    majuscules, tirets et espaces sans importance. Un ancien lien
    d'invitation (long jeton) est encore reconnu tel quel. Renvoie None si
    la saisie ne peut pas être une clé."""
    saisie = str(saisie or '').strip()
    if re.fullmatch(r'[A-Za-z0-9_-]{32,64}', saisie):
        return _hash_jeton(saisie)
    brut = re.sub(r'[^A-Za-z0-9]', '', saisie).upper()
    if brut.startswith('ZLY'):
        brut = brut[3:]
    if len(brut) != 12 or any(ch not in ALPHABET_CLE for ch in brut):
        return None
    return _hash_jeton(brut)


@app.route('/auth/register', methods=['POST'])
@limiter.limit("10 per hour")
def register():
    """Créer un compte.

    L'inscription est fermée : il faut une clé d'activation donnée par
    l'équipe Zelyro. Le forfait vient de la clé, jamais du navigateur. Si la
    clé a été créée pour une adresse précise, elle ne marche qu'avec celle-ci.
    OPEN_REGISTRATION=1 rouvre l'inscription libre : réservé aux tests, à ne
    jamais activer en production.
    """
    data = request.get_json(silent=True) or {}
    cle = str(data.get('invitation') or '').strip()
    if not cle and os.getenv("OPEN_REGISTRATION") != "1":
        return jsonify({"message": MESSAGE_INVITATION, "code": "invitation_required"}), 403
    password = data.get('password')
    first_name = str(data.get('first_name') or '').strip()[:100]
    company_name = str(data.get('company_name') or '').strip()[:255]

    email = str(data.get('email') or '').strip().lower()
    if not email or not password:
        return jsonify({"message": "Email and password required"}), 400
    if len(email) > 255 or not EMAIL_RE.match(email):
        return jsonify({"message": "Adresse email invalide"}), 400
    if not isinstance(password, str) or len(password) < 10:
        return jsonify({"message": "Le mot de passe doit contenir au moins 10 caractères"}), 400
    if len(password) > 128:
        return jsonify({"message": "Mot de passe trop long (128 caractères maximum)"}), 400
    empreinte = None
    if cle:
        empreinte = _empreinte_cle(cle)
        if not empreinte:
            return jsonify({"message": LIEN_INVITATION_INVALIDE}), 400

    try:
        _assurer_schema()
        conn = get_db_connection()
        try:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            plan, inv_id = 'essentiel', None
            if empreinte:
                cur.execute("""SELECT id, email, plan FROM invitations
                               WHERE token_hash = %s AND used_at IS NULL AND revoked_at IS NULL
                                 AND expires_at > %s FOR UPDATE""", (empreinte, _maintenant()))
                inv = cur.fetchone()
                if not inv:
                    return jsonify({"message": LIEN_INVITATION_INVALIDE}), 400
                if inv['email'] and inv['email'].strip().lower() != email:
                    return jsonify({"message": MESSAGE_CLE_AUTRE_ADRESSE}), 400
                plan, inv_id = inv['plan'], inv['id']

            cur.execute("SELECT id FROM users WHERE lower(email) = %s", (email,))
            if cur.fetchone():
                return jsonify({"message": "User already exists"}), 409

            password_hash = generate_password_hash(password, method='pbkdf2:sha256')
            cur.execute(
                "INSERT INTO users (email, password_hash, first_name, company_name, plan) VALUES (%s, %s, %s, %s, %s) RETURNING id",
                (email, password_hash, first_name, company_name, plan)
            )
            user_id = cur.fetchone()['id']
            if inv_id:
                cur.execute("UPDATE invitations SET used_at = %s, used_email = %s WHERE id = %s",
                            (_maintenant(), email, inv_id))
            conn.commit()
        finally:
            conn.close()

        token = create_access_token(identity={'id': user_id, 'email': email}, expires=timedelta(hours=TOKEN_LIFETIME_HOURS))
        return jsonify({
            "message": "User created successfully",
            "token": token,
            "user": {
                "id": user_id,
                "email": email,
                "first_name": first_name,
                "company_name": company_name,
                "plan": plan,
                "is_admin": _est_admin(email)
            }
        }), 201
    except psycopg2.errors.UniqueViolation:
        # Deux inscriptions simultanées avec la même adresse.
        return jsonify({"message": "User already exists"}), 409
    except Exception:
        return erreur_interne()

@app.route('/auth/login', methods=['POST'])
@limiter.limit("30 per minute")
@limiter.limit("8 per 15 minutes", key_func=_cle_email,
               deduct_when=lambda reponse: reponse.status_code == 401)
def login():
    """Connexion utilisateur"""
    data = request.get_json(silent=True) or {}
    email = str(data.get('email') or '').strip().lower()
    password = data.get('password')
    if not email or not password or not isinstance(password, str):
        return jsonify({"message": "Email and password required"}), 400
    if len(password) > 128:
        return jsonify({"message": "Invalid credentials"}), 401

    try:
        _assurer_schema()
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, email, password_hash, first_name, company_name, token_version, is_active, plan FROM users WHERE lower(email) = %s", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if user:
            valide = check_password_hash(user['password_hash'], password)
        else:
            check_password_hash(_HASH_FACTICE, password)
            valide = False

        if not valide:
            return jsonify({"message": "Invalid credentials"}), 401
        if not user['is_active']:
            # Après la vérification du mot de passe : seul le titulaire du compte l'apprend.
            return jsonify({"message": "Ce compte est suspendu. Contactez l'équipe Zelyro.", "code": "suspended"}), 403

        token = create_access_token(identity={'id': user['id'], 'email': user['email'], 'v': user['token_version']}, expires=timedelta(hours=TOKEN_LIFETIME_HOURS))

        return jsonify({
            "message": "Login successful",
            "token": token,
            "user": {
                "id": user['id'],
                "email": user['email'],
                "first_name": user['first_name'],
                "company_name": user['company_name'],
                "plan": user['plan'],
                "is_admin": _est_admin(user['email'])
            }
        }), 200
    except Exception:
        return erreur_interne()

# ===== MOT DE PASSE : CHANGEMENT, OUBLI, RÉINITIALISATION =====

RESET_TOKEN_MINUTES = int(os.getenv("RESET_TOKEN_MINUTES", "30"))
BREVO_URL = "https://api.brevo.com/v3/smtp/email"
MESSAGE_OUBLI = ("Si un compte existe pour cette adresse, un e-mail contenant un lien de "
                 f"réinitialisation vient d'être envoyé. Il est valable {RESET_TOKEN_MINUTES} minutes.")
LIEN_INVALIDE = "Ce lien est invalide ou a expiré. Faites une nouvelle demande."


def _erreur_mot_de_passe(mdp):
    """Message d'erreur si le mot de passe ne respecte pas la règle, sinon None."""
    if not isinstance(mdp, str) or not mdp:
        return "Mot de passe manquant"
    if len(mdp) < 10:
        return "Le mot de passe doit contenir au moins 10 caractères"
    if len(mdp) > 128:
        return "Mot de passe trop long (128 caractères maximum)"
    return None


def _hash_jeton(jeton):
    """Seule l'empreinte du lien est conservée : une copie de la base ne
    permet donc pas de réinitialiser un compte."""
    return hashlib.sha256(jeton.encode('utf-8')).hexdigest()


def _envoi_configure():
    """Vrai si tout ce qu'il faut pour envoyer un lien est renseigné."""
    return all((os.getenv(k) or "").strip() for k in ("BREVO_API_KEY", "MAIL_FROM", "FRONTEND_URL"))


def _lancer_en_arriere_plan(fonction, *args):
    """L'envoi d'e-mail est lent : le faire après la réponse évite aussi que
    le temps de réponse révèle si une adresse a un compte."""
    threading.Thread(target=fonction, args=args, daemon=True).start()


def _envoyer_email(destinataire, sujet, texte, html, nom_expediteur=None, repondre_a=None):
    """Envoie un e-mail via Brevo. Renvoie True si l'envoi est accepté.

    nom_expediteur remplace le nom affiché (l'adresse d'expédition reste
    celle du domaine authentifié) ; repondre_a est un couple (adresse, nom)
    vers lequel partent les réponses."""
    cle = (os.getenv("BREVO_API_KEY") or "").strip()
    expediteur = (os.getenv("MAIL_FROM") or "").strip()
    if not cle or not expediteur:
        app.logger.warning("E-mail non envoyé : BREVO_API_KEY ou MAIL_FROM non défini")
        return False
    try:
        charge = {
            "sender": {"name": nom_expediteur or os.getenv("MAIL_FROM_NAME", "Zelyro"), "email": expediteur},
            "to": [{"email": destinataire}],
            "subject": sujet,
            "textContent": texte,
            "htmlContent": html,
        }
        if repondre_a and repondre_a[0]:
            charge["replyTo"] = {"email": repondre_a[0], "name": repondre_a[1] or repondre_a[0]}
        r = requests.post(
            BREVO_URL,
            headers={"api-key": cle, "content-type": "application/json", "accept": "application/json"},
            json=charge,
            timeout=15,
        )
        if r.status_code not in (200, 201, 202):
            app.logger.error("Brevo a refusé l'envoi (code %s) : %s", r.status_code, r.text[:200])
            return False
        return True
    except requests.RequestException:
        app.logger.exception("Envoi d'e-mail impossible")
        return False


def _gabarit_email(titre, paragraphes, bouton=None):
    """E-mail sobre, en texte et en HTML."""
    texte = "\n\n".join(paragraphes + ([f"{bouton[0]} : {bouton[1]}"] if bouton else [])) + "\n\nZelyro"
    corps = "".join(f'<p style="margin:0 0 16px;line-height:1.6">{_html.escape(p)}</p>' for p in paragraphes)
    if bouton:
        corps += (f'<p style="margin:24px 0"><a href="{_html.escape(bouton[1])}" '
                  'style="background:#4F6353;color:#ffffff;text-decoration:none;padding:12px 22px;'
                  f'border-radius:6px;display:inline-block">{_html.escape(bouton[0])}</a></p>'
                  f'<p style="margin:0 0 16px;color:#6A7168;font-size:13px;line-height:1.5">'
                  f'Si le bouton ne fonctionne pas, copiez ce lien dans votre navigateur :<br>'
                  f'{_html.escape(bouton[1])}</p>')
    html = ('<div style="font-family:Arial,Helvetica,sans-serif;color:#1F2A24;max-width:520px;margin:0 auto;padding:24px">'
            f'<h2 style="font-family:Georgia,serif;font-weight:500;letter-spacing:.08em">ZELYRO</h2>'
            f'<h3 style="font-weight:600;margin:24px 0 16px">{_html.escape(titre)}</h3>{corps}</div>')
    return texte, html


def _traiter_oubli(email):
    """Crée un lien à usage unique et l'envoie, si l'adresse a un compte."""
    try:
        _assurer_schema()
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT id, email FROM users WHERE lower(email) = %s AND is_active", (email,))
            user = cur.fetchone()
            if not user:
                return
            jeton = secrets.token_urlsafe(32)
            maintenant = _maintenant()
            # Un seul lien valable à la fois : une nouvelle demande annule les précédentes.
            cur.execute("UPDATE password_resets SET used_at = %s WHERE user_id = %s AND used_at IS NULL",
                        (maintenant, user[0]))
            cur.execute("INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (%s, %s, %s)",
                        (user[0], _hash_jeton(jeton), maintenant + timedelta(minutes=RESET_TOKEN_MINUTES)))
            conn.commit()
            adresse = user[1]
        finally:
            conn.close()

        # L'adresse du site vient de la configuration, jamais de la requête :
        # sinon un en-tête Host falsifié ferait pointer le lien vers un autre site.
        site = (os.getenv("FRONTEND_URL") or "").strip().rstrip("/")
        if not site:
            app.logger.error("Lien de réinitialisation non envoyé : FRONTEND_URL non défini")
            return
        # Le jeton est placé après le # : il n'est jamais envoyé au serveur du site ni journalisé.
        lien = f"{site}/reset-password.html#token={jeton}"
        texte, html = _gabarit_email(
            "Réinitialiser votre mot de passe",
            ["Vous avez demandé à réinitialiser votre mot de passe Zelyro.",
             f"Ce lien est valable {RESET_TOKEN_MINUTES} minutes et ne peut servir qu'une fois.",
             "Si vous n'êtes pas à l'origine de cette demande, ignorez cet e-mail : votre mot de passe reste inchangé."],
            ("Choisir un nouveau mot de passe", lien))
        _envoyer_email(adresse, "Réinitialisation de votre mot de passe Zelyro", texte, html)
    except Exception:
        app.logger.exception("Réinitialisation du mot de passe : traitement impossible")


def _prevenir_changement(adresse):
    """Prévient le titulaire que le mot de passe vient de changer."""
    try:
        texte, html = _gabarit_email(
            "Votre mot de passe a été modifié",
            ["Le mot de passe de votre compte Zelyro vient d'être modifié.",
             "Si ce n'est pas vous, demandez immédiatement une réinitialisation depuis la page de connexion."])
        _envoyer_email(adresse, "Votre mot de passe Zelyro a été modifié", texte, html)
    except Exception:
        app.logger.exception("Notification de changement de mot de passe impossible")


@app.route('/auth/change-password', methods=['POST'])
@limiter.limit("5 per 15 minutes", key_func=_cle_utilisateur,
               deduct_when=lambda reponse: reponse.status_code >= 400)
@token_required
def change_password():
    """Changer son mot de passe en étant connecté.

    Un mauvais mot de passe actuel renvoie 400 et non 401 : le site
    déconnecte l'utilisateur sur un 401, ce qui serait déroutant ici.
    """
    data = request.get_json(silent=True) or {}
    actuel = data.get('current_password')
    nouveau = data.get('new_password')
    if not isinstance(actuel, str) or not actuel:
        return jsonify({"message": "Mot de passe actuel manquant"}), 400
    erreur = _erreur_mot_de_passe(nouveau)
    if erreur:
        return jsonify({"message": erreur}), 400
    if nouveau == actuel:
        return jsonify({"message": "Le nouveau mot de passe doit être différent de l'ancien"}), 400

    try:
        conn = get_db_connection()
        try:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT id, email, password_hash FROM users WHERE id = %s", (request.user_id,))
            user = cur.fetchone()
            if not user or not check_password_hash(user['password_hash'], actuel):
                return jsonify({"message": "Mot de passe actuel incorrect"}), 400
            cur.execute("UPDATE users SET password_hash = %s, token_version = token_version + 1 "
                        "WHERE id = %s RETURNING token_version",
                        (generate_password_hash(nouveau, method='pbkdf2:sha256'), user['id']))
            version = cur.fetchone()['token_version']
            conn.commit()
        finally:
            conn.close()

        # Les autres sessions ouvertes sont désormais refusées ; celle-ci
        # reçoit un jeton neuf pour continuer sans se reconnecter.
        token = create_access_token(identity={'id': user['id'], 'email': user['email'], 'v': version},
                                    expires=timedelta(hours=TOKEN_LIFETIME_HOURS))
        _lancer_en_arriere_plan(_prevenir_changement, user['email'])
        return jsonify({"message": "Mot de passe modifié", "token": token}), 200
    except Exception:
        return erreur_interne()


@app.route('/auth/forgot-password', methods=['POST'])
@limiter.limit("5 per hour")
@limiter.limit("3 per hour", key_func=_cle_email)
def forgot_password():
    """Demander un lien de réinitialisation par e-mail.

    La réponse est identique que l'adresse ait un compte ou non : sinon
    cette page permettrait de lister les clients de l'outil.
    """
    data = request.get_json(silent=True) or {}
    email = str(data.get('email') or '').strip().lower()
    if not email or len(email) > 255 or not EMAIL_RE.match(email):
        return jsonify({"message": "Adresse email invalide"}), 400
    if not _envoi_configure():
        # Réponse identique pour toutes les adresses : elle ne renseigne que
        # sur l'état du service, pas sur les comptes. Mieux vaut le dire que
        # laisser croire qu'un e-mail part.
        return jsonify({"message": "L'envoi d'e-mails n'est pas encore activé sur ce service. "
                                   "Contactez votre administrateur."}), 503
    _lancer_en_arriere_plan(_traiter_oubli, email)
    return jsonify({"message": MESSAGE_OUBLI}), 200


@app.route('/auth/reset-password', methods=['POST'])
@limiter.limit("10 per hour")
def reset_password():
    """Choisir un nouveau mot de passe avec le lien reçu par e-mail."""
    data = request.get_json(silent=True) or {}
    jeton = data.get('token')
    nouveau = data.get('new_password')
    if not isinstance(jeton, str) or not 20 <= len(jeton) <= 200:
        return jsonify({"message": LIEN_INVALIDE}), 400
    # Vérifié avant de consommer le lien : un mot de passe refusé
    # permet de réessayer avec le même lien.
    erreur = _erreur_mot_de_passe(nouveau)
    if erreur:
        return jsonify({"message": erreur}), 400

    try:
        _assurer_schema()
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            maintenant = _maintenant()
            cur.execute("""
                SELECT r.id, r.user_id, u.email FROM password_resets r
                JOIN users u ON u.id = r.user_id
                WHERE r.token_hash = %s AND r.used_at IS NULL AND r.expires_at > %s
                FOR UPDATE OF r
            """, (_hash_jeton(jeton), maintenant))
            ligne = cur.fetchone()
            if not ligne:
                return jsonify({"message": LIEN_INVALIDE}), 400
            cur.execute("UPDATE users SET password_hash = %s, token_version = token_version + 1 WHERE id = %s",
                        (generate_password_hash(nouveau, method='pbkdf2:sha256'), ligne[1]))
            cur.execute("UPDATE password_resets SET used_at = %s WHERE user_id = %s AND used_at IS NULL",
                        (maintenant, ligne[1]))
            conn.commit()
            adresse = ligne[2]
        finally:
            conn.close()
        _lancer_en_arriere_plan(_prevenir_changement, adresse)
        return jsonify({"message": "Mot de passe modifié. Vous pouvez maintenant vous connecter."}), 200
    except Exception:
        return erreur_interne()


@app.route('/auth/profile', methods=['GET'])
@token_required
def get_profile():
    """Récupérer le profil de l'utilisateur connecté"""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, email, first_name, company_name, created_at, alerts_enabled, plan FROM users WHERE id = %s", (request.user_id,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if not user:
            return jsonify({"message": "User not found"}), 404

        user['is_admin'] = _est_admin(user['email'])
        return jsonify(user), 200
    except Exception:
        return erreur_interne()

# ===== SCORING INTELLIGENT =====

def derive_lead_quality(lead):
    """Déduire la qualité d'un lead de ses caractéristiques.

    La qualité était auparavant une colonne saisie à la main, qui servait
    ensuite à pondérer le score de matching : l'agent décidait qu'un lead
    était chaud, et l'outil le lui confirmait. Elle est maintenant déduite
    du financement, de l'urgence et de la précision du besoin — soit des
    éléments que l'agent n'a pas toujours en tête.

    Les seuils ci-dessous sont un choix, pas une vérité. Pour les régler
    correctement, il faudrait demander à un directeur d'agence de classer
    une vingtaine de ses leads et ajuster jusqu'à retrouver son classement.
    """
    points = 0

    financing = lead.get('financing_status') or 'unknown'
    if financing == 'approved':
        points += 40
    elif financing == 'in_progress':
        points += 25
    elif financing == 'pending':
        points += 12

    urgency = lead.get('purchase_urgency') or 'unknown'
    if urgency == 'immediate':
        points += 35
    elif urgency == '1-3_months':
        points += 28
    elif urgency == '3-6_months':
        points += 15
    elif urgency == '6plus_months':
        points += 5

    # Un dossier complet est un signal d'engagement réel.
    if lead.get('budget'):
        points += 10
    if lead.get('location'):
        points += 8
    if lead.get('property_type'):
        points += 7

    if points >= 80:
        return 'hot'
    if points >= 45:
        return 'warm'
    return 'cold'


def _detail_score(lead, property_item):
    """Renvoie (score, raisons) : le score de correspondance entre un
    prospect et un bien, et les phrases qui expliquent d'où il vient.

    Les points sont ceux de l'ancien calcul, à l'identique. Seules les
    raisons sont nouvelles : elles permettent à l'agent de voir pourquoi
    un bien remonte, et de contester le classement s'il n'est pas d'accord.
    """
    score = 0
    raisons = []

    budget = lead.get('budget')
    prix = property_item.get('price')
    if budget and prix is not None:
        ecart = abs(prix - budget) / budget
        pct = round(ecart * 100)
        if ecart < 0.05:
            score += 20
            raisons.append("Budget quasi identique au prix" if pct == 0 else f"Budget très proche du prix (écart de {pct} %)")
        elif ecart < 0.10:
            score += 18
            raisons.append(f"Budget très proche du prix (écart de {pct} %)")
        elif ecart < 0.15:
            score += 15
            raisons.append(f"Budget proche du prix (écart de {pct} %)")
        elif ecart < 0.20:
            score += 12
            raisons.append(f"Budget proche du prix (écart de {pct} %)")
        elif ecart < 0.30:
            score += 8
            raisons.append(f"Prix à {pct} % du budget, à discuter")

    type_lead = lead.get('property_type')
    type_bien = property_item.get('property_type')
    if type_lead == type_bien:
        score += 30
        if type_lead:
            raisons.append(f"Même type de bien : {type_lead}")
    elif type_lead in ['Appartement', 'Maison'] and type_bien in ['Appartement', 'Maison']:
        score += 15
        raisons.append("Type voisin (appartement ou maison)")

    # La localisation est le seul critère éliminatoire : un budget et un
    # type qui collent ne rattrapent pas une ville à 750 km.
    points_loc, hors_secteur = score_localisation(lead, property_item)
    if hors_secteur:
        return 0, ["Hors du secteur recherché"]
    score += points_loc
    if points_loc == 20:
        raisons.append(f"Secteur recherché : {lead.get('location')}")
    elif points_loc == 15:
        raisons.append("Même ville, autre arrondissement")
    elif not lead.get('location'):
        raisons.append("Prospect ouvert sur le secteur")

    financing_status = lead.get('financing_status', 'unknown')
    if financing_status == 'approved':
        score += 20
        raisons.append("Financement validé")
    elif financing_status == 'in_progress':
        score += 15
        raisons.append("Financement en cours")
    elif financing_status == 'pending':
        score += 10
        raisons.append("Financement en attente")
    else:
        score += 5

    urgency = lead.get('purchase_urgency', 'unknown')
    if urgency == 'immediate':
        score += 15
        raisons.append("Achat immédiat")
    elif urgency == '1-3_months':
        score += 12
        raisons.append("Achat prévu sous 1 à 3 mois")
    elif urgency == '3-6_months':
        score += 8
        raisons.append("Achat prévu sous 3 à 6 mois")
    elif urgency == '6plus_months':
        score += 4
        raisons.append("Achat prévu dans plus de 6 mois")
    else:
        score += 5

    # Le multiplicateur par lead_quality a été retiré : le financement et
    # l'urgence sont déjà comptés ci-dessus, les réappliquer les comptait
    # deux fois.
    return min(100, max(0, int(score))), raisons


def calculate_lead_score(lead, property_item):
    return _detail_score(lead, property_item)[0]


def normaliser(txt):
    """Minuscules, sans accents. « Marseille » et « marseille » doivent
    correspondre, tout comme « Bécon » et « Becon »."""
    if not txt:
        return ""
    t = unicodedata.normalize("NFD", txt.lower())
    return "".join(c for c in t if unicodedata.category(c) != "Mn").strip()


def ville_de(secteur):
    """« Paris 15 » -> « paris ». « Lyon » -> « lyon »."""
    mots = [m for m in normaliser(secteur).split() if not m.isdigit()]
    return " ".join(mots)


# Une adresse française écrit « 75015 Paris », jamais « Paris 15 ».
# Sans cette conversion, l'arrondissement exact ne serait jamais reconnu.
PREFIXES_ARRONDISSEMENT = {"paris": "750", "lyon": "690", "marseille": "130"}


def code_postal_arrondissement(secteur):
    """« Paris 15 » -> « 75015 ». Renvoie None si non applicable."""
    mots = normaliser(secteur).split()
    chiffres = [m for m in mots if m.isdigit()]
    ville = " ".join(m for m in mots if not m.isdigit())
    prefixe = PREFIXES_ARRONDISSEMENT.get(ville)
    if not prefixe or not chiffres:
        return None
    return prefixe + chiffres[0].zfill(2)


def score_localisation(lead, prop):
    """Renvoie (points, exclu).

    La localisation est le seul critère éliminatoire du calcul. Un budget
    et un type qui correspondent ne rattrapent pas une ville à 750 km.
    """
    secteur = lead.get("location")
    adresse = prop.get("address")

    # Sans secteur déclaré, on ne pénalise pas : le prospect est ouvert.
    if not secteur or not adresse:
        return 8, False

    a = normaliser(adresse)
    ville = ville_de(secteur)

    if ville not in a:
        return 0, True

    s = normaliser(secteur)
    if s == ville:
        return 20, False

    cp = code_postal_arrondissement(secteur)
    if (cp and cp in a) or s in a:
        return 20, False       # arrondissement exact
    return 15, False           # bonne ville, autre arrondissement
# ===== ROUTES API LEADS & PROPERTIES =====

@app.route('/api/v1/leads', methods=['GET'])
@token_required
def get_leads():
    """Retourner les leads de l'utilisateur connecté"""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT id, name, email, phone, budget, location, property_type, status,
                   financing_status, purchase_urgency, source, created_at,
                   (SELECT MIN(r.due_date) FROM lead_reminders r
                     WHERE r.lead_id = leads.id AND r.done_at IS NULL) AS next_reminder
            FROM leads WHERE user_id = %s ORDER BY id
        """, (request.user_id,))
        leads = cur.fetchall()
        cur.close()
        conn.close()
        for lead in leads:
            lead['lead_quality'] = derive_lead_quality(lead)
            lead['next_reminder'] = _iso(lead['next_reminder'])
        return jsonify(leads), 200
    except Exception:
        return erreur_interne()
@app.route('/api/v1/leads', methods=['POST'])
@token_required
def create_lead():
    """Créer un prospect.

    user_id vient de la session, jamais du corps de la requête. Une page
    web est modifiable par celui qui la consulte : accepter un user_id
    envoyé par le navigateur permettrait d'écrire dans la base d'une
    autre agence.
    """
    try:
        data = request.get_json(silent=True) or {}

        nom = (data.get('name') or '').strip()
        if not nom:
            return jsonify({"message": "Le nom du prospect est obligatoire"}), 400

        # Le budget arrive en texte depuis un formulaire. Une valeur
        # illisible ne doit pas faire tomber la requête : on la traite
        # comme non renseignée.
        budget = _entier_borne(data.get('budget'))

        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        reste, forfait = _reste(cur, request.user_id, 'leads')
        if reste == 0:
            conn.close()
            return _refus_quota('leads', forfait)
        cur.execute("""
            INSERT INTO leads
                (user_id, name, email, phone, budget, location, property_type,
                 status, financing_status, purchase_urgency, source)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'nouveau', %s, %s, %s)
            RETURNING id, name, email, phone, budget, location, property_type,
                      status, financing_status, purchase_urgency, source
        """, (
            request.user_id,
            nom[:255],
            _texte_court(data.get('email'), 255),
            _texte_court(data.get('phone'), 20),
            budget,
            _texte_court(data.get('location'), 255),
            _texte_court(data.get('property_type'), 100),
            _choix(data.get('financing_status'), FINANCING_VALUES),
            _choix(data.get('purchase_urgency'), URGENCY_VALUES),
            _choix(data.get('source'), SOURCES, 'manuel')
        ))
        lead = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()

        lead['lead_quality'] = derive_lead_quality(lead)
        _lancer_en_arriere_plan(_alertes_matching, request.user_id, [lead['id']], None)
        return jsonify(lead), 201
    except Exception:
        return erreur_interne()

@app.route('/api/v1/properties', methods=['GET'])
@token_required
def get_properties():
    """Retourner les propriétés de l'utilisateur"""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, title, address, price, size, rooms, property_type, description FROM properties WHERE user_id = %s ORDER BY id", (request.user_id,))
        properties = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify(properties), 200
    except Exception:
        return erreur_interne()
@app.route('/api/v1/properties', methods=['POST'])
@token_required
def create_property():
    """Ajouter un bien au portefeuille.

    user_id vient de la session, jamais du corps de la requête : une page
    web est modifiable par celui qui la consulte, et accepter un user_id
    envoyé par le navigateur permettrait d'écrire dans le portefeuille
    d'une autre agence.
    """
    try:
        data = request.get_json(silent=True) or {}

        titre = (data.get('title') or '').strip()
        if not titre:
            return jsonify({"message": "Le titre du bien est obligatoire"}), 400

        # Les nombres arrivent en texte depuis un formulaire. Une valeur
        # illisible est traitée comme non renseignée plutôt que de faire
        # échouer toute la requête.
        def entier(cle):
            return _entier_borne(data.get(cle))

        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        reste, forfait = _reste(cur, request.user_id, 'properties')
        if reste == 0:
            conn.close()
            return _refus_quota('properties', forfait)
        cur.execute("""
            INSERT INTO properties
                (user_id, title, address, price, size, rooms, property_type, description)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, title, address, price, size, rooms, property_type, description
        """, (
            request.user_id,
            titre[:255],
            _texte_court(data.get('address'), 255),
            entier('price'),
            entier('size'),
            entier('rooms'),
            _texte_court(data.get('property_type'), 100),
            _texte_court(data.get('description'), 5000)
        ))
        bien = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()

        _lancer_en_arriere_plan(_alertes_matching, request.user_id, None, [bien['id']])
        return jsonify(bien), 201
    except Exception:
        return erreur_interne()

@app.route('/api/v1/stats', methods=['GET'])
@token_required
def get_stats():
    """Retourner les statistiques"""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT 
                (SELECT COUNT(*) FROM leads WHERE user_id = %s) as total_leads,
                (SELECT COUNT(*) FROM properties WHERE user_id = %s) as total_properties,
                (SELECT COUNT(DISTINCT name) FROM leads WHERE user_id = %s) as unique_leads
        """, (request.user_id, request.user_id, request.user_id))
        stats = cur.fetchone()
        cur.close()
        conn.close()
        return jsonify(stats), 200
    except Exception:
        return erreur_interne()


@app.route('/api/v1/leads/<int:lead_id>', methods=['GET'])
@token_required
def get_lead_detail(lead_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, user_id, name, email, phone, budget, location, property_type, status, financing_status, purchase_urgency, lead_quality, financing_amount, notes, created_at, source, status_changed_at, first_contact_at, consent_at FROM leads WHERE id = %s AND user_id = %s", (lead_id, request.user_id))
        lead = cur.fetchone()
        cur.close()
        conn.close()
        if not lead:
            return jsonify({"message": "Lead not found"}), 404
        return jsonify(lead), 200
    except Exception:
        return erreur_interne()


@app.route('/api/v1/leads/<int:lead_id>/update-financing', methods=['PUT'])
@token_required
def update_lead_financing(lead_id):
    """Mettre à jour une fiche prospect.

    lead_quality n'est volontairement pas modifiable : elle est déduite du
    financement, de l'échéance et de la complétude du dossier par
    derive_lead_quality(). L'agent renseigne les faits, l'outil en tire le
    classement.
    """
    try:
        data = request.get_json(silent=True) or {}
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            UPDATE leads SET
                budget = %s,
                location = %s,
                property_type = %s,
                financing_status = %s,
                purchase_urgency = %s,
                financing_amount = %s,
                notes = %s
            WHERE id = %s AND user_id = %s
        """, (
            _entier_borne(data.get('budget')),
            _texte_court(data.get('location'), 255),
            _texte_court(data.get('property_type'), 100),
            _choix(data.get('financing_status'), FINANCING_VALUES),
            _choix(data.get('purchase_urgency'), URGENCY_VALUES),
            _entier_borne(data.get('financing_amount')),
            _texte_court(data.get('notes'), 2000),
            lead_id,
            request.user_id
        ))
        modifiees = cur.rowcount
        conn.commit()
        cur.close()
        conn.close()

        # rowcount à zéro signifie que la fiche n'existe pas OU qu'elle
        # appartient à une autre agence. On ne distingue pas les deux cas
        # dans la réponse : révéler qu'un identifiant existe ailleurs
        # renseignerait sur les données d'un autre compte.
        if modifiees == 0:
            return jsonify({"message": "Lead not found"}), 404

        return jsonify({"message": "Lead updated successfully"}), 200
    except Exception:
        return erreur_interne()


@app.route('/api/v1/leads/quality/<quality>', methods=['GET'])
@token_required
def get_leads_by_quality(quality):
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, name, email, phone, budget, location, property_type, financing_status, purchase_urgency FROM leads WHERE user_id = %s ORDER BY created_at DESC", (request.user_id,))
        leads = cur.fetchall()
        cur.close()
        conn.close()
        # Le filtre s'applique sur la qualité déduite, pas sur la colonne.
        filtered = [l for l in leads if derive_lead_quality(l) == quality]
        for lead in filtered:
            lead['lead_quality'] = quality
        return jsonify(filtered), 200
    except Exception:
        return erreur_interne()


@app.route('/api/v1/improved-matches', methods=['GET'])
@token_required
def get_improved_matches():
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, name, email, phone, budget, location, property_type, financing_status, purchase_urgency FROM leads WHERE user_id = %s ORDER BY created_at DESC", (request.user_id,))
        leads = cur.fetchall()
        cur.execute("SELECT id, title, address, price, rooms, size, property_type, description FROM properties WHERE user_id = %s", (request.user_id,))
        properties = cur.fetchall()
        cur.close()
        conn.close()
        result = []
        for lead in leads:
            matches = []
            for prop in properties:
                score, raisons = _detail_score(lead, prop)
                if score > 30:
                    matches.append({"property_id": prop['id'], "address": prop['address'], "title": prop['title'], "type": prop['property_type'], "price": prop['price'], "rooms": prop['rooms'], "size": prop['size'], "score": score, "reasons": raisons})
            matches.sort(key=lambda x: x['score'], reverse=True)
            result.append({"id": lead['id'], "name": lead['name'], "email": lead['email'], "phone": lead['phone'], "budget": lead['budget'], "location": lead['location'], "property_type": lead['property_type'], "financing_status": lead['financing_status'], "purchase_urgency": lead['purchase_urgency'], "lead_quality": derive_lead_quality(lead), "matches": matches})
        # Les leads les plus chauds d'abord.
        ordre = {'hot': 0, 'warm': 1, 'cold': 2}
        result.sort(key=lambda x: ordre.get(x['lead_quality'], 3))
        return jsonify(result), 200
    except Exception:
        return erreur_interne()

# ===== SUIVI DES PROSPECTS =====

@contextmanager
def _base():
    """Connexion et curseur (lignes sous forme de dictionnaires), toujours
    refermés. Sans commit explicite, rien n'est enregistré."""
    conn = get_db_connection()
    try:
        yield conn, conn.cursor(cursor_factory=RealDictCursor)
    finally:
        conn.close()


def _iso(valeur):
    """Date ou heure en texte ISO, que tous les navigateurs savent lire.
    Les heures sont en UTC : on ajoute le Z pour que le navigateur les
    convertisse dans le fuseau de l'agent."""
    if valeur is None:
        return None
    if isinstance(valeur, datetime):
        return valeur.isoformat() + 'Z'
    return valeur.isoformat()


def _aujourdhui():
    """La date du jour à Paris : une relance « aujourd'hui » ne doit pas
    basculer à 2 h du matin. Repli sur UTC si les fuseaux sont absents."""
    try:
        from zoneinfo import ZoneInfo
        return datetime.now(ZoneInfo("Europe/Paris")).date()
    except Exception:
        return datetime.utcnow().date()


def _date_valide(valeur):
    """Date AAAA-MM-JJ raisonnable (un an en arrière, cinq ans devant), sinon None."""
    try:
        d = date.fromisoformat(str(valeur or '')[:10])
    except ValueError:
        return None
    aujourdhui = _aujourdhui()
    if d < aujourdhui - timedelta(days=366) or d > aujourdhui + timedelta(days=366 * 5):
        return None
    return d


def _site_url():
    return (os.getenv("FRONTEND_URL") or "").strip().rstrip("/")


@app.route('/api/v1/leads/<int:lead_id>', methods=['DELETE'])
@token_required
def delete_lead(lead_id):
    """Supprimer un prospect avec ses notes, relances et alertes (droit à
    l'effacement). L'appartenance au compte est vérifiée dans la requête."""
    try:
        with _base() as (conn, cur):
            cur.execute("DELETE FROM leads WHERE id = %s AND user_id = %s", (lead_id, request.user_id))
            supprimes = cur.rowcount
            conn.commit()
        if supprimes == 0:
            return jsonify({"message": "Lead not found"}), 404
        return jsonify({"message": "Prospect supprimé"}), 200
    except Exception:
        return erreur_interne()


@app.route('/api/v1/leads/<int:lead_id>/status', methods=['PUT'])
@token_required
def update_lead_status(lead_id):
    """Faire avancer un prospect dans le suivi. Le changement est aussi
    inscrit dans l'historique, et la première sortie de « nouveau » date le
    premier contact (utilisé pour le délai de réponse du tableau de bord)."""
    try:
        data = request.get_json(silent=True) or {}
        nouveau = data.get('status')
        if nouveau not in STATUTS:
            return jsonify({"message": "Statut inconnu"}), 400
        with _base() as (conn, cur):
            cur.execute("SELECT status FROM leads WHERE id = %s AND user_id = %s FOR UPDATE",
                        (lead_id, request.user_id))
            ligne = cur.fetchone()
            if not ligne:
                return jsonify({"message": "Lead not found"}), 404
            ancien = ligne['status'] if ligne['status'] in STATUTS else 'nouveau'
            if ancien != nouveau:
                maintenant = _maintenant()
                # Les dates du prospect utilisent l'horloge de la base, comme
                # created_at : la différence entre les deux (délai de première
                # réponse) reste juste quel que soit le fuseau du serveur.
                cur.execute("""
                    UPDATE leads SET status = %s, status_changed_at = NOW(),
                        first_contact_at = CASE WHEN %s <> 'nouveau'
                                                THEN COALESCE(first_contact_at, NOW())
                                                ELSE first_contact_at END
                    WHERE id = %s AND user_id = %s
                """, (nouveau, nouveau, lead_id, request.user_id))
                cur.execute("""
                    INSERT INTO lead_notes (lead_id, user_id, kind, body, created_at)
                    VALUES (%s, %s, 'statut', %s, %s)
                """, (lead_id, request.user_id,
                      f"{STATUTS_LIBELLES[ancien]} → {STATUTS_LIBELLES[nouveau]}", maintenant))
                conn.commit()
        return jsonify({"status": nouveau}), 200
    except Exception:
        return erreur_interne()


@app.route('/api/v1/leads/<int:lead_id>/notes', methods=['GET'])
@token_required
def get_lead_notes(lead_id):
    """L'historique d'un prospect : notes de l'agent et changements de statut."""
    try:
        with _base() as (conn, cur):
            cur.execute("SELECT 1 FROM leads WHERE id = %s AND user_id = %s", (lead_id, request.user_id))
            if not cur.fetchone():
                return jsonify({"message": "Lead not found"}), 404
            cur.execute("""
                SELECT id, kind, body, created_at FROM lead_notes
                WHERE lead_id = %s AND user_id = %s
                ORDER BY created_at DESC, id DESC LIMIT 200
            """, (lead_id, request.user_id))
            notes = cur.fetchall()
        for n in notes:
            n['created_at'] = _iso(n['created_at'])
        return jsonify(notes), 200
    except Exception:
        return erreur_interne()


@app.route('/api/v1/leads/<int:lead_id>/notes', methods=['POST'])
@token_required
def add_lead_note(lead_id):
    try:
        data = request.get_json(silent=True) or {}
        texte = _texte_court(data.get('body'), 2000)
        if not texte:
            return jsonify({"message": "La note est vide"}), 400
        with _base() as (conn, cur):
            cur.execute("SELECT 1 FROM leads WHERE id = %s AND user_id = %s", (lead_id, request.user_id))
            if not cur.fetchone():
                return jsonify({"message": "Lead not found"}), 404
            cur.execute("""
                INSERT INTO lead_notes (lead_id, user_id, kind, body, created_at)
                VALUES (%s, %s, 'note', %s, %s)
                RETURNING id, kind, body, created_at
            """, (lead_id, request.user_id, texte, _maintenant()))
            note = cur.fetchone()
            conn.commit()
        note['created_at'] = _iso(note['created_at'])
        return jsonify(note), 201
    except Exception:
        return erreur_interne()


@app.route('/api/v1/leads/<int:lead_id>/notes/<int:note_id>', methods=['DELETE'])
@token_required
def delete_lead_note(lead_id, note_id):
    """Seules les notes écrites à la main se suppriment : l'historique des
    changements de statut reste intact."""
    try:
        with _base() as (conn, cur):
            cur.execute("""
                DELETE FROM lead_notes
                WHERE id = %s AND lead_id = %s AND user_id = %s AND kind = 'note'
            """, (note_id, lead_id, request.user_id))
            supprimees = cur.rowcount
            conn.commit()
        if supprimees == 0:
            return jsonify({"message": "Note not found"}), 404
        return jsonify({"message": "Note supprimée"}), 200
    except Exception:
        return erreur_interne()


def _rappel_json(r):
    r['due_date'] = _iso(r['due_date'])
    r['done_at'] = _iso(r.get('done_at'))
    r.pop('created_at', None)
    return r


@app.route('/api/v1/leads/<int:lead_id>/reminders', methods=['GET'])
@token_required
def get_lead_reminders(lead_id):
    try:
        with _base() as (conn, cur):
            cur.execute("SELECT 1 FROM leads WHERE id = %s AND user_id = %s", (lead_id, request.user_id))
            if not cur.fetchone():
                return jsonify({"message": "Lead not found"}), 404
            cur.execute("""
                SELECT id, lead_id, due_date, label, done_at, created_at FROM lead_reminders
                WHERE lead_id = %s AND user_id = %s
                ORDER BY (done_at IS NOT NULL), due_date, id LIMIT 200
            """, (lead_id, request.user_id))
            rappels = cur.fetchall()
        return jsonify([_rappel_json(r) for r in rappels]), 200
    except Exception:
        return erreur_interne()


@app.route('/api/v1/leads/<int:lead_id>/reminders', methods=['POST'])
@token_required
def add_lead_reminder(lead_id):
    try:
        data = request.get_json(silent=True) or {}
        echeance = _date_valide(data.get('due_date'))
        if echeance is None:
            return jsonify({"message": "Date de relance invalide"}), 400
        libelle = _texte_court(data.get('label'), 255) or "Relancer"
        with _base() as (conn, cur):
            cur.execute("SELECT 1 FROM leads WHERE id = %s AND user_id = %s", (lead_id, request.user_id))
            if not cur.fetchone():
                return jsonify({"message": "Lead not found"}), 404
            cur.execute("SELECT COUNT(*) AS n FROM lead_reminders WHERE lead_id = %s AND done_at IS NULL", (lead_id,))
            if cur.fetchone()['n'] >= 50:
                return jsonify({"message": "Trop de relances en attente sur ce prospect"}), 400
            cur.execute("""
                INSERT INTO lead_reminders (lead_id, user_id, due_date, label, created_at)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id, lead_id, due_date, label, done_at, created_at
            """, (lead_id, request.user_id, echeance, libelle, _maintenant()))
            rappel = cur.fetchone()
            conn.commit()
        return jsonify(_rappel_json(rappel)), 201
    except Exception:
        return erreur_interne()


@app.route('/api/v1/reminders/<int:reminder_id>', methods=['PUT'])
@token_required
def update_reminder(reminder_id):
    """Marquer une relance faite (done: true) ou la rouvrir (done: false)."""
    try:
        data = request.get_json(silent=True) or {}
        if not isinstance(data.get('done'), bool):
            return jsonify({"message": "Valeur « done » attendue (true ou false)"}), 400
        with _base() as (conn, cur):
            cur.execute("""
                UPDATE lead_reminders SET done_at = %s WHERE id = %s AND user_id = %s
                RETURNING id, lead_id, due_date, label, done_at, created_at
            """, (_maintenant() if data['done'] else None, reminder_id, request.user_id))
            rappel = cur.fetchone()
            conn.commit()
        if not rappel:
            return jsonify({"message": "Reminder not found"}), 404
        return jsonify(_rappel_json(rappel)), 200
    except Exception:
        return erreur_interne()


@app.route('/api/v1/reminders/<int:reminder_id>', methods=['DELETE'])
@token_required
def delete_reminder(reminder_id):
    try:
        with _base() as (conn, cur):
            cur.execute("DELETE FROM lead_reminders WHERE id = %s AND user_id = %s", (reminder_id, request.user_id))
            supprimes = cur.rowcount
            conn.commit()
        if supprimes == 0:
            return jsonify({"message": "Reminder not found"}), 404
        return jsonify({"message": "Relance supprimée"}), 200
    except Exception:
        return erreur_interne()


@app.route('/api/v1/reminders', methods=['GET'])
@token_required
def get_open_reminders():
    """Toutes les relances à faire, les plus urgentes d'abord, avec le nom du
    prospect. Alimente la liste « À faire » du tableau de bord."""
    try:
        with _base() as (conn, cur):
            cur.execute("""
                SELECT r.id, r.lead_id, r.due_date, r.label, r.done_at, r.created_at,
                       l.name AS lead_name, l.status AS lead_status
                FROM lead_reminders r JOIN leads l ON l.id = r.lead_id
                WHERE r.user_id = %s AND r.done_at IS NULL
                ORDER BY r.due_date, r.id LIMIT 200
            """, (request.user_id,))
            rappels = cur.fetchall()
        aujourdhui = _aujourdhui()
        resultat = []
        for r in rappels:
            echeance = r['due_date']
            r = _rappel_json(r)
            r['en_retard'] = echeance < aujourdhui
            resultat.append(r)
        return jsonify(resultat), 200
    except Exception:
        return erreur_interne()


# ===== IMPORT ET FORMULAIRE DE CONTACT =====

MAX_LIGNES_IMPORT = 300


def _chiffres(tel):
    return re.sub(r'\D', '', tel or '')


@app.route('/api/v1/leads/import', methods=['POST'])
@limiter.limit("20 per hour", key_func=_cle_utilisateur)
@token_required
def import_leads():
    """Importer des prospects (lignes déjà lues par le navigateur).

    Un prospect dont l'e-mail ou le téléphone existe déjà est ignoré : on
    peut réimporter le même fichier sans créer de doublons. Le navigateur
    envoie le fichier par paquets de MAX_LIGNES_IMPORT lignes.
    """
    try:
        data = request.get_json(silent=True) or {}
        lignes = data.get('rows')
        if not isinstance(lignes, list) or not lignes:
            return jsonify({"message": "Aucune ligne à importer"}), 400
        if len(lignes) > MAX_LIGNES_IMPORT:
            return jsonify({"message": f"{MAX_LIGNES_IMPORT} lignes maximum par envoi"}), 400
        decalage = data.get('offset') if isinstance(data.get('offset'), int) and 0 <= data.get('offset') < 1_000_000 else 0

        importes, doublons, invalides, ids, hors_forfait = 0, 0, [], [], 0
        with _base() as (conn, cur):
            reste, forfait = _reste(cur, request.user_id, 'leads')
            if reste == 0:
                return _refus_quota('leads', forfait)
            cur.execute("SELECT lower(email) AS e, phone, lower(name) AS n FROM leads WHERE user_id = %s",
                        (request.user_id,))
            emails, telephones, noms_seuls = set(), set(), set()
            for r in cur.fetchall():
                if r['e']:
                    emails.add(r['e'])
                if len(_chiffres(r['phone'])) >= 6:
                    telephones.add(_chiffres(r['phone']))
                if not r['e'] and len(_chiffres(r['phone'])) < 6:
                    noms_seuls.add(r['n'])

            for i, ligne in enumerate(lignes):
                numero = decalage + i + 1
                if not isinstance(ligne, dict):
                    invalides.append({"ligne": numero, "raison": "Ligne illisible"})
                    continue
                nom = _texte_court(ligne.get('name'), 255)
                if not nom:
                    invalides.append({"ligne": numero, "raison": "Nom manquant"})
                    continue
                email = (_texte_court(ligne.get('email'), 255) or '').lower() or None
                if email and not EMAIL_RE.match(email):
                    invalides.append({"ligne": numero, "raison": "Adresse e-mail invalide"})
                    continue
                tel = _texte_court(ligne.get('phone'), 20)
                chiffres = _chiffres(tel)
                sans_contact = not email and len(chiffres) < 6
                if ((email and email in emails) or (len(chiffres) >= 6 and chiffres in telephones)
                        or (sans_contact and nom.lower() in noms_seuls)):
                    doublons += 1
                    continue
                if reste is not None and importes >= reste:
                    hors_forfait += 1
                    continue
                cur.execute("""
                    INSERT INTO leads (user_id, name, email, phone, budget, location, property_type,
                                       status, financing_status, purchase_urgency, source)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, 'nouveau', %s, %s, 'import')
                    RETURNING id
                """, (request.user_id, nom, email, tel,
                      _entier_borne(ligne.get('budget')),
                      _texte_court(ligne.get('location'), 255),
                      _texte_court(ligne.get('property_type'), 100),
                      _choix(ligne.get('financing_status'), FINANCING_VALUES),
                      _choix(ligne.get('purchase_urgency'), URGENCY_VALUES)))
                ids.append(cur.fetchone()['id'])
                importes += 1
                if email:
                    emails.add(email)
                if len(chiffres) >= 6:
                    telephones.add(chiffres)
                if sans_contact:
                    noms_seuls.add(nom.lower())
            conn.commit()

        if ids:
            # Un seul e-mail récapitulatif pour tout l'import.
            _lancer_en_arriere_plan(_alertes_matching, request.user_id, ids, None)
        return jsonify({"imported": importes, "duplicates": doublons, "invalid": invalides[:50],
                        "invalid_count": len(invalides), "over_quota": hors_forfait,
                        "quota_message": (f"Limite du forfait {forfait['label']} atteinte ({_nombre(forfait['limits']['leads'])} prospects) : "
                                          f"{hors_forfait} ligne(s) n'ont pas été importées.") if hors_forfait else None}), 200
    except Exception:
        return erreur_interne()


def _jeton_capture(cur, user_id, regenerer=False):
    cur.execute("SELECT capture_token FROM users WHERE id = %s", (user_id,))
    ligne = cur.fetchone()
    if ligne and ligne['capture_token'] and not regenerer:
        return ligne['capture_token']
    jeton = secrets.token_urlsafe(24)
    cur.execute("UPDATE users SET capture_token = %s WHERE id = %s", (jeton, user_id))
    return jeton


def _lien_formulaire(jeton):
    site = _site_url()
    return f"{site}/formulaire.html?a={jeton}" if site else None


@app.route('/api/v1/capture-link', methods=['GET'])
@token_required
def get_capture_link():
    """L'adresse du formulaire de contact de l'agence, créée au premier appel."""
    try:
        with _base() as (conn, cur):
            jeton = _jeton_capture(cur, request.user_id)
            conn.commit()
        return jsonify({"token": jeton, "url": _lien_formulaire(jeton)}), 200
    except Exception:
        return erreur_interne()


@app.route('/api/v1/capture-link/regenerate', methods=['POST'])
@limiter.limit("10 per hour", key_func=_cle_utilisateur)
@token_required
def regenerate_capture_link():
    """Nouvelle adresse : l'ancienne cesse de fonctionner (en cas de spam ou de fuite)."""
    try:
        with _base() as (conn, cur):
            jeton = _jeton_capture(cur, request.user_id, regenerer=True)
            conn.commit()
        return jsonify({"token": jeton, "url": _lien_formulaire(jeton)}), 200
    except Exception:
        return erreur_interne()


# ===== ADRESSE DE CAPTURE MAIL (LEBONCOIN / SELOGER) =====
# Chaque agent reçoit une adresse personnelle du type <jeton>@leads.zelyro.fr.
# Il configure un transfert depuis sa boîte mail (ou redirige directement les
# notifications leboncoin/SeLoger vers cette adresse) ; le webhook plus bas
# reconnaît l'agence à partir de cette adresse et crée le prospect.

ALPHABET_JETON_MAIL = "abcdefghjkmnpqrstuvwxyz23456789"  # sans i, l, o, 0, 1 (ambigus)
JETON_MAIL_RE = re.compile(r'^[a-z2-9]{8,16}$')


def _domaine_capture_mail():
    return (os.getenv("LEADS_INBOUND_DOMAIN") or "leads.zelyro.fr").strip().lower()


def _nouveau_jeton_mail():
    return ''.join(secrets.choice(ALPHABET_JETON_MAIL) for _ in range(10))


def _jeton_capture_mail(cur, user_id, regenerer=False):
    cur.execute("SELECT mail_capture_token FROM users WHERE id = %s", (user_id,))
    ligne = cur.fetchone()
    if ligne and ligne['mail_capture_token'] and not regenerer:
        return ligne['mail_capture_token']
    jeton = _nouveau_jeton_mail()
    cur.execute("UPDATE users SET mail_capture_token = %s WHERE id = %s", (jeton, user_id))
    return jeton


def _adresse_capture_mail(jeton):
    return f"{jeton}@{_domaine_capture_mail()}"


@app.route('/api/v1/mail-capture', methods=['GET'])
@token_required
def get_mail_capture():
    """L'adresse e-mail personnelle vers laquelle transférer les notifications
    LeBonCoin et SeLoger, créée au premier appel."""
    try:
        with _base() as (conn, cur):
            jeton = _jeton_capture_mail(cur, request.user_id)
            conn.commit()
        return jsonify({"token": jeton, "address": _adresse_capture_mail(jeton)}), 200
    except Exception:
        return erreur_interne()


@app.route('/api/v1/mail-capture/regenerate', methods=['POST'])
@limiter.limit("10 per hour", key_func=_cle_utilisateur)
@token_required
def regenerate_mail_capture():
    """Nouvelle adresse : l'ancienne cesse de fonctionner (en cas de messages indésirables)."""
    try:
        with _base() as (conn, cur):
            jeton = _jeton_capture_mail(cur, request.user_id, regenerer=True)
            conn.commit()
        return jsonify({"token": jeton, "address": _adresse_capture_mail(jeton)}), 200
    except Exception:
        return erreur_interne()


JETON_RE = re.compile(r'^[A-Za-z0-9_-]{16,64}$')
FINANCEMENT_FORMULAIRE = {'approved', 'in_progress', 'unknown'}


@app.route('/public/capture/<token>', methods=['GET'])
def capture_info(token):
    """Nom de l'agence à afficher en haut du formulaire public."""
    try:
        if not JETON_RE.match(token):
            return jsonify({"message": "Not found"}), 404
        _assurer_schema()
        with _base() as (conn, cur):
            cur.execute("SELECT company_name FROM users WHERE capture_token = %s AND is_active", (token,))
            ligne = cur.fetchone()
        if not ligne:
            return jsonify({"message": "Not found"}), 404
        return jsonify({"agence": ligne['company_name'] or ""}), 200
    except Exception:
        return erreur_interne()


def _cle_jeton():
    return "cap:" + str((request.view_args or {}).get('token', ''))[:64]


@app.route('/public/capture/<token>', methods=['POST'])
@limiter.limit("10 per hour")
@limiter.limit("60 per hour", key_func=_cle_jeton)
def capture_lead(token):
    """Un visiteur du site d'une agence remplit le formulaire : le prospect
    arrive directement dans la liste de l'agence.

    La page est publique par nature : elle n'a pas de session. Le jeton de
    l'agence désigne le compte, jamais un identifiant envoyé par le
    navigateur. Le consentement est obligatoire et daté ; un champ caché
    (« website ») piège les robots qui remplissent tout.
    """
    try:
        if not JETON_RE.match(token):
            return jsonify({"message": "Not found"}), 404
        data = request.get_json(silent=True) or {}
        if data.get('website'):
            return jsonify({"message": "Merci, votre demande a bien été envoyée."}), 201

        nom = _texte_court(data.get('name'), 255)
        if not nom:
            return jsonify({"message": "Indiquez votre nom."}), 400
        email = (_texte_court(data.get('email'), 255) or '').lower() or None
        if email and not EMAIL_RE.match(email):
            return jsonify({"message": "Cette adresse e-mail semble invalide."}), 400
        tel = _texte_court(data.get('phone'), 20)
        if not email and not tel:
            return jsonify({"message": "Indiquez un e-mail ou un téléphone pour être recontacté."}), 400
        if data.get('consent') is not True:
            return jsonify({"message": "Veuillez accepter d'être recontacté pour envoyer votre demande."}), 400
        message = _texte_court(data.get('message'), 1000)

        _assurer_schema()
        with _base() as (conn, cur):
            cur.execute("SELECT id FROM users WHERE capture_token = %s AND is_active", (token,))
            agence = cur.fetchone()
            if not agence:
                return jsonify({"message": "Not found"}), 404
            reste, _ = _reste(cur, agence['id'], 'leads')
            if reste == 0:
                return jsonify({"message": "Ce formulaire n'est pas disponible pour le moment. "
                                           "Merci de contacter directement l'agence."}), 503
            maintenant = _maintenant()
            cur.execute("""
                INSERT INTO leads (user_id, name, email, phone, budget, location, property_type,
                                   status, financing_status, purchase_urgency, source, consent_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, 'nouveau', %s, %s, 'formulaire', %s)
                RETURNING id
            """, (agence['id'], nom, email, tel,
                  _entier_borne(data.get('budget')),
                  _texte_court(data.get('location'), 255),
                  _texte_court(data.get('property_type'), 100),
                  _choix(data.get('financing_status'), FINANCEMENT_FORMULAIRE),
                  _choix(data.get('purchase_urgency'), URGENCY_VALUES),
                  maintenant))
            lead_id = cur.fetchone()['id']
            if message:
                cur.execute("""
                    INSERT INTO lead_notes (lead_id, user_id, kind, body, created_at)
                    VALUES (%s, %s, 'note', %s, %s)
                """, (lead_id, agence['id'], "Message du formulaire : " + message, maintenant))
            conn.commit()

        _lancer_en_arriere_plan(_alertes_matching, agence['id'], [lead_id], None, 'formulaire')
        return jsonify({"message": "Merci, votre demande a bien été envoyée."}), 201
    except Exception:
        return erreur_interne()


# ===== ALERTES E-MAIL =====

# Formulation de l'e-mail d'alerte selon l'origine du nouveau prospect.
ORIGINE_NOUVEAU_PROSPECT = {
    'formulaire': ("Nouveau prospect via votre formulaire",
                   "vient de remplir le formulaire de contact de votre agence."),
    'leboncoin': ("Nouveau prospect via LeBonCoin",
                  "vous a contacté via une annonce LeBonCoin, capté automatiquement par Zelyro."),
    'seloger': ("Nouveau prospect via SeLoger",
                "vous a contacté via une annonce SeLoger, capté automatiquement par Zelyro."),
    'portail': ("Nouveau prospect par e-mail",
                "vous a contacté par e-mail, capté automatiquement par Zelyro."),
}


def _alertes_matching(user_id, lead_ids=None, property_ids=None, origine=None):
    """Prévient l'agent par e-mail quand un bien correspond à un prospect.

    Appelée après la réponse (thread), à la création d'un bien, d'un
    prospect, d'un import ou d'un formulaire. Une correspondance n'est
    signalée qu'une fois (table match_alerts), et les prospects signés ou
    perdus sont laissés de côté. Sans configuration d'e-mail ou si l'agent
    a coupé les alertes, la fonction ne fait rien.
    """
    try:
        if not _envoi_configure():
            return
        _assurer_schema()
        with _base() as (conn, cur):
            cur.execute("SELECT email, alerts_enabled FROM users WHERE id = %s", (user_id,))
            agent = cur.fetchone()
            if not agent or not agent['alerts_enabled']:
                return
            cur.execute("""SELECT id, name, email, phone, budget, location, property_type,
                                  financing_status, purchase_urgency, status
                           FROM leads WHERE user_id = %s""", (user_id,))
            prospects = [l for l in cur.fetchall() if (l['status'] or 'nouveau') not in STATUTS_CLOS]
            cur.execute("SELECT id, title, address, price, property_type FROM properties WHERE user_id = %s", (user_id,))
            biens = cur.fetchall()

            ids_prospects, ids_biens = set(lead_ids or []), set(property_ids or [])
            paires = []
            for l in prospects:
                for b in biens:
                    if l['id'] in ids_prospects or b['id'] in ids_biens:
                        score, raisons = _detail_score(l, b)
                        if score >= ALERTE_SCORE_MIN:
                            paires.append((score, l, b, raisons))
            if paires:
                cur.execute("SELECT lead_id, property_id FROM match_alerts WHERE lead_id = ANY(%s)",
                            (list({p[1]['id'] for p in paires}),))
                deja = {(r['lead_id'], r['property_id']) for r in cur.fetchall()}
                paires = [p for p in paires if (p[1]['id'], p[2]['id']) not in deja]

            nouveau = None
            if origine in ORIGINE_NOUVEAU_PROSPECT:
                nouveau = next((l for l in prospects if l['id'] in ids_prospects), None)
            if not paires and not nouveau:
                return
            paires.sort(key=lambda p: -p[0])

            site = _site_url()
            paragraphes = []
            if nouveau:
                titre, phrase = ORIGINE_NOUVEAU_PROSPECT[origine]
                sujet = f"Nouveau prospect : {nouveau['name'][:80]}"
                paragraphes.append(f"{nouveau['name']} {phrase}")
                contact = " · ".join(x for x in (nouveau['email'], nouveau['phone']) if x)
                if contact:
                    paragraphes.append(f"Contact : {contact}")
                recherche = " · ".join(x for x in (
                    nouveau['property_type'], nouveau['location'],
                    f"budget {nouveau['budget']:,} €".replace(',', ' ') if nouveau['budget'] else None) if x)
                if recherche:
                    paragraphes.append(f"Recherche : {recherche}")
                bouton = ("Ouvrir la fiche du prospect", f"{site}/leads-profile.html?id={nouveau['id']}")
                if paires:
                    paragraphes.append("Des biens de votre portefeuille lui correspondent :")
            else:
                n = len(paires)
                titre = "Des biens correspondent à vos prospects"
                sujet = "Zelyro : 1 correspondance trouvée" if n == 1 else f"Zelyro : {n} correspondances trouvées"
                paragraphes.append("Zelyro a trouvé de nouvelles correspondances entre vos prospects et vos biens :")
                bouton = ("Voir mes correspondances", f"{site}/matching.html")
            for score, l, b, raisons in paires[:10]:
                ligne = f"{l['name']} ↔ {b['title']} ({score}/100)"
                if raisons:
                    ligne += " : " + ", ".join(raisons[:3])
                paragraphes.append(ligne)
            if len(paires) > 10:
                paragraphes.append(f"… et {len(paires) - 10} autre(s) correspondance(s) à retrouver dans Zelyro.")
            paragraphes.append("Vous pouvez désactiver ces e-mails depuis la page « Mon compte ».")

            texte, html = _gabarit_email(titre, paragraphes, bouton)
            if _envoyer_email(agent['email'], sujet, texte, html) and paires:
                for score, l, b, _ in paires:
                    cur.execute("""INSERT INTO match_alerts (lead_id, property_id, score)
                                   VALUES (%s, %s, %s) ON CONFLICT DO NOTHING""", (l['id'], b['id'], score))
                conn.commit()
    except Exception:
        app.logger.exception("Alertes de correspondance impossibles")


# ===== ACCÈS SUR INVITATION, FORFAITS ET ADMINISTRATION =====

INVITATION_JOURS = 14
_METRIQUES = {
    # métrique : (limite du forfait, ce qu'on compte)
    'leads': ('max_leads', 'prospects'),
    'properties': ('max_properties', 'biens'),
    'mails': ('max_mails_month', 'e-mails par mois'),
    'extractions': ('max_extractions_month', 'extractions par mois'),
}
_LIMITES_PLAN = ('max_leads', 'max_properties', 'max_mails_month', 'max_extractions_month')


def _nombre(n):
    return f"{n:,}".replace(",", " ")


def _debut_mois():
    m = _maintenant()
    return datetime(m.year, m.month, 1)


def _periode():
    return _maintenant().strftime('%Y-%m')


def _forfait(cur, user_id):
    """Le forfait du compte et ses limites (None = illimité). Un forfait
    inconnu retombe sur le plus petit : mieux vaut trop limiter que pas assez."""
    cur.execute("""SELECT u.plan, p.label, p.max_leads, p.max_properties,
                          p.max_mails_month, p.max_extractions_month
                   FROM users u LEFT JOIN plans p ON p.code = u.plan WHERE u.id = %s""", (user_id,))
    r = cur.fetchone()
    if not r or r['label'] is None:
        code, label, a, b, c, d = PLANS_PAR_DEFAUT[0][:6]
        r = {'plan': code, 'label': label, 'max_leads': a, 'max_properties': b,
             'max_mails_month': c, 'max_extractions_month': d}
    return {"code": r['plan'], "label": r['label'],
            "limits": {m: r[col] for m, (col, _) in _METRIQUES.items()}}


def _compter(cur, user_id, metrique):
    if metrique == 'leads':
        cur.execute("SELECT count(*) AS n FROM leads WHERE user_id = %s", (user_id,))
    elif metrique == 'properties':
        cur.execute("SELECT count(*) AS n FROM properties WHERE user_id = %s", (user_id,))
    elif metrique == 'mails':
        cur.execute("SELECT count(*) AS n FROM lead_mails WHERE user_id = %s AND sent_at >= %s",
                    (user_id, _debut_mois()))
    else:
        cur.execute("""SELECT n FROM usage_counters
                       WHERE user_id = %s AND period = %s AND metric = 'extractions'""", (user_id, _periode()))
        ligne = cur.fetchone()
        return ligne['n'] if ligne else 0
    return cur.fetchone()['n']


def _reste(cur, user_id, metrique, verrouiller=True):
    """(reste, forfait) : combien d'éléments le forfait autorise encore (None
    si illimité). Avec verrouiller, les ajouts simultanés d'une même agence
    passent les uns après les autres jusqu'à la fin de la transaction, pour
    qu'un lot de requêtes parallèles ne dépasse pas la limite. Le curseur doit
    renvoyer des dictionnaires."""
    if verrouiller:
        cur.execute("SELECT id FROM users WHERE id = %s FOR UPDATE", (user_id,))
    f = _forfait(cur, user_id)
    limite = f['limits'][metrique]
    if limite is None:
        return None, f
    return max(0, limite - _compter(cur, user_id, metrique)), f


def _refus_quota(metrique, forfait):
    limite = forfait['limits'][metrique]
    nom = _METRIQUES[metrique][1]
    return jsonify({
        "message": (f"Votre forfait {forfait['label']} est limité à {_nombre(limite)} {nom}. "
                    "Contactez Zelyro pour passer au forfait supérieur."),
        "code": "quota", "metric": metrique, "limit": limite,
    }), 403


def _compter_extraction(user_id):
    try:
        with _base() as (conn, cur):
            cur.execute("""INSERT INTO usage_counters (user_id, period, metric, n)
                           VALUES (%s, %s, 'extractions', 1)
                           ON CONFLICT (user_id, period, metric)
                           DO UPDATE SET n = usage_counters.n + 1""", (user_id, _periode()))
            conn.commit()
    except Exception:
        app.logger.exception("Compteur d'extractions non mis à jour")


@app.route('/api/v1/plan', methods=['GET'])
@token_required
def get_plan():
    """Le forfait du compte et ce qui en est déjà consommé."""
    try:
        with _base() as (conn, cur):
            f = _forfait(cur, request.user_id)
            usage = {m: _compter(cur, request.user_id, m) for m in _METRIQUES}
        return jsonify({"plan": {"code": f['code'], "label": f['label']},
                        "limits": f['limits'], "usage": usage}), 200
    except Exception:
        return erreur_interne()


def _journal(cur, action, cible=None, detail=None):
    cur.execute("""INSERT INTO admin_log (admin_email, action, target, detail, created_at)
                   VALUES (%s, %s, %s, %s, %s)""",
                (request.user_email, action, cible, detail, _maintenant()))


@app.route('/admin/overview', methods=['GET'])
@limiter.limit("240 per hour", key_func=_cle_utilisateur)
@admin_required
def admin_overview():
    """Tout ce qu'il faut à la page d'administration : forfaits, comptes et
    leur consommation, invitations en attente, dernières actions."""
    try:
        with _base() as (conn, cur):
            cur.execute("""SELECT code, label, max_leads, max_properties, max_mails_month,
                                  max_extractions_month FROM plans ORDER BY sort_order, code""")
            plans = cur.fetchall()
            cur.execute("""
                SELECT u.id, u.email, u.first_name, u.company_name, u.plan, u.is_active, u.created_at,
                       (SELECT count(*) FROM leads l WHERE l.user_id = u.id) AS leads,
                       (SELECT count(*) FROM properties p WHERE p.user_id = u.id) AS properties,
                       (SELECT count(*) FROM lead_mails m WHERE m.user_id = u.id AND m.sent_at >= %s) AS mails,
                       COALESCE((SELECT c.n FROM usage_counters c WHERE c.user_id = u.id
                                 AND c.period = %s AND c.metric = 'extractions'), 0) AS extractions
                FROM users u ORDER BY u.created_at DESC, u.id DESC
            """, (_debut_mois(), _periode()))
            comptes = cur.fetchall()
            maintenant = _maintenant()
            cur.execute("""SELECT id, email, label, plan, key_hint, invited_by, created_at, expires_at,
                                  used_at, used_email FROM invitations
                           WHERE revoked_at IS NULL
                           ORDER BY created_at DESC, id DESC LIMIT 100""")
            invitations = cur.fetchall()
            cur.execute("""SELECT admin_email, action, target, detail, created_at FROM admin_log
                           ORDER BY id DESC LIMIT 40""")
            journal = cur.fetchall()
        for c in comptes:
            c['created_at'] = _iso(c['created_at'])
            c['is_admin'] = _est_admin(c['email'])
        for i in invitations:
            i['expired'] = i['used_at'] is None and i['expires_at'] <= maintenant
            i['used'] = i['used_at'] is not None
            i['created_at'], i['expires_at'], i['used_at'] = _iso(i['created_at']), _iso(i['expires_at']), _iso(i['used_at'])
        for j in journal:
            j['created_at'] = _iso(j['created_at'])
        return jsonify({"plans": plans, "users": comptes, "invitations": invitations, "log": journal,
                        "mail_possible": bool(_mail_configure() and _site_url()),
                        "invitation_days": INVITATION_JOURS}), 200
    except Exception:
        return erreur_interne()


@app.route('/admin/invitations', methods=['POST'])
@limiter.limit("60 per day", key_func=_cle_utilisateur)
@admin_required
def admin_inviter():
    """Crée une clé d'activation (à usage unique) pour un forfait donné. La clé
    n'est montrée qu'une fois : seule son empreinte est conservée. L'adresse
    e-mail est facultative : si elle est renseignée, la clé ne marche qu'avec
    elle et lui est envoyée par e-mail ; on annule alors sa clé précédente."""
    try:
        data = request.get_json(silent=True) or {}
        email = str(data.get('email') or '').strip().lower()
        label = str(data.get('label') or '').strip()[:120]
        plan = str(data.get('plan') or '')
        if email and (len(email) > 255 or not EMAIL_RE.match(email)):
            return jsonify({"message": "Adresse e-mail invalide"}), 400
        with _base() as (conn, cur):
            cur.execute("SELECT label FROM plans WHERE code = %s", (plan,))
            ligne = cur.fetchone()
            if not ligne:
                return jsonify({"message": "Forfait inconnu"}), 400
            forfait = ligne['label']
            maintenant = _maintenant()
            if email:
                cur.execute("SELECT 1 FROM users WHERE lower(email) = %s", (email,))
                if cur.fetchone():
                    return jsonify({"message": "Un compte existe déjà pour cette adresse"}), 409
                cur.execute("""UPDATE invitations SET revoked_at = %s
                               WHERE lower(email) = %s AND used_at IS NULL AND revoked_at IS NULL""",
                            (maintenant, email))
            cle = _nouvelle_cle()
            expire = maintenant + timedelta(days=INVITATION_JOURS)
            cur.execute("""INSERT INTO invitations (email, label, plan, token_hash, key_hint, invited_by,
                                                    created_at, expires_at)
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id""",
                        (email or None, label or None, plan, _empreinte_cle(cle), cle[-4:],
                         request.user_email, maintenant, expire))
            inv_id = cur.fetchone()['id']
            _journal(cur, 'clé créée', email or label or None, plan)
            conn.commit()

        site = _site_url()
        # La clé est placée après le # : elle n'est ni envoyée au serveur du site ni journalisée.
        lien = f"{site}/login.html#cle={cle}" if site else None
        envoye = False
        if email and _mail_configure():
            paragraphes = ["Bonjour,",
                           "Vous avez été invité(e) à utiliser Zelyro, l'outil qui rapproche vos prospects et vos biens.",
                           f"Votre forfait : {forfait}.",
                           f"Votre clé d'activation : {cle}",
                           f"Elle est personnelle, valable {INVITATION_JOURS} jours et ne sert qu'une fois : "
                           "saisissez-la en bas du formulaire de création de compte, avec cette adresse e-mail."]
            texte, html = _gabarit_email("Votre clé d'activation Zelyro", paragraphes,
                                         ("Créer mon compte", lien) if lien else None)
            envoye = _envoyer_email(email, "Votre clé d'activation Zelyro", texte, html)
        return jsonify({"id": inv_id, "key": cle, "email": email or None, "label": label or None, "plan": plan,
                        "expires_at": _iso(expire), "link": lien, "mail_sent": envoye}), 201
    except Exception:
        return erreur_interne()


@app.route('/admin/invitations/<int:inv_id>', methods=['DELETE'])
@limiter.limit("120 per hour", key_func=_cle_utilisateur)
@admin_required
def admin_annuler_invitation(inv_id):
    try:
        with _base() as (conn, cur):
            cur.execute("""UPDATE invitations SET revoked_at = %s
                           WHERE id = %s AND used_at IS NULL AND revoked_at IS NULL RETURNING email, label""",
                        (_maintenant(), inv_id))
            ligne = cur.fetchone()
            if not ligne:
                return jsonify({"message": "Clé introuvable"}), 404
            _journal(cur, 'clé annulée', ligne['email'] or ligne['label'])
            conn.commit()
        return jsonify({"message": "Clé annulée"}), 200
    except Exception:
        return erreur_interne()


@app.route('/admin/users/<int:user_id>', methods=['PUT'])
@limiter.limit("120 per hour", key_func=_cle_utilisateur)
@admin_required
def admin_modifier_compte(user_id):
    """Change le forfait d'un compte, le suspend ou le réactive. Une
    suspension coupe aussi les sessions ouvertes (et le formulaire de contact)."""
    try:
        data = request.get_json(silent=True) or {}
        with _base() as (conn, cur):
            cur.execute("SELECT id, email, plan, is_active FROM users WHERE id = %s FOR UPDATE", (user_id,))
            compte = cur.fetchone()
            if not compte:
                return jsonify({"message": "Compte introuvable"}), 404
            plan, actif = compte['plan'], compte['is_active']
            if 'plan' in data:
                cur.execute("SELECT 1 FROM plans WHERE code = %s", (data['plan'],))
                if not isinstance(data['plan'], str) or not cur.fetchone():
                    return jsonify({"message": "Forfait inconnu"}), 400
                plan = data['plan']
            if 'is_active' in data:
                if not isinstance(data['is_active'], bool):
                    return jsonify({"message": "« is_active » doit être true ou false"}), 400
                if not data['is_active'] and _est_admin(compte['email']):
                    return jsonify({"message": "Un compte administrateur ne peut pas être suspendu"}), 400
                actif = data['is_active']
            cur.execute("""UPDATE users SET plan = %s, is_active = %s,
                               token_version = token_version + %s WHERE id = %s""",
                        (plan, actif, 1 if (compte['is_active'] and not actif) else 0, user_id))
            if plan != compte['plan']:
                _journal(cur, 'forfait', compte['email'], f"{compte['plan']} → {plan}")
            if actif != compte['is_active']:
                _journal(cur, 'compte réactivé' if actif else 'compte suspendu', compte['email'])
            conn.commit()
        return jsonify({"id": user_id, "plan": plan, "is_active": actif}), 200
    except Exception:
        return erreur_interne()


@app.route('/admin/plans/<code>', methods=['PUT'])
@limiter.limit("120 per hour", key_func=_cle_utilisateur)
@admin_required
def admin_modifier_forfait(code):
    """Règle les limites d'un forfait (null = illimité). Effet immédiat."""
    try:
        data = request.get_json(silent=True) or {}
        sets, valeurs = [], []
        for col in _LIMITES_PLAN:
            if col in data:
                v = data[col]
                if v is not None and (isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= 10_000_000):
                    return jsonify({"message": "Chaque limite est un nombre entier positif, ou vide pour illimité"}), 400
                sets.append(f"{col} = %s")
                valeurs.append(v)
        if 'label' in data:
            libelle = _texte_court(data['label'], 50)
            if not libelle:
                return jsonify({"message": "Le nom du forfait ne peut pas être vide"}), 400
            sets.append("label = %s")
            valeurs.append(libelle)
        if not sets:
            return jsonify({"message": "Rien à modifier"}), 400
        if code == 'illimite':
            return jsonify({"message": "Le forfait Illimité n'est pas modifiable"}), 400
        with _base() as (conn, cur):
            cur.execute(f"UPDATE plans SET {', '.join(sets)} WHERE code = %s RETURNING code", valeurs + [code])
            if not cur.fetchone():
                return jsonify({"message": "Forfait introuvable"}), 404
            _journal(cur, 'forfait modifié', code, ", ".join(f"{k}={data[k]}" for k in list(_LIMITES_PLAN) + ['label'] if k in data))
            conn.commit()
        return jsonify({"message": "Forfait mis à jour"}), 200
    except Exception:
        return erreur_interne()


# ===== PROPOSITIONS DE BIENS PAR E-MAIL =====

# Score minimal (sur 100) pour qu'un bien soit proposé à un prospect, et
# délai pendant lequel on n'écrit pas deux fois au même prospect.
PROPOSITION_SCORE_MIN = int(os.getenv("PROPOSAL_MIN_SCORE", "50"))
MAIL_DELAI_HEURES = 24
_MAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _mail_configure():
    """Vrai si le serveur peut envoyer un e-mail (clé Brevo et expéditeur)."""
    return all((os.getenv(k) or "").strip() for k in ("BREVO_API_KEY", "MAIL_FROM"))


def _prospect_complet(lead):
    """Un prospect est prêt pour une proposition quand on peut le joindre et
    qu'on sait ce qu'il cherche : e-mail valide, budget, et un secteur ou un
    type de bien."""
    email = (lead.get('email') or '').strip()
    return bool(
        _MAIL_RE.match(email) and len(email) <= 255 and lead.get('budget')
        and ((lead.get('location') or '').strip() or (lead.get('property_type') or '').strip())
    )


def _nom_affiche(texte, defaut):
    """Nom d'expéditeur sans caractère qui casserait un en-tête d'e-mail."""
    propre = re.sub(r'[\r\n<>"]+', ' ', str(texte or '')).strip()[:60]
    return propre or defaut


def _corps_html(texte, pied):
    """Le message de l'agent en HTML simple : un paragraphe par bloc, un
    saut de ligne à chaque retour à la ligne, puis le pied de message."""
    blocs = [b.strip() for b in re.split(r"\n\s*\n", texte.strip()) if b.strip()]
    corps = "".join('<p style="margin:0 0 16px;line-height:1.6">'
                    + _html.escape(b).replace("\n", "<br>") + "</p>" for b in blocs)
    return ('<div style="font-family:Arial,Helvetica,sans-serif;color:#1F2A24;max-width:560px;margin:0 auto;padding:24px">'
            + corps
            + '<p style="margin:28px 0 0;padding-top:14px;border-top:1px solid #E3DCCC;color:#6A7168;'
              f'font-size:12px;line-height:1.5">{_html.escape(pied)}</p></div>')


@app.route('/api/v1/proposals', methods=['GET'])
@token_required
def get_proposals():
    """Les prospects à qui l'agent peut envoyer une sélection de biens.

    Un prospect est proposé quand son dossier est complet, qu'il n'est ni
    signé ni perdu, qu'aucun e-mail ne lui a été envoyé ces dernières
    24 heures et qu'au moins un bien qu'on ne lui a pas encore proposé lui
    correspond. Les biens déjà envoyés ne reviennent pas : un bien qui
    arrive plus tard refait apparaître le prospect.
    """
    try:
        with _base() as (conn, cur):
            cur.execute("SELECT first_name, company_name FROM users WHERE id = %s", (request.user_id,))
            agent = cur.fetchone() or {}
            cur.execute("""SELECT id, name, email, phone, budget, location, property_type,
                                  financing_status, purchase_urgency, status
                           FROM leads WHERE user_id = %s""", (request.user_id,))
            prospects = [l for l in cur.fetchall()
                         if (l['status'] or 'nouveau') not in STATUTS_CLOS and _prospect_complet(l)]
            cur.execute("""SELECT id, title, address, price, rooms, size, property_type
                           FROM properties WHERE user_id = %s""", (request.user_id,))
            biens = cur.fetchall()
            cur.execute("""SELECT m.lead_id, l.name, l.email, m.subject, m.property_ids, m.sent_at
                           FROM lead_mails m JOIN leads l ON l.id = m.lead_id
                           WHERE m.user_id = %s ORDER BY m.sent_at DESC, m.id DESC""", (request.user_id,))
            mails = cur.fetchall()

        limite = _maintenant() - timedelta(hours=MAIL_DELAI_HEURES)
        deja, dernier = {}, {}
        for m in mails:
            deja.setdefault(m['lead_id'], set()).update(m['property_ids'] or [])
            dernier.setdefault(m['lead_id'], m['sent_at'])

        a_envoyer = []
        for l in prospects:
            if dernier.get(l['id']) and dernier[l['id']] > limite:
                continue
            candidats = []
            for b in biens:
                if b['id'] in deja.get(l['id'], ()):
                    continue
                score, raisons = _detail_score(l, b)
                if score >= PROPOSITION_SCORE_MIN:
                    candidats.append({"property_id": b['id'], "title": b['title'], "address": b['address'],
                                      "type": b['property_type'], "price": b['price'], "rooms": b['rooms'],
                                      "size": b['size'], "score": score, "reasons": raisons})
            if not candidats:
                continue
            candidats.sort(key=lambda c: -c['score'])
            a_envoyer.append({
                "lead": {"id": l['id'], "name": l['name'], "email": l['email'], "phone": l['phone'],
                         "budget": l['budget'], "location": l['location'], "property_type": l['property_type']},
                "lead_quality": derive_lead_quality(l),
                "biens": candidats[:5],
                "deja_proposes": len(deja.get(l['id'], ())),
            })
        ordre = {'hot': 0, 'warm': 1, 'cold': 2}
        a_envoyer.sort(key=lambda x: (ordre.get(x['lead_quality'], 3), -x['biens'][0]['score']))

        envoyes = [{"lead_id": m['lead_id'], "name": m['name'], "email": m['email'], "subject": m['subject'],
                    "biens": len(m['property_ids'] or []), "sent_at": _iso(m['sent_at'])} for m in mails[:20]]
        return jsonify({
            "envoi_possible": _mail_configure(),
            "agent": {"first_name": agent.get('first_name') or '', "company_name": agent.get('company_name') or ''},
            "a_envoyer": a_envoyer,
            "envoyes": envoyes,
        }), 200
    except Exception:
        return erreur_interne()


@app.route('/api/v1/leads/<int:lead_id>/send-mail', methods=['POST'])
@limiter.limit("30 per hour;150 per day", key_func=_cle_utilisateur)
@token_required
def send_lead_mail(lead_id):
    """Envoie au prospect le message rédigé (et modifié) par l'agent.

    Le destinataire est toujours l'adresse enregistrée sur la fiche du
    prospect, jamais une adresse envoyée par le navigateur. Le message part
    au nom de l'agence, les réponses arrivent directement à l'agent. Le
    prospect est verrouillé pendant l'envoi : un double clic n'envoie qu'un
    seul e-mail.
    """
    try:
        data = request.get_json(silent=True) or {}
        sujet = str(data.get('subject') or '').strip()
        corps = str(data.get('body') or '').replace('\r\n', '\n').strip()
        ids = data.get('property_ids')
        if not 3 <= len(sujet) <= 200 or '\n' in sujet or '\r' in sujet:
            return jsonify({"message": "L'objet doit faire entre 3 et 200 caractères, sur une seule ligne"}), 400
        if not 20 <= len(corps) <= 5000:
            return jsonify({"message": "Le message doit faire entre 20 et 5000 caractères"}), 400
        if (not isinstance(ids, list) or not 1 <= len(ids) <= 10
                or not all(isinstance(i, int) and not isinstance(i, bool) for i in ids)):
            return jsonify({"message": "Choisissez de 1 à 10 biens à proposer"}), 400
        ids = sorted(set(ids))
        if not _mail_configure():
            return jsonify({"message": "L'envoi d'e-mails n'est pas encore configuré sur ce serveur"}), 503

        with _base() as (conn, cur):
            cur.execute("""SELECT id, name, email, status FROM leads
                           WHERE id = %s AND user_id = %s FOR UPDATE""", (lead_id, request.user_id))
            lead = cur.fetchone()
            if not lead:
                return jsonify({"message": "Lead not found"}), 404
            statut = lead['status'] if lead['status'] in STATUTS else 'nouveau'
            if statut in STATUTS_CLOS:
                return jsonify({"message": "Ce prospect est clos (signé ou perdu)"}), 409
            destinataire = (lead['email'] or '').strip()
            if not _MAIL_RE.match(destinataire):
                return jsonify({"message": "Ce prospect n'a pas d'adresse e-mail valide"}), 400
            cur.execute("SELECT id, title FROM properties WHERE user_id = %s AND id = ANY(%s)",
                        (request.user_id, ids))
            biens = cur.fetchall()
            if len(biens) != len(ids):
                return jsonify({"message": "Un des biens choisis n'existe plus"}), 400
            cur.execute("SELECT 1 FROM lead_mails WHERE lead_id = %s AND sent_at > %s LIMIT 1",
                        (lead_id, _maintenant() - timedelta(hours=MAIL_DELAI_HEURES)))
            if cur.fetchone():
                return jsonify({"message": f"Un e-mail a déjà été envoyé à ce prospect il y a moins de {MAIL_DELAI_HEURES} h"}), 409
            reste, forfait = _reste(cur, request.user_id, 'mails', verrouiller=False)
            if reste == 0:
                return _refus_quota('mails', forfait)
            cur.execute("SELECT email, first_name, company_name FROM users WHERE id = %s", (request.user_id,))
            agent = cur.fetchone()

            agence = _nom_affiche(agent['company_name'] or agent['first_name'], "Votre agence")
            pied = (f"Ce message vous est adressé par {agence} dans le cadre de votre recherche immobilière. "
                    "Pour ne plus recevoir de propositions, répondez simplement « STOP » à ce message.")
            texte = corps + "\n\n--\n" + pied
            if not _envoyer_email(destinataire, sujet, texte, _corps_html(corps, pied),
                                  nom_expediteur=agence,
                                  repondre_a=(agent['email'], _nom_affiche(agent['first_name'] or agence, agence))):
                return jsonify({"message": "L'envoi a échoué. Réessayez dans un instant."}), 502

            maintenant = _maintenant()
            cur.execute("""INSERT INTO lead_mails (lead_id, user_id, subject, body, property_ids, sent_at)
                           VALUES (%s, %s, %s, %s, %s, %s)""",
                        (lead_id, request.user_id, sujet, corps, ids, maintenant))
            titres = ", ".join(b['title'] for b in biens)
            cur.execute("""INSERT INTO lead_notes (lead_id, user_id, kind, body, created_at)
                           VALUES (%s, %s, 'note', %s, %s)""",
                        (lead_id, request.user_id,
                         f"E-mail envoyé à {destinataire} : « {sujet} ». Biens proposés : {titres}"[:2000],
                         maintenant))
            if statut == 'nouveau':
                cur.execute("""UPDATE leads SET status = 'contacte', status_changed_at = NOW(),
                                   first_contact_at = COALESCE(first_contact_at, NOW())
                               WHERE id = %s AND user_id = %s""", (lead_id, request.user_id))
                cur.execute("""INSERT INTO lead_notes (lead_id, user_id, kind, body, created_at)
                               VALUES (%s, %s, 'statut', %s, %s)""",
                            (lead_id, request.user_id,
                             f"{STATUTS_LIBELLES['nouveau']} → {STATUTS_LIBELLES['contacte']}", maintenant))
            conn.commit()
        return jsonify({"sent_at": _iso(maintenant), "status": 'contacte' if statut == 'nouveau' else statut}), 200
    except Exception:
        return erreur_interne()


@app.route('/auth/preferences', methods=['PUT'])
@token_required
def update_preferences():
    """Réglages du compte : pour l'instant, les alertes e-mail."""
    try:
        data = request.get_json(silent=True) or {}
        if not isinstance(data.get('alerts_enabled'), bool):
            return jsonify({"message": "Valeur « alerts_enabled » attendue (true ou false)"}), 400
        with _base() as (conn, cur):
            cur.execute("UPDATE users SET alerts_enabled = %s WHERE id = %s", (data['alerts_enabled'], request.user_id))
            conn.commit()
        return jsonify({"alerts_enabled": data['alerts_enabled']}), 200
    except Exception:
        return erreur_interne()


# ===== TABLEAU DE BORD =====

@app.route('/api/v1/dashboard', methods=['GET'])
@token_required
def get_dashboard():
    """Les chiffres utiles à l'agence : où en sont les prospects, d'où ils
    viennent, à quelle vitesse on les contacte et ce qui reste à faire."""
    try:
        with _base() as (conn, cur):
            cur.execute("""SELECT id, status, source, created_at, first_contact_at, budget, location,
                                  property_type, financing_status, purchase_urgency
                           FROM leads WHERE user_id = %s""", (request.user_id,))
            prospects = cur.fetchall()
            cur.execute("""SELECT COUNT(*) AS n FROM properties WHERE user_id = %s""", (request.user_id,))
            nb_biens = cur.fetchone()['n']
            # « Maintenant » sur l'horloge de la base, celle de created_at.
            cur.execute("SELECT NOW()::timestamp AS maintenant")
            maintenant = cur.fetchone()['maintenant']
            aujourdhui = _aujourdhui()
            cur.execute("""SELECT
                    COUNT(*) FILTER (WHERE due_date < %s) AS en_retard,
                    COUNT(*) FILTER (WHERE due_date = %s) AS aujourdhui,
                    COUNT(*) FILTER (WHERE due_date > %s AND due_date <= %s) AS semaine
                FROM lead_reminders WHERE user_id = %s AND done_at IS NULL""",
                        (aujourdhui, aujourdhui, aujourdhui, aujourdhui + timedelta(days=7), request.user_id))
            rappels = cur.fetchone()

        pipeline = {s: 0 for s in STATUTS}
        qualite = {'hot': 0, 'warm': 0, 'cold': 0}
        sources = {}
        delais, recents, a_contacter = [], 0, 0
        for p in prospects:
            statut = p['status'] if p['status'] in STATUTS else 'nouveau'
            pipeline[statut] += 1
            if statut not in STATUTS_CLOS:
                qualite[derive_lead_quality(p)] += 1
            source = p['source'] if p['source'] in SOURCES else 'manuel'
            sources[source] = sources.get(source, 0) + 1
            if p['created_at'] and p['first_contact_at']:
                delta = (p['first_contact_at'] - p['created_at']).total_seconds() / 3600
                if delta >= 0:
                    delais.append(delta)
            if p['created_at'] and p['created_at'] >= maintenant - timedelta(days=30):
                recents += 1
            if statut == 'nouveau' and p['created_at'] and p['created_at'] < maintenant - timedelta(days=2):
                a_contacter += 1

        total = len(prospects)
        return jsonify({
            "total_leads": total,
            "total_properties": nb_biens,
            "pipeline": pipeline,
            "quality": qualite,
            "sources": sources,
            "new_last_30_days": recents,
            "to_contact": a_contacter,
            "avg_first_response_hours": round(sum(delais) / len(delais), 1) if delais else None,
            "conversion_rate": round(100 * pipeline['signe'] / total) if total else None,
            "reminders": {"overdue": rappels['en_retard'], "today": rappels['aujourdhui'],
                          "this_week": rappels['semaine']},
        }), 200
    except Exception:
        return erreur_interne()


# ===== EXTRACTION DEPUIS UN MESSAGE LIBRE =====

import json as _json
import requests

# Les seules valeurs que la base accepte. Un modèle de langage produit du
# texte : sans cette liste, il finira par renvoyer "appartement" ou
# "T3" un jour où l'autre, et la comparaison avec la base échouera en
# silence.
BALISE = chr(96) * 3          # trois accents graves
TYPES_BIEN = ['Appartement', 'Maison', 'Villa', 'Studio', 'Penthouse', 'Terrain']
ECHEANCES = ['immediate', '1-3_months', '3-6_months', '6plus_months']
FINANCEMENTS = ['approved', 'in_progress', 'pending', 'rejected']

CONSIGNE = """Tu es un assistant pour une agence immobilière. Extrais les \
informations du message et réponds UNIQUEMENT en JSON, sans commentaire ni \
texte autour.

Date du jour : {date}

Champs : nom, email, telephone, transaction, budget, secteurs, type_bien, \
nombre_pieces, echeance, financement, garants, profession, notes

Règles strictes :
- N'invente jamais. Information non explicite dans le message = null.
- transaction : "achat", "location" ou null. Si le message mentionne des \
garants, des revenus ou un loyer, c'est une location.
- secteurs : TABLEAU de noms de communes. "Lille ou Marcq" devient \
["Lille","Marcq"]. null si aucun secteur.
- type_bien : exactement l'un de {types}, ou null.
- telephone : chiffres uniquement, sans espaces ni points.
- budget : entier en euros. Pour une location, le loyer mensuel.
- echeance : l'un de {echeances}, ou null. Calcule par rapport à la date du jour.
- financement : l'un de {financements}, ou null.
- garants : nombre de garants mentionnés, ou null.
- profession : situation professionnelle citée, ou null.
- notes : une phrase résumant ce qui n'entre dans aucun champ, ou null.

Message :
{message}"""


def _entier(v):
    """Le modèle renvoie parfois "280 000" ou "280000 euros"."""
    if v in (None, '', 'null'):
        return None
    if isinstance(v, int):
        return v
    try:
        return int(''.join(c for c in str(v) if c.isdigit()) or 0) or None
    except (TypeError, ValueError):
        return None


def _valider(brut):
    """Ne garde que ce qui est utilisable.

    Un modèle de langage produit du texte libre : tout ce qui sort d'ici
    est traité comme non fiable jusqu'à vérification. Une valeur hors
    liste est ramenée à null plutôt que d'être écrite en base, où elle
    casserait le rapprochement sans qu'on s'en aperçoive.
    """
    def texte(cle, maxlen=255):
        v = brut.get(cle)
        if not v or not isinstance(v, str):
            return None
        v = v.strip()
        return v[:maxlen] if v and v.lower() != 'null' else None

    def dans(cle, valeurs):
        """Comparaison insensible à la casse.

        Le modèle renvoie parfois "appartement" au lieu de "Appartement".
        L'information est juste : la rejeter pour une majuscule reviendrait
        à perdre un champ correct. En revanche, une valeur absente de la
        liste reste écartée — c'est ce qui protège la base.
        """
        v = brut.get(cle)
        if not isinstance(v, str):
            return None
        v = v.strip().lower()
        for attendu in valeurs:
            if v == attendu.lower():
                return attendu
        return None

    tel = texte('telephone', 30)
    if tel:
        tel = ''.join(c for c in tel if c.isdigit())
        tel = tel or None

    secteurs = brut.get('secteurs')
    if isinstance(secteurs, str):
        secteurs = [secteurs]
    if not isinstance(secteurs, list):
        secteurs = []
    secteurs = [s.strip() for s in secteurs if isinstance(s, str) and s.strip()][:5]

    return {
        'nom': texte('nom', 120),
        'email': texte('email', 200),
        'telephone': tel,
        'transaction': dans('transaction', ['achat', 'location']),
        'budget': _entier(brut.get('budget')),
        # La base ne stocke qu'un secteur : on garde le premier et on
        # signale les autres dans les notes plutôt que de les perdre.
        'secteur': secteurs[0] if secteurs else None,
        'secteurs_secondaires': secteurs[1:] if len(secteurs) > 1 else [],
        'type_bien': dans('type_bien', TYPES_BIEN),
        'nombre_pieces': _entier(brut.get('nombre_pieces')),
        'echeance': dans('echeance', ECHEANCES),
        'financement': dans('financement', FINANCEMENTS),
        'garants': _entier(brut.get('garants')),
        'profession': texte('profession', 120),
        'notes': texte('notes', 1000),
    }


def _appeler_extraction_ia(consigne):
    """Appelle Claude Haiku avec `consigne` et renvoie les champs validés.

    (champs, None) en cas de succès ; (None, (message, code_http)) sinon. Ce
    que renvoie le modèle est toujours traité comme non fiable : voir
    _valider. Suppose que la clé ANTHROPIC_API_KEY est déjà vérifiée présente
    par l'appelant.
    """
    cle = (os.getenv('ANTHROPIC_API_KEY') or '').strip()
    texte = ''
    try:
        r = requests.post(
            'https://api.anthropic.com/v1/messages',
            headers={
                'content-type': 'application/json',
                'x-api-key': cle,
                'anthropic-version': '2023-06-01',
            },
            json={
                'model': 'claude-haiku-4-5-20251001',
                'max_tokens': 1000,
                'messages': [{'role': 'user', 'content': consigne}],
            },
            timeout=30,
        )
        if r.status_code != 200:
            print(f"Erreur API extraction : {r.status_code} {r.text[:200]}")
            # On renvoie le code de l'API en amont : sans lui, il faut aller
            # dans les logs du serveur pour distinguer une clé invalide d'un
            # manque de crédit.
            return None, (f"Service d'extraction indisponible (code {r.status_code})", 502)
        texte = ''.join(
            bloc.get('text', '') for bloc in r.json().get('content', [])
        ).strip()

        # Le modèle encadre parfois sa réponse de balises de code.
        # BALISE est construit par chr() plutôt qu'écrit littéralement :
        # trois accents graves dans un fichier Python collé depuis un
        # document markdown coupent le bloc de code à cet endroit.
        if texte.startswith(BALISE):
            texte = texte.split(BALISE)[1]
            if texte.startswith('json'):
                texte = texte[4:]
            texte = texte.strip()

        brut = _json.loads(texte)

    except _json.JSONDecodeError:
        print(f"Réponse non JSON : {texte[:200]}")
        return None, ("Réponse du modèle illisible", 502)
    except requests.Timeout:
        return None, ("Délai dépassé, réessayez", 504)
    except Exception:
        app.logger.exception("Appel d'extraction impossible")
        return None, ("Erreur interne du serveur", 500)

    return _valider(brut), None


@app.route('/api/v1/extract', methods=['POST'])
@limiter.limit("30 per hour;200 per day", key_func=_cle_utilisateur)
@token_required
def extract_message():
    """Extraire des critères d'un message écrit en langage naturel."""
    # Une clé collée dans une interface web emporte souvent un espace ou
    # un retour à la ligne invisible, que l'API rejette avec un 401.
    cle = (os.getenv('ANTHROPIC_API_KEY') or '').strip()
    if not cle:
        return jsonify({"message": "Extraction non configurée sur le serveur"}), 503

    data = request.get_json(silent=True) or {}
    message = (data.get('message') or '').strip()
    if len(message) < 10:
        return jsonify({"message": "Message trop court pour être analysé"}), 400
    message = message[:8000]

    try:
        with _base() as (conn, cur):
            reste, forfait = _reste(cur, request.user_id, 'extractions', verrouiller=False)
        if reste == 0:
            return _refus_quota('extractions', forfait)
    except Exception:
        return erreur_interne()

    consigne = CONSIGNE.format(
        date=datetime.utcnow().strftime('%Y-%m-%d'),
        types=', '.join(TYPES_BIEN),
        echeances=', '.join(ECHEANCES),
        financements=', '.join(FINANCEMENTS),
        message=message,
    )

    champs, erreur = _appeler_extraction_ia(consigne)
    if erreur:
        return jsonify({"message": erreur[0]}), erreur[1]
    _compter_extraction(request.user_id)

    # Les secteurs qui ne tiennent pas dans la fiche rejoignent les notes :
    # un agent doit pouvoir voir que le prospect cherche aussi ailleurs.
    if champs['secteurs_secondaires']:
        mention = "Cherche aussi : " + ', '.join(champs['secteurs_secondaires'])
        champs['notes'] = f"{champs['notes']} — {mention}" if champs['notes'] else mention

    # Ce que l'agent doit savoir avant d'enregistrer.
    remplis = sum(1 for k, v in champs.items()
                  if k != 'secteurs_secondaires' and v not in (None, [], ''))
    champs['_champs_remplis'] = remplis
    champs['_message_source'] = message[:2000]

    return jsonify(champs), 200


# ===== RÉCEPTION AUTOMATIQUE DES LEADS (E-MAIL LEBONCOIN / SELOGER) =====
# Un agent transfère (ou redirige) vers son adresse de capture les
# notifications de contact que lui envoient leboncoin et SeLoger ; Brevo
# (Inbound Parsing) relaie chaque e-mail reçu sur le domaine dédié à ce
# webhook, qui identifie l'agence et crée le prospect automatiquement.
# Aucune des deux plateformes n'offre d'API publique pour ça : c'est
# l'approche qu'utilisent en pratique les CRM immobiliers indépendants.

CONSIGNE_PORTAIL = """Tu es un assistant pour une agence immobilière. Voici un e-mail de \
notification envoyé par {portail} quand quelqu'un contacte l'agence au sujet d'une annonce. \
Extrais les informations du contact et réponds UNIQUEMENT en JSON, sans commentaire ni texte \
autour.

Date du jour : {date}

Champs : nom, email, telephone, transaction, budget, secteurs, type_bien, nombre_pieces, \
echeance, financement, garants, profession, notes

Règles strictes :
- N'invente jamais. Information non explicite dans le message = null.
- Le nom, l'email et le téléphone sont ceux du CONTACT (l'acheteur ou locataire potentiel), \
jamais ceux de l'agence ni du portail.
- Ignore les mentions légales, liens de désinscription et signatures automatiques du portail.
- transaction : "achat", "location" ou null.
- secteurs : TABLEAU de noms de communes mentionnées, [] si aucune.
- type_bien : exactement l'un de {types}, ou null.
- telephone : chiffres uniquement, sans espaces ni points.
- budget : entier en euros si un montant est explicitement mentionné, sinon null.
- echeance : l'un de {echeances}, ou null.
- financement : l'un de {financements}, ou null.
- garants : nombre de garants mentionnés, ou null.
- profession : situation professionnelle citée, ou null.
- notes : le message du contact et l'annonce concernée (titre, référence ou adresse) si \
identifiable, résumés en une ou deux phrases. null si rien d'utile.

E-mail :
{message}"""

_PORTAIL_LIBELLE = {'leboncoin': 'LeBonCoin', 'seloger': 'SeLoger'}
_PORTAIL_NOM_DEFAUT = {'leboncoin': 'Contact LeBonCoin', 'seloger': 'Contact SeLoger',
                       'portail': 'Contact (e-mail transféré)'}


def _source_portail(adresse_expediteur):
    domaine = (adresse_expediteur or '').rsplit('@', 1)[-1].lower()
    if 'leboncoin' in domaine:
        return 'leboncoin'
    if 'seloger' in domaine:
        return 'seloger'
    return 'portail'


_BALISE_HTML_RE = re.compile(r'<[a-zA-Z!/][^>]{0,200}>')


def _deshtmliser(brut):
    """HTML -> texte lisible, en gardant les liens : un e-mail de confirmation
    (Gmail, Outlook...) affiche un texte court sur le lien ("cliquez ici") alors
    que l'URL utile est dans le href. La stripper sans la garder rendrait le
    lien de confirmation inutilisable une fois affiché dans les notes."""
    if not brut:
        return ''
    texte = re.sub(r'(?is)<(script|style)[^>]*>.*?</\1>', ' ', brut)
    texte = re.sub(
        r'(?is)<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>',
        lambda m: f"{re.sub(r'(?s)<[^>]+>', ' ', m.group(2)).strip()} ({m.group(1)})",
        texte,
    )
    texte = re.sub(r'(?s)<[^>]+>', ' ', texte)
    texte = _html.unescape(texte)
    return re.sub(r'\s+', ' ', texte).strip()


def _corps_texte_email(item):
    """Le texte le plus propre disponible : Brevo nettoie déjà signatures et
    citations dans ExtractedMarkdownMessage. À défaut, le texte brut, puis en
    dernier recours le HTML débarrassé de ses balises (en gardant les liens).
    Certains expéditeurs (dont les e-mails de confirmation Gmail/Outlook) ne
    fournissent pas d'alternative texte propre : ExtractedMarkdownMessage ou
    RawTextBody contiennent alors du HTML brut qu'il faut nettoyer aussi."""
    for cle in ('ExtractedMarkdownMessage', 'RawTextBody'):
        v = item.get(cle)
        if v and str(v).strip():
            v = str(v).strip()
            # Certains envois (dont les e-mails Gmail/Outlook) livrent ce champ
            # avec les balises HTML échappées ("&lt;html&gt;...") plutôt qu'en
            # clair : on déséchappe avant de tester, sinon la détection de
            # balises ci-dessous ne voit jamais rien à nettoyer.
            v_visible = _html.unescape(v)
            if _BALISE_HTML_RE.search(v_visible):
                return _deshtmliser(v_visible)
            return v_visible
    return _deshtmliser(item.get('RawHtmlBody') or '')


def _adresse_capture_dans(destinataires):
    """L'adresse de capture Zelyro parmi les destinataires de l'e-mail, ou
    None. Un e-mail transféré porte souvent plusieurs destinataires."""
    domaine = '@' + _domaine_capture_mail()
    for d in (destinataires or []):
        if not isinstance(d, dict):
            continue
        adresse = (d.get('Address') or '').strip().lower()
        if adresse.endswith(domaine):
            return adresse
    return None


def _traiter_email_entrant(item):
    """Transforme un e-mail entrant (notification LeBonCoin/SeLoger transférée
    par un agent) en prospect. Ne lève jamais : une erreur reste dans les
    journaux, un e-mail malformé ne doit pas faire échouer les autres."""
    message_id = _texte_court(item.get('MessageId'), 255)
    adresse_capture = _adresse_capture_dans(item.get('To'))
    if not adresse_capture:
        return
    jeton = adresse_capture.split('@', 1)[0]
    if not JETON_MAIL_RE.match(jeton):
        return

    _assurer_schema()
    with _base() as (conn, cur):
        if message_id:
            cur.execute("SELECT id FROM inbound_emails WHERE message_id = %s", (message_id,))
            if cur.fetchone():
                return
        cur.execute("SELECT id FROM users WHERE mail_capture_token = %s AND is_active", (jeton,))
        agence = cur.fetchone()
        if not agence:
            return
        user_id = agence['id']

        expediteur = ((item.get('From') or {}).get('Address') or '').strip()
        portail = _source_portail(expediteur)
        sujet = _texte_court(item.get('Subject'), 255) or ''
        corps = _corps_texte_email(item)[:6000]

        reste_leads, _ = _reste(cur, user_id, 'leads')
        if reste_leads == 0:
            if message_id:
                cur.execute("""INSERT INTO inbound_emails (message_id, user_id, source, received_at)
                               VALUES (%s, %s, %s, %s) ON CONFLICT (message_id) DO NOTHING""",
                            (message_id, user_id, portail, _maintenant()))
            conn.commit()
            return

        champs = None
        extraction_effectuee = False
        if corps and len(corps) >= 10 and (os.getenv('ANTHROPIC_API_KEY') or '').strip():
            reste_extr, _ = _reste(cur, user_id, 'extractions', verrouiller=False)
            if reste_extr != 0:
                consigne = CONSIGNE_PORTAIL.format(
                    portail=_PORTAIL_LIBELLE.get(portail, "un portail d'annonces"),
                    date=datetime.utcnow().strftime('%Y-%m-%d'),
                    types=', '.join(TYPES_BIEN), echeances=', '.join(ECHEANCES),
                    financements=', '.join(FINANCEMENTS), message=corps[:4000],
                )
                valides, erreur = _appeler_extraction_ia(consigne)
                if erreur:
                    app.logger.warning("Extraction e-mail entrant : %s", erreur[0])
                else:
                    champs = valides
                    extraction_effectuee = True

        nom = (champs or {}).get('nom')
        if not nom and expediteur and EMAIL_RE.match(expediteur):
            nom = expediteur.split('@', 1)[0].replace('.', ' ').replace('_', ' ').title()
        nom = nom or _PORTAIL_NOM_DEFAUT.get(portail, 'Contact')

        notes = (champs or {}).get('notes')
        if not champs and corps:
            notes = corps[:900]
        if sujet and (not notes or sujet.lower() not in notes.lower()):
            notes = f"{sujet} — {notes}" if notes else sujet

        email_contact = (champs or {}).get('email')
        if not email_contact and expediteur and EMAIL_RE.match(expediteur) and 'noreply' not in expediteur.lower():
            email_contact = expediteur

        cur.execute("""
            INSERT INTO leads
                (user_id, name, email, phone, budget, location, property_type,
                 status, financing_status, purchase_urgency, source)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'nouveau', %s, %s, %s)
            RETURNING id
        """, (
            user_id, nom[:255],
            _texte_court(email_contact, 255),
            (champs or {}).get('telephone'),
            (champs or {}).get('budget'),
            _texte_court((champs or {}).get('secteur'), 255),
            (champs or {}).get('type_bien'),
            _choix((champs or {}).get('financement'), FINANCING_VALUES),
            _choix((champs or {}).get('echeance'), URGENCY_VALUES),
            portail,
        ))
        lead_id = cur.fetchone()['id']
        if notes:
            cur.execute("""INSERT INTO lead_notes (lead_id, user_id, kind, body, created_at)
                           VALUES (%s, %s, 'note', %s, %s)""",
                        (lead_id, user_id, notes[:1000], _maintenant()))
        if message_id:
            cur.execute("""INSERT INTO inbound_emails (message_id, user_id, source, lead_id, received_at)
                           VALUES (%s, %s, %s, %s, %s) ON CONFLICT (message_id) DO NOTHING""",
                        (message_id, user_id, portail, lead_id, _maintenant()))
        conn.commit()

    # Après la fermeture de la transaction ci-dessus : _compter_extraction
    # ouvre sa propre connexion, et l'appeler pendant que la transaction
    # tient encore le verrou FOR UPDATE sur la ligne de l'agence (posé par
    # _reste ci-dessus) la ferait attendre indéfiniment sur elle-même.
    if extraction_effectuee:
        _compter_extraction(user_id)
    _lancer_en_arriere_plan(_alertes_matching, user_id, [lead_id], None, portail)


@app.route('/webhooks/email-inbound', methods=['POST'])
@limiter.limit("300 per hour")
def email_inbound():
    """Point d'entrée pour Brevo (Inbound Parsing) : un agent a transféré ou
    redirigé une notification LeBonCoin/SeLoger vers son adresse de capture
    Zelyro, et Brevo nous relaie l'e-mail. Protégé par un jeton secret dans
    l'URL, Brevo ne signant pas ses appels."""
    secret = (os.getenv('EMAIL_INBOUND_SECRET') or '').strip()
    cle_recue = request.args.get('cle') or ''
    if not secret or not secrets.compare_digest(cle_recue, secret):
        return jsonify({"message": "Not found"}), 404
    data = request.get_json(silent=True) or {}
    items = data.get('items')
    if not isinstance(items, list):
        items = [data] if data.get('MessageId') else []
    traites = 0
    for item in items:
        try:
            if isinstance(item, dict):
                _traiter_email_entrant(item)
                traites += 1
        except Exception:
            app.logger.exception("E-mail entrant : échec de traitement")
    return jsonify({"received": len(items), "processed": traites}), 200


if __name__ == '__main__':
    if sys.argv[1:2] == ['init-db']:
        init_database(demo='--demo' in sys.argv)
    else:
        print(f"🚀 Backend running on http://localhost:{PORT}")
        app.run(host='0.0.0.0', port=PORT, debug=False)
