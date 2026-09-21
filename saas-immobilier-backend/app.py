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
SOURCES = {'manuel', 'import', 'formulaire', 'extraction'}
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
                       to_regclass('match_alerts') IS NOT NULL
            """)
            if not all(cur.fetchone()):
                cur.execute("SELECT pg_advisory_xact_lock(727301)")
                for ddl in _DDL_COMPTES + _DDL_SUIVI:
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
                cur.execute("SELECT token_version FROM users WHERE id = %s", (current_user_id,))
                ligne = cur.fetchone()
            finally:
                conn.close()
        except Exception:
            return erreur_interne()
        if ligne is None:
            return jsonify({"message": "Invalid token"}), 401
        if int(data.get('v', 0)) != ligne[0]:
            return jsonify({"message": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated

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
        for ddl in _DDL_COMPTES + _DDL_SUIVI:
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


@app.route('/auth/register', methods=['POST'])
@limiter.limit("10 per hour")
def register():
    """Enregistrer un nouvel utilisateur"""
    data = request.get_json(silent=True) or {}
    email = str(data.get('email') or '').strip().lower()
    password = data.get('password')
    first_name = str(data.get('first_name') or '').strip()[:100]
    company_name = str(data.get('company_name') or '').strip()[:255]

    if not email or not password:
        return jsonify({"message": "Email and password required"}), 400
    if len(email) > 255 or not EMAIL_RE.match(email):
        return jsonify({"message": "Adresse email invalide"}), 400
    if not isinstance(password, str) or len(password) < 10:
        return jsonify({"message": "Le mot de passe doit contenir au moins 10 caractères"}), 400
    if len(password) > 128:
        return jsonify({"message": "Mot de passe trop long (128 caractères maximum)"}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id FROM users WHERE lower(email) = %s", (email,))
        if cur.fetchone():
            cur.close()
            conn.close()
            return jsonify({"message": "User already exists"}), 409

        password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        cur.execute(
            "INSERT INTO users (email, password_hash, first_name, company_name) VALUES (%s, %s, %s, %s) RETURNING id",
            (email, password_hash, first_name, company_name)
        )
        user_id = cur.fetchone()['id']
        conn.commit()

        token = create_access_token(identity={'id': user_id, 'email': email}, expires=timedelta(hours=TOKEN_LIFETIME_HOURS))

        cur.close()
        conn.close()

        return jsonify({
            "message": "User created successfully",
            "token": token,
            "user": {
                "id": user_id,
                "email": email,
                "first_name": first_name,
                "company_name": company_name
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
        cur.execute("SELECT id, email, password_hash, first_name, company_name, token_version FROM users WHERE lower(email) = %s", (email,))
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

        token = create_access_token(identity={'id': user['id'], 'email': user['email'], 'v': user['token_version']}, expires=timedelta(hours=TOKEN_LIFETIME_HOURS))

        return jsonify({
            "message": "Login successful",
            "token": token,
            "user": {
                "id": user['id'],
                "email": user['email'],
                "first_name": user['first_name'],
                "company_name": user['company_name']
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


def _envoyer_email(destinataire, sujet, texte, html):
    """Envoie un e-mail via Brevo. Renvoie True si l'envoi est accepté."""
    cle = (os.getenv("BREVO_API_KEY") or "").strip()
    expediteur = (os.getenv("MAIL_FROM") or "").strip()
    if not cle or not expediteur:
        app.logger.warning("E-mail non envoyé : BREVO_API_KEY ou MAIL_FROM non défini")
        return False
    try:
        r = requests.post(
            BREVO_URL,
            headers={"api-key": cle, "content-type": "application/json", "accept": "application/json"},
            json={
                "sender": {"name": os.getenv("MAIL_FROM_NAME", "Zelyro"), "email": expediteur},
                "to": [{"email": destinataire}],
                "subject": sujet,
                "textContent": texte,
                "htmlContent": html,
            },
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
            cur.execute("SELECT id, email FROM users WHERE lower(email) = %s", (email,))
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
        cur.execute("SELECT id, email, first_name, company_name, created_at, alerts_enabled FROM users WHERE id = %s", (request.user_id,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if not user:
            return jsonify({"message": "User not found"}), 404

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

        importes, doublons, invalides, ids = 0, 0, [], []
        with _base() as (conn, cur):
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
                        "invalid_count": len(invalides)}), 200
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
            cur.execute("SELECT company_name FROM users WHERE capture_token = %s", (token,))
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
            cur.execute("SELECT id FROM users WHERE capture_token = %s", (token,))
            agence = cur.fetchone()
            if not agence:
                return jsonify({"message": "Not found"}), 404
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
            if origine == 'formulaire':
                nouveau = next((l for l in prospects if l['id'] in ids_prospects), None)
            if not paires and not nouveau:
                return
            paires.sort(key=lambda p: -p[0])

            site = _site_url()
            paragraphes = []
            if nouveau:
                titre = "Nouveau prospect via votre formulaire"
                sujet = f"Nouveau prospect : {nouveau['name'][:80]}"
                paragraphes.append(f"{nouveau['name']} vient de remplir le formulaire de contact de votre agence.")
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

    consigne = CONSIGNE.format(
        date=datetime.utcnow().strftime('%Y-%m-%d'),
        types=', '.join(TYPES_BIEN),
        echeances=', '.join(ECHEANCES),
        financements=', '.join(FINANCEMENTS),
        message=message,
    )

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
                        # On renvoie le code de l'API en amont : sans lui, il faut
            # aller dans les logs du serveur pour distinguer une clé
            # invalide d'un manque de crédit.
            return jsonify({
                "message": f"Service d'extraction indisponible (code {r.status_code})"
            }), 502
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
        return jsonify({"message": "Réponse du modèle illisible"}), 502
    except requests.Timeout:
        return jsonify({"message": "Délai dépassé, réessayez"}), 504
    except Exception:
        return erreur_interne()

    champs = _valider(brut)

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
if __name__ == '__main__':
    if sys.argv[1:2] == ['init-db']:
        init_database(demo='--demo' in sys.argv)
    else:
        print(f"🚀 Backend running on http://localhost:{PORT}")
        app.run(host='0.0.0.0', port=PORT, debug=False)
