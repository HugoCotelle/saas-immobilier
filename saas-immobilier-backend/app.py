from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
import jwt
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
    methods=["GET", "POST", "PUT", "OPTIONS"],
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
        'exp': datetime.utcnow() + expires,
        'iat': datetime.utcnow()
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token

def get_db_connection():
    """Obtenir une connexion à la base de données"""
    conn = psycopg2.connect(DATABASE_URL)
    return conn

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
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, email, password_hash, first_name, company_name FROM users WHERE lower(email) = %s", (email,))
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

        token = create_access_token(identity={'id': user['id'], 'email': user['email']}, expires=timedelta(hours=TOKEN_LIFETIME_HOURS))

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

@app.route('/auth/profile', methods=['GET'])
@token_required
def get_profile():
    """Récupérer le profil de l'utilisateur connecté"""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, email, first_name, company_name, created_at FROM users WHERE id = %s", (request.user_id,))
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


def calculate_lead_score(lead, property_item):
    score = 0
    if lead['budget']:
        price_diff = abs(property_item['price'] - lead['budget'])
        budget_ratio = price_diff / lead['budget']
        if budget_ratio < 0.05:
            score += 20
        elif budget_ratio < 0.10:
            score += 18
        elif budget_ratio < 0.15:
            score += 15
        elif budget_ratio < 0.20:
            score += 12
        elif budget_ratio < 0.30:
            score += 8

    if lead.get('property_type') == property_item.get('property_type'):
        score += 30
    elif lead.get('property_type') in ['Appartement', 'Maison'] and property_item.get('property_type') in ['Appartement', 'Maison']:
        score += 15

    # La localisation est le seul critère éliminatoire : un budget et un
    # type qui collent ne rattrapent pas une ville à 750 km.
    points_loc, hors_secteur = score_localisation(lead, property_item)
    if hors_secteur:
        return 0
    score += points_loc

    financing_status = lead.get('financing_status', 'unknown')
    if financing_status == 'approved':
        score += 20
    elif financing_status == 'in_progress':
        score += 15
    elif financing_status == 'pending':
        score += 10
    else:
        score += 5

    urgency = lead.get('purchase_urgency', 'unknown')
    if urgency == 'immediate':
        score += 15
    elif urgency == '1-3_months':
        score += 12
    elif urgency == '3-6_months':
        score += 8
    elif urgency == '6plus_months':
        score += 4
    else:
        score += 5

    # Le multiplicateur par lead_quality a été retiré : le financement et
    # l'urgence sont déjà comptés ci-dessus, les réappliquer les comptait
    # deux fois.
    return min(100, max(0, int(score)))
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
        cur.execute("SELECT id, name, email, phone, budget, location, property_type, status, financing_status, purchase_urgency FROM leads WHERE user_id = %s ORDER BY id", (request.user_id,))
        leads = cur.fetchall()
        cur.close()
        conn.close()
        for lead in leads:
            lead['lead_quality'] = derive_lead_quality(lead)
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
                 status, financing_status, purchase_urgency)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'nouveau', %s, %s)
            RETURNING id, name, email, phone, budget, location, property_type,
                      status, financing_status, purchase_urgency
        """, (
            request.user_id,
            nom[:255],
            _texte_court(data.get('email'), 255),
            _texte_court(data.get('phone'), 20),
            budget,
            _texte_court(data.get('location'), 255),
            _texte_court(data.get('property_type'), 100),
            _choix(data.get('financing_status'), FINANCING_VALUES),
            _choix(data.get('purchase_urgency'), URGENCY_VALUES)
        ))
        lead = cur.fetchone()
        conn.commit()
        cur.close()
        conn.close()

        lead['lead_quality'] = derive_lead_quality(lead)
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
        cur.execute("SELECT id, user_id, name, email, phone, budget, location, property_type, status, financing_status, purchase_urgency, lead_quality, financing_amount, notes, created_at FROM leads WHERE id = %s AND user_id = %s", (lead_id, request.user_id))
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
                score = calculate_lead_score(lead, prop)
                if score > 30:
                    matches.append({"property_id": prop['id'], "address": prop['address'], "title": prop['title'], "type": prop['property_type'], "price": prop['price'], "rooms": prop['rooms'], "size": prop['size'], "score": score})
            matches.sort(key=lambda x: x['score'], reverse=True)
            result.append({"id": lead['id'], "name": lead['name'], "email": lead['email'], "phone": lead['phone'], "budget": lead['budget'], "location": lead['location'], "property_type": lead['property_type'], "financing_status": lead['financing_status'], "purchase_urgency": lead['purchase_urgency'], "lead_quality": derive_lead_quality(lead), "matches": matches})
        # Les leads les plus chauds d'abord.
        ordre = {'hot': 0, 'warm': 1, 'cold': 2}
        result.sort(key=lambda x: ordre.get(x['lead_quality'], 3))
        return jsonify(result), 200
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
