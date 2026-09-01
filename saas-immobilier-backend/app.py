from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
import jwt
import os
from functools import wraps
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash
load_dotenv()

app = Flask(__name__)
CORS(app)

SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://hugocotelle@localhost:5432/saas_immobilier")
PORT = int(os.getenv("PORT", 8888))
# Créer la connexion globale à la BD
try:
    db = psycopg2.connect(DATABASE_URL)
    print("✅ Connexion à la base de données établie")
except Exception as e:
    print(f"❌ Erreur de connexion: {e}")
    db = None# Initialiser la base de données

def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    return conn

def token_required(f):
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
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user_id = data['user_id']
            request.user_id = current_user_id
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token"}), 401
        return f(*args, **kwargs)
    return decorated
def init_database():
    """Initialiser la base de données avec les tables et données de test"""
    try:
        cursor = db.cursor()
        
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
        
        # Vérifier si vide
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        
        if user_count == 0:
            # Insérer utilisateur de test
            cursor.execute("""
                INSERT INTO users (email, password_hash, first_name, company_name)
                VALUES (%s, %s, %s, %s)
      """, ('test@example.com', generate_password_hash('password123'), 'Test', 'Test Company'))
            
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
                    VALUES (1, %s, %s, %s, %s, %s, %s, 'nouveau')
                """, (name, email, phone, budget, location, property_type))
        
        db.commit()
        cursor.close()
        print("✅ Base de données initialisée!")
        
    except Exception as e:
        print(f"❌ Erreur: {e}")
        db.rollback()
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data.get('email') or not data.get('password'):
        return jsonify({"message": "Email and password required"}), 400
    email = data.get('email')
    password = data.get('password')
    first_name = data.get('first_name', '')
    company_name = data.get('company_name', '')
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
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
        token = jwt.encode(
            {
                'user_id': user_id,
                'email': email,
                'exp': datetime.utcnow() + timedelta(days=30)
            },
            SECRET_KEY,
            algorithm="HS256"
        )
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
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"message": str(e)}), 500

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data.get('email') or not data.get('password'):
        return jsonify({"message": "Email and password required"}), 400
    email = data.get('email')
    password = data.get('password')
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, email, password_hash, first_name, company_name FROM users WHERE email = %s", (email,))
user = cur.fetchone()
        if not user or not check_password_hash(user['password_hash'], password):
            cur.close()
            conn.close()
            return jsonify({"message": "Invalid credentials"}), 401
        token = jwt.encode(
            {
                'user_id': user['id'],
                'email': user['email'],
                'exp': datetime.utcnow() + timedelta(days=30)
            },
            SECRET_KEY,
            algorithm="HS256"
        )
        cur.close()
        conn.close()
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
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"message": str(e)}), 500

@app.route('/auth/profile', methods=['GET'])
@token_required
def get_profile():
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
    except Exception as e:
        return jsonify({"message": str(e)}), 500

@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "OK"}), 200

@app.route('/api/v1/leads', methods=['GET'])
@token_required
def get_leads():
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, \"firstName\", \"lastName\", email, phone, \"propertyType\" FROM \"Lead\" ORDER BY id")
        leads = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify(leads), 200
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"message": str(e)}), 500

@app.route('/api/v1/properties', methods=['GET'])
@token_required
def get_properties():
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, address, title as name, \"propertyType\" as type, price, status as price_type FROM \"Property\" ORDER BY id")
        properties = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify(properties), 200
    except Exception as e:
        return jsonify({"message": str(e)}), 500

@app.route('/api/v1/improved-matches', methods=['GET'])
@token_required
def get_improved_matches():
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT l.id, l."firstName", l."lastName", l.email, l.phone, l."propertyType",
                   p.id as property_id, p.address, p.title as name, p."propertyType" as type, p.price, p.status as price_type,
                   CASE 
                       WHEN l."propertyType" = p."propertyType" THEN 50
                       ELSE 0
                   END +
                   CASE 
                       WHEN p.address LIKE '%Paris%' THEN 30
                       ELSE 0
                   END +
                   CASE
                       WHEN p.status = 'available' THEN 20
                       ELSE 0
                   END as match_score
            FROM "Lead" l
            CROSS JOIN "Property" p
            ORDER BY l.id, match_score DESC
        """)
        matches = cur.fetchall()
        cur.close()
        conn.close()
        result = {}
        for match in matches:
            lead_id = match['id']
            if lead_id not in result:
                result[lead_id] = {
                    "id": match['id'],
                    "firstName": match['firstName'],
                    "lastName": match['lastName'],
                    "email": match['email'],
                    "phone": match['phone'],
                    "propertyType": match['propertyType'],
                    "matches": []
                }
            result[lead_id]["matches"].append({
                "property_id": match['property_id'],
                "address": match['address'],
                "name": match['name'],
                "type": match['type'],
                "price": match['price'],
                "price_type": match['price_type'],
                "score": match['match_score']
            })
        return jsonify(list(result.values())), 200
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"message": str(e)}), 500

@app.route('/api/v1/stats', methods=['GET'])
@token_required
def get_stats():
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT 
                (SELECT COUNT(*) FROM "Lead") as total_leads,
                (SELECT COUNT(*) FROM "Property") as total_properties,
                (SELECT COUNT(DISTINCT "firstName" || "lastName") FROM "Lead") as unique_leads
        """)
        stats = cur.fetchone()
        cur.close()
        conn.close()
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({"message": str(e)}), 500
# Initialiser la base de données au démarrage
@app.route('/api/v1/init-db', methods=['POST'])
def init_db():
    """Route pour initialiser la base de données"""
    try:
        if db:
            init_database()
            return jsonify({"message": "Database initialized successfully"}), 200
        else:
            return jsonify({"message": "Database connection failed"}), 500
    except Exception as e:
        return jsonify({"message": str(e)}), 500
if __name__ == '__main__':
    print(f"🚀 Backend running on http://localhost:{PORT}")
    print(f"🔐 JWT Secret Key: {SECRET_KEY}")
    app.run(host='0.0.0.0', port=PORT, debug=False)
