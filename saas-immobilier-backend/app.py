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
    db = None

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
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user_id = data['id']
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

# ===== ROUTES HEALTH & INIT =====

@app.route('/health', methods=['GET'])
def health():
    """Vérifier que le backend répond"""
    return jsonify({"status": "OK"}), 200

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

# ===== ROUTES AUTHENTICATION =====

@app.route('/auth/register', methods=['POST'])
def register():
    """Enregistrer un nouvel utilisateur"""
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
        
        token = create_access_token(identity={'id': user_id, 'email': email}, expires=timedelta(days=30))
        
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
    """Connexion utilisateur"""
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
        
        cur.close()
        conn.close()
        
        token = create_access_token(identity={'id': user['id'], 'email': user['email']}, expires=timedelta(days=30))
        
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
        return jsonify({"message": str(e)}), 500

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
    except Exception as e:
        return jsonify({"message": str(e)}), 500

# ===== ROUTES API LEADS & PROPERTIES =====

@app.route('/api/v1/leads', methods=['GET'])
def get_leads():
    """Retourner tous les leads"""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, name, email, phone, budget, location, property_type, status FROM leads ORDER BY id")
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
    """Retourner les propriétés de l'utilisateur"""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, title, address, price, size, rooms, property_type, description FROM properties WHERE user_id = %s ORDER BY id", (request.user_id,))
        properties = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify(properties), 200
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"message": str(e)}), 500

@app.route('/api/v1/stats', methods=['GET'])
@token_required
def get_stats():
    """Retourner les statistiques"""
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT 
                (SELECT COUNT(*) FROM leads) as total_leads,
                (SELECT COUNT(*) FROM properties WHERE user_id = %s) as total_properties,
                (SELECT COUNT(DISTINCT name) FROM leads) as unique_leads
        """, (request.user_id,))
        stats = cur.fetchone()
        cur.close()
        conn.close()
        return jsonify(stats), 200
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"message": str(e)}), 500

# ===== SCORING INTELLIGENT =====

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
    if lead.get('location') == property_item.get('address'):
        score += 15
    elif lead.get('location') and property_item.get('address'):
        if lead['location'].lower() in property_item['address'].lower():
            score += 12
        else:
            score += 5
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
    quality = lead.get('lead_quality', 'cold')
    quality_multiplier = {'hot': 1.15, 'warm': 1.05, 'cold': 0.90}
    score = score * quality_multiplier.get(quality, 1.0)
    return min(100, max(0, int(score)))


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
    except Exception as e:
        return jsonify({"message": str(e)}), 500


@app.route('/api/v1/leads/<int:lead_id>/update-financing', methods=['PUT'])
@token_required
def update_lead_financing(lead_id):
    try:
        data = request.get_json()
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE leads SET financing_status = %s, purchase_urgency = %s, lead_quality = %s, financing_amount = %s, notes = %s WHERE id = %s AND user_id = %s", (data.get('financing_status'), data.get('purchase_urgency'), data.get('lead_quality'), data.get('financing_amount'), data.get('notes'), lead_id, request.user_id))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"message": "Lead updated successfully"}), 200
    except Exception as e:
        return jsonify({"message": str(e)}), 500


@app.route('/api/v1/leads/quality/<quality>', methods=['GET'])
@token_required
def get_leads_by_quality(quality):
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, name, email, phone, budget, location, property_type, financing_status, purchase_urgency, lead_quality FROM leads WHERE user_id = %s AND lead_quality = %s ORDER BY created_at DESC", (request.user_id, quality))
        leads = cur.fetchall()
        cur.close()
        conn.close()
        return jsonify(leads), 200
    except Exception as e:
        return jsonify({"message": str(e)}), 500


@app.route('/api/v1/improved-matches', methods=['GET'])
@token_required
def get_improved_matches():
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT id, name, email, phone, budget, location, property_type, financing_status, purchase_urgency, lead_quality FROM leads WHERE user_id = %s ORDER BY lead_quality DESC, created_at DESC", (request.user_id,))
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
            result.append({"id": lead['id'], "name": lead['name'], "email": lead['email'], "phone": lead['phone'], "budget": lead['budget'], "location": lead['location'], "property_type": lead['property_type'], "financing_status": lead['financing_status'], "purchase_urgency": lead['purchase_urgency'], "lead_quality": lead['lead_quality'], "matches": matches})
        return jsonify(result), 200
    except Exception as e:
        print(f"Error: {str(e)}")
        return jsonify({"message": str(e)}), 500
if __name__ == '__main__':
    print(f"🚀 Backend running on http://localhost:{PORT}")
    print(f"🔐 JWT Secret Key: {SECRET_KEY}")
    app.run(host='0.0.0.0', port=PORT, debug=False)
