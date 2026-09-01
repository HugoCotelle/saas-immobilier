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

if __name__ == '__main__':
    print(f"🚀 Backend running on http://localhost:{PORT}")
    print(f"🔐 JWT Secret Key: {SECRET_KEY}")
    app.run(host='0.0.0.0', port=PORT, debug=True)
