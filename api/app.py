import os
import json
import sqlite3
import hashlib
import secrets
from datetime import datetime, date, timedelta
from pathlib import Path
from functools import wraps

from flask import Flask, request, jsonify, g
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

DB_PATH = Path("/tmp/hulk_reservas.db")
SECRET_KEY = os.environ.get("HULK_SECRET_KEY", secrets.token_hex(32))

# ── CONFIG: Horarios y clases ──────────────────────────────────
# Formato: { "dia_semana_0-6": [ {"hora": "HH:MM", "tipo": "WOD|OPEN BOX|...", "max": 20}, ... ] }
# domingo=0, lunes=1, ... sábado=6

SCHEDULE = {
    1: [  # Lunes
        {"hora": "10:00", "tipo": "Jiu-Jitsu", "max": 15},
        {"hora": "16:15", "tipo": "WOD", "max": 20},
        {"hora": "17:30", "tipo": "WOD", "max": 20},
        {"hora": "18:45", "tipo": "WOD", "max": 20},
        {"hora": "20:00", "tipo": "WOD", "max": 20},
    ],
    2: [  # Martes
        {"hora": "16:15", "tipo": "WOD", "max": 20},
        {"hora": "17:30", "tipo": "WOD", "max": 20},
        {"hora": "18:45", "tipo": "WOD", "max": 20},
        {"hora": "20:00", "tipo": "WOD", "max": 20},
    ],
    3: [  # Miércoles
        {"hora": "10:00", "tipo": "Jiu-Jitsu", "max": 15},
        {"hora": "16:15", "tipo": "WOD", "max": 20},
        {"hora": "17:30", "tipo": "WOD", "max": 20},
        {"hora": "18:45", "tipo": "WOD", "max": 20},
        {"hora": "19:45", "tipo": "Strongman", "max": 12},
        {"hora": "20:00", "tipo": "WOD", "max": 20},
    ],
    4: [  # Jueves
        {"hora": "16:15", "tipo": "WOD", "max": 20},
        {"hora": "17:30", "tipo": "WOD", "max": 20},
        {"hora": "18:45", "tipo": "WOD", "max": 20},
        {"hora": "20:00", "tipo": "WOD", "max": 20},
    ],
    5: [  # Viernes
        {"hora": "10:00", "tipo": "Jiu-Jitsu", "max": 15},
        {"hora": "16:15", "tipo": "WOD", "max": 20},
        {"hora": "17:30", "tipo": "WOD", "max": 20},
        {"hora": "18:45", "tipo": "WOD", "max": 20},
        {"hora": "19:45", "tipo": "Gimnásticos", "max": 15},
        {"hora": "20:00", "tipo": "WOD", "max": 20},
    ],
    6: [  # Sábado
        {"hora": "09:00", "tipo": "Jiu-Jitsu", "max": 15},
        {"hora": "10:00", "tipo": "WOD", "max": 20},
        {"hora": "11:00", "tipo": "Open Box", "max": 15},
    ],
}


# ── DB ──────────────────────────────────────────────────────────

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(str(DB_PATH))
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        _init_db(g.db)
    return g.db

def _init_db(db):
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now'))
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS reservas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            fecha TEXT NOT NULL,
            hora TEXT NOT NULL,
            tipo TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, fecha, hora)
        )
    """)
    db.commit()

@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()


# ── AUTH ────────────────────────────────────────────────────────

def hash_pass(pwd):
    return hashlib.sha256((pwd + SECRET_KEY).encode()).hexdigest()

def make_token(user_id, is_admin):
    raw = f"{user_id}:{is_admin}:{SECRET_KEY}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]

def verify_token(token):
    for row in query_db("SELECT id, is_admin FROM users"):
        if make_token(row["id"], row["is_admin"]) == token:
            return {"id": row["id"], "is_admin": bool(row["is_admin"])}
    return None

def query_db(sql, args=(), one=False):
    db = get_db()
    cur = db.execute(sql, args)
    rows = cur.fetchall()
    db.commit()
    return (rows[0] if rows else None) if one else rows

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        user = verify_token(token)
        if not user:
            return jsonify({"error": "No autorizado"}), 401
        g.current_user = user
        return f(*args, **kwargs)
    return decorated


# ── API ENDPOINTS ───────────────────────────────────────────────

@app.route("/api/health")
def health():
    return jsonify({"ok": True, "time": datetime.now().isoformat()})

@app.route("/api/register", methods=["POST"])
def register():
    data = request.json
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    name = data.get("name", "").strip()
    
    if not email or not password or not name:
        return jsonify({"error": "Faltan datos"}), 400
    if len(password) < 4:
        return jsonify({"error": "Contraseña muy corta"}), 400
    
    try:
        db = get_db()
        db.execute("INSERT INTO users (email, name, password_hash) VALUES (?, ?, ?)",
                   (email, name, hash_pass(password)))
        db.commit()
        user = query_db("SELECT id, is_admin FROM users WHERE email=?", (email,), one=True)
        token = make_token(user["id"], user["is_admin"])
        return jsonify({"token": token, "user": {"id": user["id"], "email": email, "name": name}})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Email ya registrado"}), 400

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    
    user = query_db("SELECT * FROM users WHERE email=?", (email,), one=True)
    if not user or user["password_hash"] != hash_pass(password):
        return jsonify({"error": "Email o contraseña incorrectos"}), 401
    
    token = make_token(user["id"], user["is_admin"])
    return jsonify({
        "token": token,
        "user": {"id": user["id"], "email": user["email"], "name": user["name"], "is_admin": bool(user["is_admin"])}
    })

@app.route("/api/schedule")
def get_schedule():
    """Devuelve los horarios de la semana."""
    return jsonify(SCHEDULE)

@app.route("/api/reservas/<fecha>")
@require_auth
def get_reservas(fecha):
    """Reservas de una fecha concreta (YYYY-MM-DD)."""
    rows = query_db("""
        SELECT r.*, u.name as user_name
        FROM reservas r JOIN users u ON r.user_id = u.id
        WHERE r.fecha = ?
        ORDER BY r.hora
    """, (fecha,))
    
    # Agrupar por hora
    by_hour = {}
    for r in rows:
        key = r["hora"]
        if key not in by_hour:
            by_hour[key] = {"hora": key, "tipo": r["tipo"], "reservados": [], "count": 0}
        by_hour[key]["reservados"].append({
            "id": r["id"],
            "user_id": r["user_id"],
            "user_name": r["user_name"],
            "es_mio": r["user_id"] == g.current_user["id"]
        })
        by_hour[key]["count"] += 1
    
    return jsonify({
        "fecha": fecha,
        "dia_semana": datetime.strptime(fecha, "%Y-%m-%d").weekday(),
        "clases": list(by_hour.values())
    })

@app.route("/api/reservar", methods=["POST"])
@require_auth
def reservar():
    data = request.json
    fecha = data.get("fecha")
    hora = data.get("hora")
    tipo = data.get("tipo")
    
    if not fecha or not hora:
        return jsonify({"error": "Faltan datos"}), 400
    
    # Validar que la clase existe en el horario
    dia = datetime.strptime(fecha, "%Y-%m-%d").weekday()
    # Python weekday: lunes=0, domingo=6. Nuestro SCHEDULE: lunes=1, domingo=0
    dia_key = dia + 1 if dia < 6 else 0
    slots = SCHEDULE.get(dia_key, [])
    slot = next((s for s in slots if s["hora"] == hora), None)
    if not slot:
        return jsonify({"error": "Clase no disponible en este horario"}), 400
    
    # Verificar aforo
    count = query_db(
        "SELECT COUNT(*) as c FROM reservas WHERE fecha=? AND hora=?",
        (fecha, hora), one=True
    )["c"]
    if count >= slot["max"]:
        return jsonify({"error": "Clase completa"}), 400
    
    # Verificar que no tenga ya reserva en ese horario
    existing = query_db(
        "SELECT id FROM reservas WHERE user_id=? AND fecha=? AND hora=?",
        (g.current_user["id"], fecha, hora), one=True
    )
    if existing:
        return jsonify({"error": "Ya tienes reserva en este horario"}), 400
    
    try:
        db = get_db()
        db.execute(
            "INSERT INTO reservas (user_id, fecha, hora, tipo) VALUES (?, ?, ?, ?)",
            (g.current_user["id"], fecha, hora, tipo)
        )
        db.commit()
        return jsonify({"ok": True, "mensaje": "Reserva confirmada"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/api/cancelar/<int:reserva_id>", methods=["DELETE"])
@require_auth
def cancelar(reserva_id):
    r = query_db("SELECT * FROM reservas WHERE id=?", (reserva_id,), one=True)
    if not r:
        return jsonify({"error": "Reserva no encontrada"}), 404
    if r["user_id"] != g.current_user["id"] and not g.current_user["is_admin"]:
        return jsonify({"error": "No puedes cancelar esta reserva"}), 403
    
    db = get_db()
    db.execute("DELETE FROM reservas WHERE id=?", (reserva_id,))
    db.commit()
    return jsonify({"ok": True})

@app.route("/api/mis-reservas")
@require_auth
def mis_reservas():
    rows = query_db("""
        SELECT r.*, u.name as user_name
        FROM reservas r JOIN users u ON r.user_id = u.id
        WHERE r.user_id = ? AND r.fecha >= date('now')
        ORDER BY r.fecha, r.hora
    """, (g.current_user["id"],))
    
    return jsonify([{
        "id": r["id"], "fecha": r["fecha"], "hora": r["hora"],
        "tipo": r["tipo"], "user_name": r["user_name"]
    } for r in rows])

@app.route("/api/admin/reservas")
@require_auth
def admin_reservas():
    if not g.current_user["is_admin"]:
        return jsonify({"error": "No autorizado"}), 403
    
    rows = query_db("""
        SELECT r.*, u.name as user_name, u.email as user_email
        FROM reservas r JOIN users u ON r.user_id = u.id
        ORDER BY r.fecha DESC, r.hora
        LIMIT 200
    """)
    return jsonify([dict(r) for r in rows])


# ── MAIN ────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
