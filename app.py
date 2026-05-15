from flask import Flask, request, jsonify
import sqlite3
import jwt
import datetime
import bcrypt

app = Flask(__name__)

SECRET_KEY = "supersecretkey"

# ---------- Database ----------
conn = sqlite3.connect("users.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password BLOB
)
""")

conn.commit()
conn.close()

# ---------- Register ----------
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    hashed = bcrypt.hashpw(
        data["password"].encode(),
        bcrypt.gensalt()
    )

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        (data["username"], hashed)
    )

    conn.commit()
    conn.close()

    return jsonify({
        "message": "User registered"
    })

# ---------- Login ----------
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE username=?",
        (data["username"],)
    )

    user = cursor.fetchone()

    conn.close()

    if user:
        stored_password = user[2]

        if bcrypt.checkpw(
            data["password"].encode(),
            stored_password
        ):
            token = jwt.encode(
                {
                    "username": data["username"],
                    "exp": datetime.datetime.utcnow()
                    + datetime.timedelta(hours=1)
                },
                SECRET_KEY,
                algorithm="HS256"
            )

            return jsonify({
                "token": token
            })

    return jsonify({
        "message": "Invalid credentials"
    }), 401

# ---------- Protected Route ----------
@app.route("/profile")
def profile():
    token = request.headers.get("Authorization")

    if not token:
        return jsonify({
            "message": "Token missing"
        }), 401

    try:
        decoded = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256"]
        )

        return jsonify({
            "message": f"Welcome {decoded['username']}"
        })

    except:
        return jsonify({
            "message": "Invalid token"
        }), 401

# ---------- Run ----------
if __name__ == "__main__":
    app.run(debug=True)
