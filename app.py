import os
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from flask import Flask, jsonify, request

from db import get_conn

from contextlib import closing

app = Flask(__name__)

JWT_SECRET = os.environ.get("JWT_SECRET", "dev-only-secret")
JWT_ALG = "HS256"
TOKEN_TTL_MINUTES = 15


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify(error="username and password are required"), 400

    with closing(get_conn()) as conn:
        row = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

    if row is None:
        return jsonify(error="invalid credentials"), 401

    is_password_valid = bcrypt.checkpw(password.encode('utf-8'), row["password_hash"].encode('utf-8'))
    
    if not is_password_valid:
        return jsonify(error="invalid credentials"), 401
    
    payload = {
        "sub": str(row["id"]),
        "username": row["username"],
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=TOKEN_TTL_MINUTES),
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

    return jsonify(token=token)


if __name__ == "__main__":
    app.run(port=5000)