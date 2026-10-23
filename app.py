import os
import html
from contextlib import closing
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import jwt
from flask import Flask, g, jsonify, request

from db import get_conn

app = Flask(__name__)

JWT_SECRET = os.environ.get("JWT_SECRET", "dev-only-secret")
JWT_ALG = "HS256"
TOKEN_TTL_MINUTES = 15

def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify(error="missing bearer token"), 401

        token = header.split(" ", 1)[1].strip()
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        except jwt.ExpiredSignatureError:
            return jsonify(error="token expired"), 401
        except jwt.InvalidTokenError:
            return jsonify(error="invalid token"), 401

        g.user = payload
        return fn(*args, **kwargs)

    return wrapper

def esc(value):
    return html.escape(value or "", quote=True)

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

@app.get("/api/data")
@require_auth
def get_data():
    with closing(get_conn()) as conn:
        rows = conn.execute(
            """
            SELECT posts.id, posts.title, posts.body, users.username AS author
            FROM posts JOIN users ON posts.user_id = users.id
            ORDER BY posts.id DESC
            """,
            (),
        ).fetchall()
    return jsonify(
        posts=[
            {
                "id": r["id"],
                "title": esc(r["title"]),
                "body": esc(r["body"]),
                "author": esc(r["author"]),
            }
            for r in rows
        ]
    )

@app.post("/api/posts")
@require_auth
def create_post():
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    body = (data.get("body") or "").strip()

    # TODO 1: 校验
    #   title 为空          -> return jsonify(error="title is required"), 400
    #   len(title) > 200    -> return jsonify(error="title too long"), 400
    #   len(body)  > 2000   -> return jsonify(error="body too long"), 400
    if not title:
        return jsonify(error="title is required!"), 400
    if len(title) > 200:
        return jsonify(error="title too long"), 400
    if len(body) > 2000:
        return jsonify(error="body too long"), 400

    # TODO 2: 作者是谁，只能从 token 里拿
    #   提示: user_id = int(g.user["sub"])
    user_id = int(g.user["sub"])

    with closing(get_conn()) as conn, conn:
        cur = conn.execute(
            "INSERT INTO posts (user_id, title, body) VALUES (?, ?, ?)",
            (user_id, title, body),
        )
        new_id = cur.lastrowid

    return jsonify(id=new_id, title=esc(title), body=esc(body)), 201


if __name__ == "__main__":
    app.run(port=5000)