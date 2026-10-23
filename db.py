import sqlite3
import bcrypt

from contextlib import closing

DB_PATH = "app.db"

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with closing(get_conn()) as conn, conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                body TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            """
        )

def create_user(username, password):
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    with closing(get_conn()) as conn, conn:
        conn.execute(
            "INSERT OR IGNORE INTO users (username, password_hash) VALUES (?, ?)",
            (username, pw_hash),
        )
def create_post(user_id, title, body):
    with closing(get_conn()) as conn, conn:
        conn.execute(
            "INSERT INTO posts (user_id, title, body) VALUES (?, ?, ?)",
            (user_id, title, body),
        )

if __name__ == "__main__":
    init_db()
    create_user("alice", "Password123!")

    with closing(get_conn()) as conn, conn:
        uid = conn.execute(
            "SELECT id FROM users WHERE username = ?", ("alice",)
        ).fetchone()[0]
        posts = conn.execute("SELECT COUNT(*) FROM posts").fetchone()[0]

    if posts == 0:
        create_post(uid, "Welcome", "first post by alice")
        create_post(uid, "Second", "another post")

    print("db ready")