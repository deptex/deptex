"""FastAPI + SQLAlchemy — one reachable SQLi, one safe ORM query."""

from fastapi import FastAPI, Query
from sqlalchemy import create_engine, text

app = FastAPI()
engine = create_engine("sqlite:///./test.db")


@app.get("/users/lookup")
def lookup_user(name: str = Query(...)):
    # REACHABLE: query string concatenated into raw SQL.
    with engine.connect() as conn:
        rows = conn.execute(text(f"SELECT * FROM users WHERE name = '{name}'"))
        return [dict(r) for r in rows]


@app.get("/users")
def list_users():
    # UNREACHABLE: hardcoded query, no user taint.
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT id, name FROM users LIMIT 50"))
        return [dict(r) for r in rows]
