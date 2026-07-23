"""A small secure second-hand marketplace demonstration."""
from __future__ import annotations

import html
import os
import secrets
import sqlite3
from functools import wraps
from pathlib import Path

import click
from flask import Flask, abort, g, jsonify, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

APP_DIR = Path(__file__).parent
DB_PATH = APP_DIR / "market.db"
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("MARKET_SECRET", secrets.token_hex(32)),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


def db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_: object) -> None:
    if connection := g.pop("db", None):
        connection.close()


def init_db() -> None:
    db().executescript("""
    PRAGMA foreign_keys=ON;
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0,
      blocked INTEGER NOT NULL DEFAULT 0,
      balance INTEGER NOT NULL DEFAULT 100000 CHECK(balance >= 0));
    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY, seller_id INTEGER NOT NULL REFERENCES users(id),
      title TEXT NOT NULL CHECK(length(title) BETWEEN 1 AND 120),
      description TEXT NOT NULL CHECK(length(description) <= 2000),
      price INTEGER NOT NULL CHECK(price > 0), blocked INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS blocks (
      blocker_id INTEGER NOT NULL REFERENCES users(id),
      blocked_id INTEGER NOT NULL REFERENCES users(id),
      PRIMARY KEY(blocker_id, blocked_id), CHECK(blocker_id != blocked_id));
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY, sender_id INTEGER NOT NULL REFERENCES users(id),
      receiver_id INTEGER NOT NULL REFERENCES users(id),
      product_id INTEGER REFERENCES products(id),
      body TEXT NOT NULL CHECK(length(body) BETWEEN 1 AND 1000),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS transfers (
      id INTEGER PRIMARY KEY, sender_id INTEGER NOT NULL REFERENCES users(id),
      receiver_id INTEGER NOT NULL REFERENCES users(id),
      product_id INTEGER REFERENCES products(id), amount INTEGER NOT NULL CHECK(amount > 0),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
    """)
    db().commit()


def current_user() -> sqlite3.Row | None:
    user_id = session.get("user_id")
    return db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone() if user_id else None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user() or current_user()["blocked"]:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user() or not current_user()["is_admin"]:
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def validate_csrf() -> None:
    if request.method == "POST" and request.form.get("csrf") != session.get("csrf"):
        abort(400, "CSRF validation failed")


def page(title: str, body: str, **context: object) -> str:
    template = """<!doctype html><meta charset=utf-8><title>""" + html.escape(title) + """</title>
    <style>body{font-family:sans-serif;max-width:850px;margin:2rem auto}input,textarea{display:block;width:100%;margin:.4rem 0;padding:.5rem}button{padding:.45rem .8rem}article{border:1px solid #ddd;margin:.6rem 0;padding:.8rem}</style>
    <h1>""" + html.escape(title) + """</h1>
    <p><a href='/'>Products</a> | <a href='/login'>Login</a> | <a href='/register'>Register</a>{% if user %} | {{user['username']}} (balance: {{user['balance']}}) <a href='/logout'>Logout</a>{% endif %}</p>""" + body
    return render_template_string(template, user=current_user(), csrf=session.get("csrf"), **context)


@app.before_request
def setup() -> None:
    init_db()
    session.setdefault("csrf", secrets.token_urlsafe(24))


@app.cli.command("create-admin")
@click.option("--username", prompt=True)
@click.password_option()
def create_admin(username: str, password: str) -> None:
    """Create or promote a local administrator account."""
    if not (3 <= len(username.strip()) <= 30 and len(password) >= 12):
        raise click.UsageError("username: 3-30 chars; password: at least 12 chars")
    init_db()
    existing = db().execute("SELECT id FROM users WHERE username=?", (username.strip(),)).fetchone()
    if existing:
        db().execute("UPDATE users SET is_admin=1, blocked=0 WHERE id=?", (existing["id"],))
    else:
        db().execute("INSERT INTO users(username,password_hash,is_admin) VALUES(?,?,1)", (username.strip(), generate_password_hash(password)))
    db().commit()
    click.echo("Administrator account is ready.")


@app.route("/")
def index():
    keyword = request.args.get("q", "").strip()
    rows = db().execute(
        "SELECT p.*,u.username FROM products p JOIN users u ON p.seller_id=u.id "
        "WHERE p.blocked=0 AND u.blocked=0 AND (p.title LIKE ? OR p.description LIKE ?) ORDER BY p.id DESC",
        (f"%{keyword}%", f"%{keyword}%"),
    ).fetchall()
    body = """<form><input name=q value='{{q}}' placeholder='Search products'><button>Search</button></form>
    {% if user %}<p><a href='/products/new'>List product</a> | <a href='/messages'>Messages</a> | <a href='/transfer'>Transfer</a></p>{% endif %}
    {% for p in rows %}<article><a href='/products/{{p.id}}'><b>{{p.title}}</b></a> - {{p.price}} KRW<br>{{p.username}}</article>{% else %}<p>No products found.</p>{% endfor %}"""
    return page("Tiny Second-hand", body, q=keyword, rows=rows)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        validate_csrf()
        username, password = request.form.get("username", "").strip(), request.form.get("password", "")
        if not (3 <= len(username) <= 30 and len(password) >= 12):
            abort(400, "username: 3-30 chars; password: at least 12 chars")
        try:
            db().execute("INSERT INTO users(username,password_hash) VALUES(?,?)", (username, generate_password_hash(password)))
            db().commit()
        except sqlite3.IntegrityError:
            abort(400, "duplicate username")
        return redirect(url_for("login"))
    return page("Register", "<form method=post><input type=hidden name=csrf value='{{csrf}}'><input name=username placeholder='Username' required><input name=password type=password minlength=12 placeholder='Password (12+ chars)' required><button>Register</button></form>")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        validate_csrf()
        user = db().execute("SELECT * FROM users WHERE username=?", (request.form.get("username", ""),)).fetchone()
        if not user or user["blocked"] or not check_password_hash(user["password_hash"], request.form.get("password", "")):
            abort(401, "invalid credentials")
        session.clear()
        session["user_id"], session["csrf"] = user["id"], secrets.token_urlsafe(24)
        return redirect(url_for("index"))
    return page("Login", "<form method=post><input type=hidden name=csrf value='{{csrf}}'><input name=username required><input name=password type=password required><button>Login</button></form>")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/products/new", methods=["GET", "POST"])
@login_required
def new_product():
    if request.method == "POST":
        validate_csrf()
        try:
            db().execute("INSERT INTO products(seller_id,title,description,price) VALUES(?,?,?,?)", (current_user()["id"], request.form.get("title", "").strip(), request.form.get("description", "").strip(), int(request.form.get("price", "0"))))
            db().commit()
        except (ValueError, sqlite3.IntegrityError):
            abort(400, "invalid product data")
        return redirect(url_for("index"))
    return page("List a product", "<form method=post><input type=hidden name=csrf value='{{csrf}}'><input name=title maxlength=120 placeholder='Title' required><textarea name=description maxlength=2000 placeholder='Description' required></textarea><input name=price type=number min=1 placeholder='Price' required><button>List</button></form>")


@app.route("/products/<int:product_id>")
def product(product_id: int):
    product = db().execute("SELECT p.*,u.username FROM products p JOIN users u ON p.seller_id=u.id WHERE p.id=? AND p.blocked=0 AND u.blocked=0", (product_id,)).fetchone()
    if not product:
        abort(404)
    body = """<article><b>{{p.title}}</b><p>{{p.description}}</p><p>{{p.price}} KRW - seller: {{p.username}}</p></article>
    {% if user and user['id'] != p['seller_id'] %}<form method=post action='/messages'><input type=hidden name=csrf value='{{csrf}}'><input type=hidden name=receiver_id value='{{p.seller_id}}'><input type=hidden name=product_id value='{{p.id}}'><textarea name=body required placeholder='Message the seller'></textarea><button>Send</button></form>{% endif %}"""
    return page("Product details", body, p=product)


@app.route("/messages", methods=["GET", "POST"])
@login_required
def messages():
    if request.method == "POST":
        validate_csrf()
        sender = current_user()["id"]
        try:
            receiver = int(request.form["receiver_id"])
        except (KeyError, ValueError):
            abort(400, "invalid receiver")
        if sender == receiver or db().execute("SELECT 1 FROM blocks WHERE blocker_id=? AND blocked_id=?", (receiver, sender)).fetchone():
            abort(403, "message not permitted")
        try:
            db().execute("INSERT INTO messages(sender_id,receiver_id,product_id,body) VALUES(?,?,?,?)", (sender, receiver, request.form.get("product_id") or None, request.form.get("body", "").strip()))
            db().commit()
        except sqlite3.IntegrityError:
            abort(400, "invalid message")
        return redirect(url_for("messages"))
    rows = db().execute("SELECT m.*,s.username sender,r.username receiver FROM messages m JOIN users s ON m.sender_id=s.id JOIN users r ON m.receiver_id=r.id WHERE m.sender_id=? OR m.receiver_id=? ORDER BY m.id DESC", (current_user()["id"], current_user()["id"])).fetchall()
    return page("Messages", "{% for m in rows %}<article>{{m.sender}} to {{m.receiver}}: {{m.body}}</article>{% else %}<p>No messages.</p>{% endfor %}", rows=rows)


@app.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    if request.method == "POST":
        validate_csrf()
        try:
            sender, receiver, amount = current_user()["id"], int(request.form["receiver_id"]), int(request.form["amount"])
        except (KeyError, ValueError):
            abort(400, "invalid transfer")
        if sender == receiver or amount <= 0:
            abort(400, "invalid transfer")
        with db():
            debit = db().execute("UPDATE users SET balance=balance-? WHERE id=? AND balance>=? AND blocked=0", (amount, sender, amount))
            credit = db().execute("UPDATE users SET balance=balance+? WHERE id=? AND blocked=0", (amount, receiver))
            if debit.rowcount != 1 or credit.rowcount != 1:
                abort(400, "transfer denied")
            db().execute("INSERT INTO transfers(sender_id,receiver_id,product_id,amount) VALUES(?,?,?,?)", (sender, receiver, request.form.get("product_id") or None, amount))
        return redirect(url_for("index"))
    return page("Transfer", "<form method=post><input type=hidden name=csrf value='{{csrf}}'><input name=receiver_id type=number placeholder='Recipient user ID' required><input name=product_id type=number placeholder='Product ID (optional)'><input name=amount type=number min=1 placeholder='Amount' required><button>Transfer</button></form>")


@app.route("/admin")
@admin_required
def admin_dashboard():
    users = db().execute("SELECT id,username,is_admin,blocked,balance FROM users ORDER BY id").fetchall()
    products = db().execute("SELECT p.id,p.title,p.price,p.blocked,u.username FROM products p JOIN users u ON u.id=p.seller_id ORDER BY p.id DESC").fetchall()
    body = """<h2>User management</h2>{% for item in users %}<article>#{{item.id}} {{item.username}} | admin={{item.is_admin}} | blocked={{item.blocked}} | balance={{item.balance}}
    {% if not item.blocked and item.id != user.id %}<form method=post action='/admin/block/user/{{item.id}}'><input type=hidden name=csrf value='{{csrf}}'><button>Block user</button></form>{% endif %}</article>{% endfor %}
    <h2>Product management</h2>{% for item in products %}<article>#{{item.id}} {{item.title}} | seller={{item.username}} | {{item.price}} KRW | blocked={{item.blocked}}
    {% if not item.blocked %}<form method=post action='/admin/block/product/{{item.id}}'><input type=hidden name=csrf value='{{csrf}}'><button>Block product</button></form>{% endif %}</article>{% else %}<p>No products.</p>{% endfor %}"""
    return page("Administration", body, users=users, products=products)


@app.route("/admin/block/user/<int:user_id>", methods=["POST"])
@admin_required
def block_user(user_id: int):
    validate_csrf()
    db().execute("UPDATE users SET blocked=1 WHERE id=?", (user_id,))
    db().commit()
    return jsonify(ok=True)


@app.route("/admin/block/product/<int:product_id>", methods=["POST"])
@admin_required
def block_product(product_id: int):
    validate_csrf()
    db().execute("UPDATE products SET blocked=1 WHERE id=?", (product_id,))
    db().commit()
    return jsonify(ok=True)


if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
