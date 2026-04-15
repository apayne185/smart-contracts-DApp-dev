"""
Flask + SQLite web2 backend for the Ticket Office.

Mirrors the surface area of the Solidity TicketOffice contract:
 - admin can create events and toggle active / update price
 - users can buy, transfer, list for resale, buy resale
 - persistent storage in app.db
 - no real payments (just integer `price_wei` counters) since there's no chain

Run:
    python -m app.server.app
    (from implementation/exercise-2/)
"""

import os
import sqlite3
import time
from flask import Flask, g, jsonify, request

HERE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("TICKET_DB", os.path.join(HERE, "app.db"))
SCHEMA  = os.path.join(HERE, "schema.sql")

app = Flask(__name__)


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_err):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    with open(SCHEMA) as f:
        conn.executescript(f.read())
    # seed users + events if empty
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM users")
    if cur.fetchone()[0] == 0:
        cur.executemany(
            "INSERT INTO users(name, is_admin) VALUES (?, ?)",
            [("admin", 1), ("alice", 0), ("bob", 0), ("carol", 0)],
        )
    cur.execute("SELECT COUNT(*) AS c FROM events")
    if cur.fetchone()[0] == 0:
        now = int(time.time())
        cur.executemany(
            "INSERT INTO events(name, price_wei, total_supply, event_date) VALUES (?, ?, ?, ?)",
            [
                ("Rock Concert", 20_000_000_000_000_000,  5, now + 14 * 86400),
                ("Tech Meetup",  10_000_000_000_000_000, 10, now +  7 * 86400),
            ],
        )
    conn.commit()
    conn.close()


def require_user():
    """Resolve caller identity from the X-User header (by name). No auth —
    this is a demo backend; see README for why that's fine here."""
    name = request.headers.get("X-User")
    if not name:
        return None, (jsonify(error="missing X-User header"), 401)
    row = db().execute("SELECT * FROM users WHERE name=?", (name,)).fetchone()
    if not row:
        return None, (jsonify(error=f"unknown user {name!r}"), 404)
    return row, None


def require_admin():
    user, err = require_user()
    if err:
        return None, err
    if not user["is_admin"]:
        return None, (jsonify(error="admin only"), 403)
    return user, None


# ---- Read-only routes -------------------------------------------------------

@app.get("/users")
def list_users():
    rows = db().execute("SELECT id, name, is_admin FROM users ORDER BY id").fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/events")
def list_events():
    rows = db().execute("SELECT * FROM events ORDER BY id").fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/events/<int:eid>")
def get_event(eid):
    row = db().execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
    if not row:
        return jsonify(error="event not found"), 404
    return jsonify(dict(row))


@app.get("/tickets/of/<name>")
def tickets_of(name):
    u = db().execute("SELECT id FROM users WHERE name=?", (name,)).fetchone()
    if not u:
        return jsonify(error="unknown user"), 404
    rows = db().execute(
        "SELECT t.id, t.event_id, e.name AS event_name FROM tickets t "
        "JOIN events e ON e.id = t.event_id WHERE t.owner_id=? ORDER BY t.id",
        (u["id"],),
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/listings")
def all_listings():
    rows = db().execute(
        "SELECT l.ticket_id, l.price_wei, u.name AS seller, t.event_id, e.name AS event_name "
        "FROM listings l "
        "JOIN users u  ON u.id = l.seller_id "
        "JOIN tickets t ON t.id = l.ticket_id "
        "JOIN events e  ON e.id = t.event_id "
        "ORDER BY l.ticket_id"
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.get("/listings/<int:ticket_id>")
def get_listing(ticket_id):
    row = db().execute(
        "SELECT ticket_id, price_wei FROM listings WHERE ticket_id=?",
        (ticket_id,),
    ).fetchone()
    return jsonify({"ticket_id": ticket_id, "active": bool(row), "price_wei": row["price_wei"] if row else 0})


# ---- Admin routes -----------------------------------------------------------

@app.post("/events")
def create_event():
    _, err = require_admin()
    if err:
        return err
    data = request.get_json(force=True)
    name  = (data.get("name") or "").strip()
    price = int(data.get("price_wei") or 0)
    supply = int(data.get("total_supply") or 0)
    edate  = int(data.get("event_date") or 0)
    if not name:         return jsonify(error="empty name"), 400
    if price <= 0:       return jsonify(error="invalid price"), 400
    if supply <= 0:      return jsonify(error="invalid supply"), 400
    cur = db().execute(
        "INSERT INTO events(name, price_wei, total_supply, event_date) VALUES (?, ?, ?, ?)",
        (name, price, supply, edate),
    )
    db().commit()
    return jsonify(id=cur.lastrowid), 201


@app.post("/events/<int:eid>/active")
def set_active(eid):
    _, err = require_admin()
    if err:
        return err
    active = 1 if request.get_json(force=True).get("active") else 0
    cur = db().execute("UPDATE events SET active=? WHERE id=?", (active, eid))
    db().commit()
    if cur.rowcount == 0:
        return jsonify(error="event not found"), 404
    return jsonify(ok=True)


@app.post("/events/<int:eid>/price")
def update_price(eid):
    _, err = require_admin()
    if err:
        return err
    price = int(request.get_json(force=True).get("price_wei") or 0)
    if price <= 0:
        return jsonify(error="invalid price"), 400
    cur = db().execute("UPDATE events SET price_wei=? WHERE id=?", (price, eid))
    db().commit()
    if cur.rowcount == 0:
        return jsonify(error="event not found"), 404
    return jsonify(ok=True)


# ---- User routes ------------------------------------------------------------

@app.post("/events/<int:eid>/buy")
def buy_ticket(eid):
    user, err = require_user()
    if err:
        return err
    conn = db()
    ev = conn.execute("SELECT * FROM events WHERE id=?", (eid,)).fetchone()
    if not ev:            return jsonify(error="event not found"), 404
    if not ev["active"]:  return jsonify(error="event inactive"), 400
    if ev["sold"] >= ev["total_supply"]:
        return jsonify(error="sold out"), 400
    conn.execute("UPDATE events SET sold = sold + 1 WHERE id=?", (eid,))
    cur = conn.execute(
        "INSERT INTO tickets(event_id, owner_id) VALUES (?, ?)",
        (eid, user["id"]),
    )
    conn.commit()
    return jsonify(ticket_id=cur.lastrowid), 201


@app.post("/tickets/<int:tid>/transfer")
def transfer_ticket(tid):
    user, err = require_user()
    if err:
        return err
    to_name = (request.get_json(force=True).get("to") or "").strip()
    if not to_name:
        return jsonify(error="missing to"), 400
    conn = db()
    t = conn.execute("SELECT * FROM tickets WHERE id=?", (tid,)).fetchone()
    if not t:                          return jsonify(error="ticket not found"), 404
    if t["owner_id"] != user["id"]:    return jsonify(error="not ticket owner"), 403
    dest = conn.execute("SELECT * FROM users WHERE name=?", (to_name,)).fetchone()
    if not dest:                       return jsonify(error="unknown recipient"), 404
    if dest["id"] == user["id"]:       return jsonify(error="self transfer"), 400
    # Clear any listing (mirrors contract behaviour)
    conn.execute("DELETE FROM listings WHERE ticket_id=?", (tid,))
    conn.execute("UPDATE tickets SET owner_id=? WHERE id=?", (dest["id"], tid))
    conn.commit()
    return jsonify(ok=True)


@app.post("/tickets/<int:tid>/list")
def list_for_resale(tid):
    user, err = require_user()
    if err:
        return err
    price = int(request.get_json(force=True).get("price_wei") or 0)
    if price <= 0:
        return jsonify(error="invalid price"), 400
    conn = db()
    t = conn.execute("SELECT * FROM tickets WHERE id=?", (tid,)).fetchone()
    if not t:                          return jsonify(error="ticket not found"), 404
    if t["owner_id"] != user["id"]:    return jsonify(error="not ticket owner"), 403
    existing = conn.execute("SELECT 1 FROM listings WHERE ticket_id=?", (tid,)).fetchone()
    if existing:                       return jsonify(error="already listed"), 400
    conn.execute(
        "INSERT INTO listings(ticket_id, price_wei, seller_id) VALUES (?, ?, ?)",
        (tid, price, user["id"]),
    )
    conn.commit()
    return jsonify(ok=True)


@app.post("/tickets/<int:tid>/cancel")
def cancel_listing(tid):
    user, err = require_user()
    if err:
        return err
    conn = db()
    l = conn.execute("SELECT * FROM listings WHERE ticket_id=?", (tid,)).fetchone()
    if not l:                          return jsonify(error="not listed"), 404
    if l["seller_id"] != user["id"]:   return jsonify(error="not your listing"), 403
    conn.execute("DELETE FROM listings WHERE ticket_id=?", (tid,))
    conn.commit()
    return jsonify(ok=True)


@app.post("/tickets/<int:tid>/buy")
def buy_resale(tid):
    user, err = require_user()
    if err:
        return err
    conn = db()
    l = conn.execute("SELECT * FROM listings WHERE ticket_id=?", (tid,)).fetchone()
    if not l:                          return jsonify(error="not listed"), 404
    t = conn.execute("SELECT * FROM tickets WHERE id=?", (tid,)).fetchone()
    if t["owner_id"] == user["id"]:    return jsonify(error="self purchase"), 400
    conn.execute("UPDATE tickets SET owner_id=? WHERE id=?", (user["id"], tid))
    conn.execute("DELETE FROM listings WHERE ticket_id=?", (tid,))
    conn.commit()
    return jsonify(ok=True)


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
