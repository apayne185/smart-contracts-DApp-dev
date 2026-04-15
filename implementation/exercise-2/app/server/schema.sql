CREATE TABLE IF NOT EXISTS users (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    name      TEXT UNIQUE NOT NULL,
    is_admin  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    price_wei     INTEGER NOT NULL,
    total_supply  INTEGER NOT NULL,
    sold          INTEGER NOT NULL DEFAULT 0,
    event_date    INTEGER NOT NULL,
    active        INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS tickets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id   INTEGER NOT NULL REFERENCES events(id),
    owner_id   INTEGER NOT NULL REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS listings (
    ticket_id  INTEGER PRIMARY KEY REFERENCES tickets(id),
    price_wei  INTEGER NOT NULL,
    seller_id  INTEGER NOT NULL REFERENCES users(id)
);
