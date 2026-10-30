"""Penyimpanan permanen (SQLite). Default di home Termux (bukan /storage),
karena SQLite sering bermasalah di penyimpanan bersama Android."""
import os
import sqlite3
import time

DB_PATH = os.getenv("DB_PATH") or os.path.expanduser("~/.tg-ai-bot/bot.db")
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

_conn = sqlite3.connect(DB_PATH, check_same_thread=False)
_conn.row_factory = sqlite3.Row
_conn.executescript("""
CREATE TABLE IF NOT EXISTS messages(
  id INTEGER PRIMARY KEY AUTOINCREMENT, uid INTEGER, role TEXT, content TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS facts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, uid INTEGER, fact TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS reminders(
  id INTEGER PRIMARY KEY AUTOINCREMENT, uid INTEGER, chat_id INTEGER,
  text TEXT, due REAL, repeat TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS prefs(
  uid INTEGER PRIMARY KEY, agent INTEGER DEFAULT 1, provider TEXT);
""")
_conn.commit()
try:  # migrasi: kolom model pilihan pengguna
    _conn.execute("ALTER TABLE prefs ADD COLUMN model TEXT")
    _conn.commit()
except sqlite3.OperationalError:
    pass


def _run(sql, args=()):
    cur = _conn.execute(sql, args)
    _conn.commit()
    return cur


# ---------- riwayat percakapan ----------
def add_message(uid, role, content):
    _run("INSERT INTO messages(uid,role,content,ts) VALUES(?,?,?,?)",
         (uid, role, content, time.time()))
    _run("DELETE FROM messages WHERE uid=? AND id NOT IN "
         "(SELECT id FROM messages WHERE uid=? ORDER BY id DESC LIMIT 200)", (uid, uid))


def get_history(uid, n=12):
    rows = _run("SELECT role, content FROM messages WHERE uid=? "
                "ORDER BY id DESC LIMIT ?", (uid, n)).fetchall()
    return [{"role": r["role"], "content": r["content"]} for r in reversed(rows)]


def clear_history(uid):
    _run("DELETE FROM messages WHERE uid=?", (uid,))


# ---------- memori jangka panjang ----------
def add_fact(uid, fact):
    n = _run("SELECT COUNT(*) c FROM facts WHERE uid=?", (uid,)).fetchone()["c"]
    if n >= 100:
        return None
    return _run("INSERT INTO facts(uid,fact,ts) VALUES(?,?,?)",
                (uid, fact, time.time())).lastrowid


def list_facts(uid):
    return _run("SELECT id, fact FROM facts WHERE uid=? ORDER BY id", (uid,)).fetchall()


def del_fact(uid, fid):
    return _run("DELETE FROM facts WHERE uid=? AND id=?", (uid, fid)).rowcount > 0


def clear_facts(uid):
    _run("DELETE FROM facts WHERE uid=?", (uid,))


# ---------- pengingat ----------
def add_reminder(uid, chat_id, text, due, repeat=""):
    return _run("INSERT INTO reminders(uid,chat_id,text,due,repeat) VALUES(?,?,?,?,?)",
                (uid, chat_id, text, due, repeat)).lastrowid


def list_reminders(uid):
    return _run("SELECT id, text, due, repeat FROM reminders WHERE uid=? ORDER BY due",
                (uid,)).fetchall()


def del_reminder(uid, rid):
    return _run("DELETE FROM reminders WHERE uid=? AND id=?", (uid, rid)).rowcount > 0


def due_reminders(now):
    return _run("SELECT * FROM reminders WHERE due<=?", (now,)).fetchall()


def advance_or_delete(r, now):
    step = {"daily": 86400, "weekly": 604800}.get(r["repeat"])
    if not step:
        _run("DELETE FROM reminders WHERE id=?", (r["id"],))
        return
    due = r["due"]
    while due <= now:
        due += step
    _run("UPDATE reminders SET due=? WHERE id=?", (due, r["id"]))


# ---------- preferensi ----------
def get_prefs(uid):
    _run("INSERT OR IGNORE INTO prefs(uid) VALUES(?)", (uid,))
    r = _run("SELECT agent, provider, model FROM prefs WHERE uid=?", (uid,)).fetchone()
    return {"agent": bool(r["agent"]), "provider": r["provider"], "model": r["model"]}


def set_agent(uid, on):
    get_prefs(uid)
    _run("UPDATE prefs SET agent=? WHERE uid=?", (1 if on else 0, uid))


def set_provider(uid, name, model=None):
    get_prefs(uid)
    _run("UPDATE prefs SET provider=?, model=? WHERE uid=?", (name, model, uid))


# ---------- sinkronisasi state (untuk failover HP <-> GitHub) ----------
def export_state():
    """Snapshot data penting. Riwayat chat sengaja TIDAK ikut (privasi & ukuran)."""
    return {
        "facts": [dict(r) for r in _run("SELECT id,uid,fact,ts FROM facts").fetchall()],
        "reminders": [dict(r) for r in _run(
            "SELECT id,uid,chat_id,text,due,repeat FROM reminders").fetchall()],
        "prefs": [dict(r) for r in _run("SELECT uid,agent,provider,model FROM prefs").fetchall()],
    }


def import_state(s):
    with _conn:
        _conn.execute("DELETE FROM facts")
        _conn.execute("DELETE FROM reminders")
        _conn.execute("DELETE FROM prefs")
        _conn.executemany("INSERT INTO facts(id,uid,fact,ts) VALUES(:id,:uid,:fact,:ts)",
                          s.get("facts", []))
        _conn.executemany(
            "INSERT INTO reminders(id,uid,chat_id,text,due,repeat) "
            "VALUES(:id,:uid,:chat_id,:text,:due,:repeat)", s.get("reminders", []))
        _conn.executemany(
            "INSERT INTO prefs(uid,agent,provider,model) VALUES(:uid,:agent,:provider,:model)",
            [{"model": None, **p} for p in s.get("prefs", [])])
