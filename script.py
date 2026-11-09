#!/usr/bin/env python3
"""
Bot Telegram AI hybrid, SATU FILE.

Jalankan:  python bot.py            -> meluncurkan bot di latar belakang lalu langsung selesai
Kelola:    python bot.py --status   -> cek apakah bot berjalan
           python bot.py --log [n]  -> lihat n baris terakhir log (default 30)
           python bot.py --stop     -> hentikan bot
           python bot.py --token    -> ganti token bot (hentikan bot dulu)
           python bot.py --watchdog-on|off|status -> penjaga: hidupkan bot lagi bila mati (Termux:API)
Debug:     python bot.py --listen   -> jalan di terminal (tanpa melepas diri)
Semua pengaturan (kunci AI, GitHub, failover) dilakukan lewat Telegram: /setup
Mode internal: --worker, --check, --standby (GitHub Actions)
"""
from __future__ import annotations

import ast
import asyncio
import base64
import hashlib
import hmac
import html as htmlmod
import io
import json
import logging
import operator as op
import os
import re
import secrets
import shlex
import shutil
import signal
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

# Pustaka pihak ketiga: dipasang otomatis saat pertama jalan (mode --check tidak butuh)
try:
    import httpx
except ImportError:
    httpx = None
try:
    from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
    from telegram.constants import ChatAction
    from telegram.error import Conflict, InvalidToken
    from telegram.ext import (ApplicationBuilder, CallbackQueryHandler, CommandHandler,
                              ContextTypes, MessageHandler, filters)
except ImportError:
    pass

# ======================================================================
# KONFIGURASI (disimpan di ~/.tg-ai-bot/config.json, izin 600)
# ======================================================================
APP_DIR = os.path.expanduser(os.environ.get("TGBOT_HOME", "~/.tg-ai-bot"))
os.makedirs(APP_DIR, exist_ok=True)
CFG_PATH = os.path.join(APP_DIR, "config.json")
SELF_PATH = os.path.abspath(__file__)
_cfg: dict = {}

ENV_KEYS = {"TELEGRAM_BOT_TOKEN", "GROQ_API_KEY", "GEMINI_API_KEY", "CEREBRAS_API_KEY",
            "OPENROUTER_API_KEY", "MISTRAL_API_KEY", "NVIDIA_API_KEY", "GITHUB_TOKEN",
            "GIST_TOKEN", "HA_GIST_ID", "GH_USER", "GH_REPO", "GH_PUSH_TOKEN"}


def cfg_load():
    global _cfg
    try:
        with open(CFG_PATH, encoding="utf-8") as f:
            _cfg = json.load(f)
    except (OSError, ValueError):
        _cfg = {}


def cfg_save():
    tmp = CFG_PATH + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(_cfg, f, indent=1)
    os.replace(tmp, CFG_PATH)


def cfg_get(key, default=""):
    """Urutan: variabel lingkungan (GitHub Actions) > config.json."""
    return os.environ.get(key) or _cfg.get(key) or default


def cfg_set(key, value, save=True):
    if value in (None, ""):
        _cfg.pop(key, None)
    else:
        _cfg[key] = value
    if save:
        cfg_save()


def cfg_ids(key):
    v = _cfg.get(key) or []
    if not v and os.environ.get(key):
        v = [x for x in os.environ[key].split(",") if x.strip().isdigit()]
    return [int(x) for x in v]


def import_dotenv():
    """Impor .env lama (di samping script.py atau folder kerja) satu kali saja."""
    path = None
    for d in (os.path.dirname(SELF_PATH), os.getcwd()):
        p = os.path.join(d, ".env")
        if os.path.isfile(p):
            path = p
            break
    if not path:
        return
    owners, got = set(cfg_ids("OWNER_IDS")), set()
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if not v:
                continue
            if k == "ALLOWED_USER_IDS":
                owners |= {int(x) for x in v.split(",") if x.strip().isdigit()}
            elif k in ENV_KEYS and not _cfg.get(k):
                _cfg[k] = v
                got.add(k)
    if owners:
        _cfg["OWNER_IDS"] = sorted(owners)
    if {"GIST_TOKEN", "HA_GIST_ID"} <= got:
        _cfg["FAILOVER"] = "1"
    cfg_save()


# ======================================================================
# ENKRIPSI (hanya stdlib): PBKDF2 + keystream HMAC-SHA256 + tag HMAC (encrypt-then-MAC)
# Dipakai agar konfigurasi di Gist tidak terbaca siapa pun tanpa GIST_TOKEN.
# ======================================================================
def _kdf(secret: str, salt: bytes):
    k = hashlib.pbkdf2_hmac("sha256", secret.encode(), salt, 200_000, 64)
    return k[:32], k[32:]


def _keystream(key: bytes, nonce: bytes, n: int) -> bytes:
    out, ctr = bytearray(), 0
    while len(out) < n:
        out += hmac.new(key, nonce + ctr.to_bytes(8, "big"), hashlib.sha256).digest()
        ctr += 1
    return bytes(out[:n])


def enc_blob(secret: str, data: bytes) -> str:
    salt, nonce = os.urandom(16), os.urandom(16)
    ke, km = _kdf(secret, salt)
    ct = bytes(a ^ b for a, b in zip(data, _keystream(ke, nonce, len(data))))
    tag = hmac.new(km, b"v1" + salt + nonce + ct, hashlib.sha256).digest()
    return base64.b64encode(b"v1" + salt + nonce + ct + tag).decode()


def dec_blob(secret: str, text: str) -> bytes:
    raw = base64.b64decode(text)
    if raw[:2] != b"v1" or len(raw) < 2 + 16 + 16 + 32:
        raise ValueError("format data salah")
    salt, nonce, ct, tag = raw[2:18], raw[18:34], raw[34:-32], raw[-32:]
    ke, km = _kdf(secret, salt)
    good = hmac.new(km, b"v1" + salt + nonce + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, good):
        raise ValueError("kunci salah atau data rusak")
    return bytes(a ^ b for a, b in zip(ct, _keystream(ke, nonce, len(ct))))

# ======================================================================
# DATABASE (SQLite)
# ======================================================================
DB_PATH = os.environ.get("DB_PATH") or os.path.join(APP_DIR, "bot.db")

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
_conn.executescript("""
CREATE TABLE IF NOT EXISTS signals(
  id INTEGER PRIMARY KEY AUTOINCREMENT, uid INTEGER, sym TEXT, strat TEXT, direction TEXT,
  tf TEXT, entry REAL, stop REAL, tp REAL, sig_t INTEGER, status TEXT DEFAULT 'open',
  exit_px REAL, exit_t INTEGER, r REAL,
  UNIQUE(uid, sym, strat, direction, tf, sig_t));
""")
_conn.commit()
for _col in ("model TEXT", "equity REAL", "risk_pct REAL",
             "daily_time TEXT", "daily_chat INTEGER", "last_daily TEXT"):  # migrasi kolom baru
    try:
        _conn.execute(f"ALTER TABLE prefs ADD COLUMN {_col}")
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
    r = _run("SELECT * FROM prefs WHERE uid=?", (uid,)).fetchone()
    return {"agent": bool(r["agent"]), "provider": r["provider"], "model": r["model"],
            "equity": r["equity"], "risk_pct": r["risk_pct"],
            "daily_time": r["daily_time"], "last_daily": r["last_daily"]}


def set_agent(uid, on):
    get_prefs(uid)
    _run("UPDATE prefs SET agent=? WHERE uid=?", (1 if on else 0, uid))


def set_daily(uid, hhmm, chat_id=None):
    get_prefs(uid)
    _run("UPDATE prefs SET daily_time=?, daily_chat=? WHERE uid=?", (hhmm, chat_id, uid))


def mark_daily(uid, day):
    _run("UPDATE prefs SET last_daily=? WHERE uid=?", (day, uid))


def daily_users():
    return _run("SELECT uid, daily_time, daily_chat, last_daily FROM prefs "
                "WHERE daily_time IS NOT NULL AND daily_chat IS NOT NULL").fetchall()


# ---------- pelacak sinyal ----------
def add_signal(uid, sym, strat, direction, tf, entry, stop, tp, sig_t):
    return _run("INSERT OR IGNORE INTO signals(uid,sym,strat,direction,tf,entry,stop,tp,sig_t) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (uid, sym, strat, direction, tf, entry, stop, tp, sig_t)).rowcount > 0


def open_signals():
    return _run("SELECT * FROM signals WHERE status='open'").fetchall()


def close_signal(sid, status, exit_px, exit_t, r):
    _run("UPDATE signals SET status=?, exit_px=?, exit_t=?, r=? WHERE id=?",
         (status, exit_px, exit_t, r, sid))


def resolved_signals(uid):
    return _run("SELECT * FROM signals WHERE uid=? AND status IN ('tp','sl','exp') "
                "ORDER BY exit_t DESC", (uid,)).fetchall()


def open_count(uid):
    return _run("SELECT COUNT(*) c FROM signals WHERE uid=? AND status='open'",
                (uid,)).fetchone()["c"]


def set_risk(uid, equity, risk_pct):
    get_prefs(uid)
    _run("UPDATE prefs SET equity=?, risk_pct=? WHERE uid=?", (equity, risk_pct, uid))


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
        "signals": [dict(r) for r in _run(
            "SELECT * FROM signals ORDER BY id DESC LIMIT 300").fetchall()],
        "prefs": [dict(r) for r in _run("SELECT uid,agent,provider,model,equity,risk_pct,daily_time,daily_chat,last_daily FROM prefs").fetchall()],
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
            "INSERT INTO prefs(uid,agent,provider,model,equity,risk_pct,daily_time,daily_chat,last_daily) "
            "VALUES(:uid,:agent,:provider,:model,:equity,:risk_pct,:daily_time,:daily_chat,:last_daily)",
            [{"model": None, "equity": None, "risk_pct": None, "daily_time": None,
              "daily_chat": None, "last_daily": None, **p} for p in s.get("prefs", [])])
        if "signals" in s:  # snapshot lama tanpa kunci ini tidak menghapus data lokal
            _conn.execute("DELETE FROM signals")
            _conn.executemany(
                "INSERT INTO signals(id,uid,sym,strat,direction,tf,entry,stop,tp,sig_t,status,"
                "exit_px,exit_t,r) VALUES(:id,:uid,:sym,:strat,:direction,:tf,:entry,:stop,:tp,"
                ":sig_t,:status,:exit_px,:exit_t,:r)", s["signals"])

# ======================================================================
# PROVIDER AI (router + pilih model)
# ======================================================================
log = logging.getLogger("providers")

# Kata kunci model yang bukan untuk chat teks
BAD = ("whisper", "tts", "embed", "guard", "safeguard", "orpheus", "playai",
       "image", "imagen", "veo", "rerank", "moderation", "audio", "transcribe",
       "live", "aqa", "retriev", "parse", "reward", "clip", "diffusion",
       "stable", "robotics", "computer-use", "compound")

# Urutan = prioritas. "model" = tebakan awal, "prefer" = urutan pilihan saat
# auto-discovery. Model bisa dipaksa lewat env, mis. GROQ_MODEL=...
PROVIDERS = [
    {"name": "groq", "base": "https://api.groq.com/openai/v1",
     "key": "GROQ_API_KEY", "model": "openai/gpt-oss-120b",
     "prefer": ["gpt-oss-120b", "gpt-oss-20b", "llama-4", "llama-3.3", "qwen", "kimi", "llama"]},
    {"name": "gemini", "base": "https://generativelanguage.googleapis.com/v1beta/openai",
     "key": "GEMINI_API_KEY", "model": "gemini-flash-latest", "vision": True,
     "prefer": ["gemini-flash-latest", "flash-lite", "flash"]},
    {"name": "cerebras", "base": "https://api.cerebras.ai/v1",
     "key": "CEREBRAS_API_KEY", "model": "gpt-oss-120b",
     "prefer": ["gpt-oss-120b", "llama", "qwen"]},
    {"name": "openrouter", "base": "https://openrouter.ai/api/v1",
     "key": "OPENROUTER_API_KEY", "model": "openrouter/free", "only_suffix": ":free",
     "prefer": ["gpt-oss-120b", "llama-3.3-70b", "qwen", "deepseek", "gemma"]},
    {"name": "mistral", "base": "https://api.mistral.ai/v1",
     "key": "MISTRAL_API_KEY", "model": "mistral-small-latest", "vision": True,
     "prefer": ["mistral-small", "mistral-medium", "open-mistral"]},
    {"name": "github", "base": "https://models.github.ai/inference",
     "key": "GITHUB_TOKEN", "model": "openai/gpt-4o-mini", "no_discovery": True,
     "vision": True},
    {"name": "nvidia", "base": "https://integrate.api.nvidia.com/v1",
     "key": "NVIDIA_API_KEY", "model": "openai/gpt-oss-120b",
     "prefer": ["gpt-oss-120b", "llama-3.1-70b", "llama", "qwen", "deepseek"]},
]

COOLDOWN = 60  # detik provider "istirahat" setelah gagal


class Router:
    def __init__(self):
        self.providers = []
        self.client = httpx.AsyncClient(timeout=60)
        self.reload()

    def reload(self):
        """Baca ulang kunci dari konfigurasi (dipanggil setelah /setkey atau /delkey)."""
        old = {p["name"]: p["down_until"] for p in self.providers}
        self.providers = []
        for p in PROVIDERS:
            key = cfg_get(p["key"])
            if not key:
                continue
            pinned = cfg_get(p["name"].upper() + "_MODEL")
            self.providers.append({**p, "api_key": key,
                                   "model": pinned or p["model"],
                                   "pinned": bool(pinned),
                                   "down_until": old.get(p["name"], 0.0)})

    def status(self):
        now = time.time()
        return [(p["name"], p["model"], max(0, int(p["down_until"] - now)))
                for p in self.providers]

    def names(self):
        return [p["name"] for p in self.providers]

    async def _list_ids(self, p):
        """Daftar id model chat milik provider (tanpa model non-chat)."""
        if p["name"] == "github":  # katalog GitHub Models
            r = await self.client.get(
                "https://models.github.ai/catalog/models",
                headers={"Authorization": f"Bearer {p['api_key']}"})
            r.raise_for_status()
            j = r.json()
            items = j if isinstance(j, list) else j.get("data", [])
            ids = [m["id"] for m in items if isinstance(m, dict) and "id" in m]
        else:
            r = await self.client.get(
                p["base"].rstrip("/") + "/models",
                headers={"Authorization": f"Bearer {p['api_key']}"})
            r.raise_for_status()
            ids = [m["id"].removeprefix("models/") for m in r.json().get("data", [])]
            if p.get("only_suffix"):
                ids = [i for i in ids if i.endswith(p["only_suffix"])]
        return sorted({i for i in ids if not any(b in i.lower() for b in BAD)})

    async def list_models(self, name):
        p = next((x for x in self.providers if x["name"] == name), None)
        return await self._list_ids(p) if p else []

    async def _discover(self, p, avoid=None):
        """Pilih otomatis model chat pengganti."""
        ids = [i for i in await self._list_ids(p) if i != avoid]
        for pref in p.get("prefer", []):
            for i in ids:
                if pref in i.lower():
                    return i
        return ids[0] if ids else None

    async def chat(self, messages, prefer=None, temperature=0.4, vision=False, model=None):
        if not self.providers:
            raise RuntimeError("Belum ada kunci AI. Kirim /setkey groq <kunci> "
                               "(gratis di console.groq.com/keys). Lihat /setup")
        order = [p for p in self.providers if p.get("vision")] if vision \
            else list(self.providers)
        if vision and not order:
            raise RuntimeError("Tidak ada provider yang mendukung gambar. "
                               "Tambah kunci gemini/mistral/github lewat /setkey")
        if prefer:
            order.sort(key=lambda p: p["name"] != prefer)
        now = time.time()
        errors = []
        for p in order:
            if p["down_until"] > now and p["name"] != prefer:
                continue
            # model pilihan pengguna hanya berlaku untuk provider pilihannya
            override = model if (model and not vision and p["name"] == prefer) else None
            for attempt in (1, 2):
                try:
                    r = await self.client.post(
                        p["base"].rstrip("/") + "/chat/completions",
                        headers={"Authorization": f"Bearer {p['api_key']}"},
                        json={"model": override or p["model"], "messages": messages,
                              "temperature": temperature},
                    )
                    if r.status_code != 200:
                        # model hilang/dihapus -> cari model pengganti, coba lagi
                        if (r.status_code in (400, 404, 410) and attempt == 1 and not override
                                and not p["pinned"] and not p.get("no_discovery")):
                            new = await self._discover(p, avoid=p["model"])
                            if new:
                                log.info("%s: model diganti %s -> %s",
                                         p["name"], p["model"], new)
                                p["model"] = new
                                continue
                        raise RuntimeError(f"HTTP {r.status_code}: {r.text[:100]}")
                    data = r.json()
                    text = data["choices"][0]["message"]["content"]
                    if not text:
                        raise RuntimeError("respons kosong")
                    # nama model yang benar-benar dipakai (router seperti OpenRouter bisa memilih sendiri)
                    used_model = data.get("model") or override or p["model"]
                    return text.strip(), f"{p['name']} · {used_model}"
                except Exception as e:
                    log.warning("%s gagal: %s", p["name"], e)
                    p["down_until"] = time.time() + COOLDOWN
                    errors.append(f"{p['name']}"
                                  f"{' (' + override + ')' if override else ''}: {str(e)[:120]}")
                    break
        raise RuntimeError("Semua provider gagal:\n" + "\n".join(errors))

# ======================================================================
# TOOLS AGENT
# ======================================================================
TZ = timezone(timedelta(hours=7))  # WIB, tanpa DST
HARI = ["Senin", "Selasa", "Rabu", "Kamis", "Jumat", "Sabtu", "Minggu"]


def fmt_ts(ts: float) -> str:
    d = datetime.fromtimestamp(ts, TZ)
    return d.strftime("%d-%m-%Y %H:%M WIB")


def now_str() -> str:
    d = datetime.now(TZ)
    return f"{HARI[d.weekday()]}, {d.strftime('%Y-%m-%d %H:%M')} WIB"


def _arg(args: dict, *names) -> str:
    for n in names:
        if args.get(n) not in (None, ""):
            return str(args[n])
    return str(next(iter(args.values()), "")) if args else ""


# ---------- kalkulator ----------
_OPS = {ast.Add: op.add, ast.Sub: op.sub, ast.Mult: op.mul, ast.Div: op.truediv,
        ast.Pow: op.pow, ast.Mod: op.mod, ast.USub: op.neg, ast.FloorDiv: op.floordiv}


def _eval(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_eval(node.left), _eval(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_eval(node.operand))
    raise ValueError("ekspresi tidak didukung")


async def calculator(args, ctx):
    try:
        expr = _arg(args, "expression", "expr")
        return str(_eval(ast.parse(expr, mode="eval").body))
    except Exception as e:
        return f"Error: {e}"


async def now(args, ctx):
    return now_str()


# ---------- web ----------
def _clean(s: str) -> str:
    return htmlmod.unescape(re.sub(r"<[^>]+>", "", s)).strip()


async def web_search(args, ctx):
    query = _arg(args, "query", "q")
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=20) as c:
            r = await c.post("https://html.duckduckgo.com/html/", data={"q": query},
                             headers={"User-Agent": "Mozilla/5.0"})
        links = re.findall(
            r'<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', r.text, re.S)
        snips = re.findall(
            r'<a[^>]*class="result__snippet"[^>]*>(.*?)</a>', r.text, re.S)
        out = []
        for i, (href, title) in enumerate(links[:5]):
            real = parse_qs(urlparse(href).query).get("uddg", [href])[0]
            snip = _clean(snips[i]) if i < len(snips) else ""
            out.append(f"{_clean(title)}\n{real}\n{snip}")
        return "\n\n".join(out) or "Tidak ada hasil."
    except Exception as e:
        return f"Error pencarian: {e}"


async def fetch_url(args, ctx):
    url = _arg(args, "url")
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=20) as c:
            r = await c.get(url, headers={"User-Agent": "Mozilla/5.0"})
        h = re.sub(r"(?is)<(script|style).*?</\1>", " ", r.text)
        text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", h)).strip()
        return text[:3500]
    except Exception as e:
        return f"Error: {e}"


# ---------- memori jangka panjang ----------
async def remember(args, ctx):
    fact = _arg(args, "fact", "text")[:300].strip()
    if not fact:
        return "Error: fakta kosong."
    fid = add_fact(ctx["uid"], fact)
    return f"Tersimpan (id {fid})." if fid else "Memori penuh (maks 100). Hapus dulu beberapa."


async def forget_memory(args, ctx):
    try:
        fid = int(_arg(args, "id"))
    except ValueError:
        return "Error: id harus angka."
    return "Terhapus." if del_fact(ctx["uid"], fid) else "Id tidak ditemukan."


# ---------- pengingat ----------
async def set_reminder(args, ctx):
    text = str(args.get("text", "")).strip()
    if not text:
        return "Error: isi pengingat (text) kosong."
    repeat = str(args.get("repeat", "") or "").lower()
    if repeat not in ("daily", "weekly"):
        repeat = ""
    try:
        if args.get("in_minutes") not in (None, ""):
            due = time.time() + float(args["in_minutes"]) * 60
        else:
            t = str(args.get("time", "")).strip()
            due = datetime.strptime(t, "%Y-%m-%d %H:%M").replace(tzinfo=TZ).timestamp()
    except Exception:
        return 'Error: pakai in_minutes (angka) atau time "YYYY-MM-DD HH:MM" (WIB).'
    if due < time.time() - 30:
        return "Error: waktu sudah lewat."
    rid = add_reminder(ctx["uid"], ctx["chat_id"], text, due, repeat)
    extra = f", berulang {repeat}" if repeat else ""
    return f"Pengingat #{rid} diset untuk {fmt_ts(due)}{extra}."


async def tool_list_reminders(args, ctx):
    rows = list_reminders(ctx["uid"])
    if not rows:
        return "Tidak ada pengingat aktif."
    return "\n".join(
        f"#{r['id']} {fmt_ts(r['due'])}{' (' + r['repeat'] + ')' if r['repeat'] else ''}: {r['text']}"
        for r in rows)


async def delete_reminder(args, ctx):
    try:
        rid = int(_arg(args, "id"))
    except ValueError:
        return "Error: id harus angka."
    return "Pengingat dihapus." if del_reminder(ctx["uid"], rid) else "Id tidak ditemukan."


async def scan_market(args, ctx):
    tf = str(args.get("timeframe", "1d")).lower()
    if tf not in ("1d", "4h"):
        tf = "1d"
    data = await run_scan(tf)
    p = get_prefs(ctx["uid"])
    return format_scan(data, p["equity"], p["risk_pct"])


TOOLS = {
    "web_search": (web_search, 'Cari info terbaru di internet. args: {"query": "..."}'),
    "fetch_url": (fetch_url, 'Baca teks sebuah halaman web. args: {"url": "..."}'),
    "calculator": (calculator, 'Hitung matematika. args: {"expression": "2*(3+4)"}'),
    "now": (now, "Tanggal & jam sekarang (WIB). args: {}"),
    "remember": (remember, 'Simpan fakta/preferensi pengguna ke memori jangka panjang. args: {"fact": "..."}'),
    "forget_memory": (forget_memory, 'Hapus fakta dari memori. args: {"id": 3}'),
    "set_reminder": (set_reminder,
                     'Buat pengingat. args: {"text": "...", "in_minutes": 30} ATAU '
                     '{"text": "...", "time": "YYYY-MM-DD HH:MM"} (WIB); opsional "repeat": "daily"|"weekly"'),
    "scan_market": (scan_market,
                    'Pindai koin kripto (data nyata + uji historis + hitungan risiko). '
                    'args: {"timeframe": "1d"|"4h"}. Hasilnya sudah final: salin APA ADANYA, '
                    'jangan ubah angka.'),
    "list_reminders": (tool_list_reminders, "Lihat semua pengingat aktif. args: {}"),
    "delete_reminder": (delete_reminder, 'Hapus pengingat. args: {"id": 2}'),
}


async def run_tool(name: str, args, ctx: dict) -> str:
    if name not in TOOLS:
        return f"Tool '{name}' tidak ada."
    if not isinstance(args, dict):
        args = {"value": args}
    try:
        return str(await TOOLS[name][0](args, ctx))[:3500]
    except Exception as e:
        return f"Error tool: {e}"

# ======================================================================
# AGENT
# ======================================================================
MAX_STEPS = 4


def _facts_text(uid):
    rows = list_facts(uid)
    return "\n".join(f"[{r['id']}] {r['fact']}" for r in rows) or "(belum ada)"


def basic_system(uid):
    return ("Kamu asisten AI di Telegram. Jawab dalam bahasa pengguna, ringkas dan jelas.\n"
            f"Waktu sekarang: {now_str()}\n\n"
            f"Hal yang kamu ketahui tentang pengguna:\n{_facts_text(uid)}")


def agent_system(uid):
    tool_list = "\n".join(f"- {n}: {d[1]}" for n, d in TOOLS.items())
    return f"""{basic_system(uid)}

Kamu punya tools:
{tool_list}

ATURAN FORMAT:
- Jika butuh tool, balas HANYA JSON: {{"tool": "nama_tool", "args": {{...}}}}
- Jika siap menjawab, balas HANYA JSON: {{"final": "jawaban untuk pengguna"}}
- Obrolan biasa atau pertanyaan umum: langsung jawab dengan final.
- Gunakan tool hanya bila perlu (info terbaru, hitungan, baca link, pengingat, memori).
- Pengingat: hitung waktu dari "Waktu sekarang". Pakai in_minutes untuk "X menit/jam lagi" (jam x 60).
- DILARANG menyebut sinyal trading, rekomendasi beli/jual, atau harga koin dari ingatan.
  Untuk mencari koin/sinyal WAJIB panggil scan_market; untuk harga pakai web_search.
- Panggil remember bila pengguna minta "ingat ..." atau menyebut info pribadi yang berguna
  jangka panjang (nama, kebiasaan, proyek). JANGAN simpan password, API key, atau data sensitif."""


def _parse(text: str):
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except json.JSONDecodeError:
        return None


async def run_agent(router, history, user_text, ctx, prefer=None, model=None):
    """Return (jawaban, provider_terakhir, daftar_tool_dipakai)."""
    msgs = [{"role": "system", "content": agent_system(ctx["uid"])}] + history + [
        {"role": "user", "content": user_text}]
    used_tools = []
    provider = None
    for _ in range(MAX_STEPS):
        reply, provider = await router.chat(msgs, prefer, model=model)
        data = _parse(reply)
        if not isinstance(data, dict):
            return reply, provider, used_tools
        if "final" in data:
            return str(data["final"]), provider, used_tools
        if "tool" in data:
            name, args = data["tool"], data.get("args", {}) or {}
            used_tools.append(name)
            result = await run_tool(name, args, ctx)
            msgs.append({"role": "assistant", "content": reply})
            msgs.append({"role": "user",
                         "content": f"HASIL_TOOL {name}:\n{result}\n\n"
                                    "Lanjutkan: panggil tool lain atau balas final."})
        else:
            return reply, provider, used_tools
    msgs.append({"role": "user", "content": 'Berikan jawaban akhir sekarang: {"final": "..."}'})
    reply, provider = await router.chat(msgs, prefer, model=model)
    data = _parse(reply)
    return (str(data["final"]) if isinstance(data, dict) and "final" in data else reply), \
        provider, used_tools

# ======================================================================
# PEMINDAI KOIN
# ======================================================================
BASES = ["https://data-api.binance.vision", "https://api.binance.com"]
STABLES = {"USDC", "FDUSD", "TUSD", "USDP", "DAI", "BUSD", "EUR", "AEUR", "USD1",
           "PYUSD", "XUSD", "UST", "USDE", "RLUSD", "EURI", "USDT"}
LEVERAGED = ("UP", "DOWN", "BULL", "BEAR")
MIN_QUOTE_VOL = 10_000_000          # USDT per 24 jam
MAXH = {"1d": 15, "4h": 30}          # batas lama posisi (jumlah candle)
ATR_K = 1.5                          # stop = 1.5 x ATR
RR = 2.0                             # target = 2 x risiko
COST = 0.003                         # biaya pulang-pergi (fee 0.1%/sisi + slippage 0.05%/sisi)
WIB = timezone(timedelta(hours=7))
_cache = {}


# ------------------------------------------------------------------ indikator
def ema(vals, n):
    out = [None] * len(vals)
    if len(vals) < n:
        return out
    e = sum(vals[:n]) / n
    out[n - 1] = e
    k = 2 / (n + 1)
    for i in range(n, len(vals)):
        e = vals[i] * k + e * (1 - k)
        out[i] = e
    return out


def rsi(c, n=14):
    out = [None] * len(c)
    if len(c) <= n:
        return out
    g = [max(c[i] - c[i - 1], 0) for i in range(1, n + 1)]
    l_ = [max(c[i - 1] - c[i], 0) for i in range(1, n + 1)]
    ag, al = sum(g) / n, sum(l_) / n
    out[n] = 100 if al == 0 else 100 - 100 / (1 + ag / al)
    for i in range(n + 1, len(c)):
        d = c[i] - c[i - 1]
        ag = (ag * (n - 1) + max(d, 0)) / n
        al = (al * (n - 1) + max(-d, 0)) / n
        out[i] = 100 if al == 0 else 100 - 100 / (1 + ag / al)
    return out


def _tr(h, l, c):
    tr = [0.0] * len(c)
    for i in range(1, len(c)):
        tr[i] = max(h[i] - l[i], abs(h[i] - c[i - 1]), abs(l[i] - c[i - 1]))
    return tr


def atr(h, l, c, n=14):
    out = [None] * len(c)
    if len(c) <= n:
        return out
    tr = _tr(h, l, c)
    a = sum(tr[1:n + 1]) / n
    out[n] = a
    for i in range(n + 1, len(c)):
        a = (a * (n - 1) + tr[i]) / n
        out[i] = a
    return out


def adx(h, l, c, n=14):
    L = len(c)
    out = [None] * L
    if L < 2 * n + 1:
        return out
    tr = _tr(h, l, c)
    pdm, ndm = [0.0] * L, [0.0] * L
    for i in range(1, L):
        up, dn = h[i] - h[i - 1], l[i - 1] - l[i]
        pdm[i] = up if (up > dn and up > 0) else 0.0
        ndm[i] = dn if (dn > up and dn > 0) else 0.0

    def dxv(a, p, m):
        if a == 0:
            return 0.0
        pi, mi = 100 * p / a, 100 * m / a
        s = pi + mi
        return 0.0 if s == 0 else 100 * abs(pi - mi) / s

    a, p, m = sum(tr[1:n + 1]), sum(pdm[1:n + 1]), sum(ndm[1:n + 1])
    dx = [None] * L
    dx[n] = dxv(a, p, m)
    for i in range(n + 1, L):
        a = a - a / n + tr[i]
        p = p - p / n + pdm[i]
        m = m - m / n + ndm[i]
        dx[i] = dxv(a, p, m)
    v = sum(dx[n:2 * n]) / n
    out[2 * n - 1] = v
    for i in range(2 * n, L):
        v = (v * (n - 1) + dx[i]) / n
        out[i] = v
    return out


# ------------------------------------------------------------------ strategi
def prepare(rows):
    d = {"t": [r[0] for r in rows], "ct": [r[6] for r in rows],
         "o": [float(r[1]) for r in rows], "h": [float(r[2]) for r in rows],
         "l": [float(r[3]) for r in rows], "c": [float(r[4]) for r in rows],
         "v": [float(r[5]) for r in rows]}
    d["e50"], d["e200"] = ema(d["c"], 50), ema(d["c"], 200)
    d["rsi"] = rsi(d["c"])
    d["atr"] = atr(d["h"], d["l"], d["c"])
    d["adx"] = adx(d["h"], d["l"], d["c"])
    return d


def signals_at(i, d):
    """Sinyal pada candle ke-i yang SUDAH tertutup (hanya data sampai i)."""
    if i < 205:
        return []
    c, h, v = d["c"], d["h"], d["v"]
    need = (d["e50"][i], d["e200"][i], d["rsi"][i], d["rsi"][i - 1], d["atr"][i], d["adx"][i])
    if any(x is None for x in need):
        return []
    e50, e200, r, rp, a, ax = need
    out = []
    if ax < 20:                      # pasar sideways: lewati
        return out
    vma = sum(v[i - 20:i]) / 20
    hh, ll = max(h[i - 20:i]), min(d["l"][i - 20:i])
    if c[i] > e200 and e50 > e200:   # tren naik
        if rp < 40 <= r and c[i] > c[i - 1]:
            out.append(("pullback", "long"))
        if c[i] > hh and v[i] >= 1.5 * vma and c[i] - e50 <= 3 * a:
            out.append(("breakout", "long"))
    if c[i] < e200 and e50 < e200:   # tren turun
        if rp > 60 >= r and c[i] < c[i - 1]:
            out.append(("pullback", "short"))
        if c[i] < ll and v[i] >= 1.5 * vma and e50 - c[i] <= 3 * a:
            out.append(("breakout", "short"))
    return out


def levels(entry, a, direction):
    risk = ATR_K * a
    if risk <= 0 or risk / entry < 0.004 or risk / entry > 0.15:
        return None                   # stop terlalu sempit/lebar -> tidak layak
    if direction == "long":
        return entry - risk, entry + RR * risk, risk
    return entry + risk, entry - RR * risk, risk


def simulate(d, i, direction, maxh):
    n = len(d["c"])
    if i + 1 >= n:
        return None
    entry = d["o"][i + 1]            # masuk di open candle berikutnya (tanpa lookahead)
    lv = levels(entry, d["atr"][i], direction)
    if not lv:
        return None
    stop, tp, risk = lv
    long = direction == "long"
    last = min(i + maxh, n - 1)
    exit_px, j = None, i + 1
    for j in range(i + 1, last + 1):
        hi, lo = d["h"][j], d["l"][j]
        hit_stop = lo <= stop if long else hi >= stop
        hit_tp = hi >= tp if long else lo <= tp
        if hit_stop:                  # konservatif: bila stop & target satu candle, anggap stop dulu
            exit_px = stop
            break
        if hit_tp:
            exit_px = tp
            break
    else:
        if i + maxh > n - 1:          # posisi belum selesai di ujung data -> jangan dihitung
            return None
        exit_px = d["c"][last]
        j = last
    r = (exit_px - entry) / risk * (1 if long else -1) - COST * entry / risk
    return {"R": r, "t": d["t"][i + 1], "exit": j}


def backtest(d, maxh):
    res, busy = {}, {}
    for i in range(205, len(d["c"]) - 1):
        for strat, direction in signals_at(i, d):
            key = (strat, direction)
            if busy.get(key, -1) >= i:
                continue
            t = simulate(d, i, direction, maxh)
            if t:
                busy[key] = t["exit"]
                res.setdefault(key, []).append((t["t"], t["R"]))
    return res


def stats(rs):
    n = len(rs)
    if not n:
        return {"n": 0, "win": 0.0, "exp": 0.0, "pf": 0.0}
    wins = sum(r for r in rs if r > 0)
    loss = abs(sum(r for r in rs if r <= 0))
    return {"n": n, "win": sum(1 for r in rs if r > 0) / n, "exp": sum(rs) / n,
            "pf": (wins / loss) if loss else float("inf")}


def gate(trades):
    """Lolos hanya bila untung setelah biaya di seluruh data DAN di kedua bagian waktu."""
    trades = sorted(trades)
    rs = [r for _, r in trades]
    cut = int(len(rs) * 0.6)
    a, b, s = stats(rs[:cut]), stats(rs[cut:]), stats(rs)
    ok = (s["n"] >= 60 and a["n"] >= 20 and b["n"] >= 20 and s["exp"] > 0.10
          and a["exp"] > 0.03 and b["exp"] > 0.03 and s["pf"] >= 1.15)
    return {**s, "is": a["exp"], "oos": b["exp"], "pass": ok}


INTERVAL_MS = {"1d": 86_400_000, "4h": 14_400_000}


def resolve(sig, rows, tf):
    """Cek hasil sinyal yang dicatat: (status, harga_keluar, waktu, R) atau None bila masih berjalan.
    Konservatif: bila SL & TP tersentuh di candle yang sama, dianggap SL."""
    entry, stop, tp = sig["entry"], sig["stop"], sig["tp"]
    long = sig["direction"] == "long"
    risk = abs(entry - stop)
    after = [r for r in rows if r[0] > sig["sig_t"]]
    if after and after[0][0] > sig["sig_t"] + 2 * INTERVAL_MS[tf]:
        return "unk", entry, after[0][0], None        # data awal hilang (bot lama mati)

    def rr(px):
        return (px - entry) / risk * (1 if long else -1) - COST * entry / risk

    for n, r in enumerate(after, 1):
        hi, lo, cl = float(r[2]), float(r[3]), float(r[4])
        if (lo <= stop) if long else (hi >= stop):
            return "sl", stop, r[6], rr(stop)
        if (hi >= tp) if long else (lo <= tp):
            return "tp", tp, r[6], rr(tp)
        if n >= MAXH[tf]:
            return "exp", cl, r[6], rr(cl)
    return None


# ------------------------------------------------------------------ data
async def _get(client, path, params=None):
    last = None
    for base in BASES:
        try:
            r = await client.get(base + path, params=params)
            if r.status_code == 200:
                return r.json()
            last = f"HTTP {r.status_code}"
        except Exception as e:
            last = str(e)[:80]
    raise RuntimeError(f"Tidak bisa mengambil data Binance ({last}). "
                       "Jaringan/negaramu mungkin memblokirnya.")


async def universe(client, top):
    rows = await _get(client, "/api/v3/ticker/24hr")
    out = []
    for x in rows:
        s = x.get("symbol", "")
        if not s.endswith("USDT"):
            continue
        base = s[:-4]
        if base in STABLES or base.endswith(LEVERAGED):
            continue
        qv = float(x.get("quoteVolume", 0) or 0)
        if qv >= MIN_QUOTE_VOL:
            out.append((s, qv))
    out.sort(key=lambda z: -z[1])
    return out[:top]


async def klines(client, sym, tf, limit=1000):
    rows = await _get(client, "/api/v3/klines", {"symbol": sym, "interval": tf, "limit": limit})
    if rows and rows[-1][6] > time.time() * 1000:   # buang candle yang belum tertutup
        rows = rows[:-1]
    return rows


# ------------------------------------------------------------------ analisis
def analyze(res, tf):
    maxh = MAXH[tf]
    pool, per_coin, cands = {}, {}, []
    btc_up, asof, used = None, None, 0
    for sym, vol, rows in res:
        if not rows or len(rows) < 260:
            continue
        d = prepare(rows)
        used += 1
        if sym == "BTCUSDT":
            if d["e200"][-1] is not None:
                btc_up = d["c"][-1] > d["e200"][-1]
            asof = d["ct"][-1]
        for key, lst in backtest(d, maxh).items():
            pool.setdefault(key, []).extend(lst)
            per_coin[(sym, key)] = [r for _, r in lst]
        n = len(d["c"]) - 1
        for strat, direction in signals_at(n, d):
            lv = levels(d["c"][n], d["atr"][n], direction)
            if lv:
                cands.append({"sym": sym, "vol": vol, "key": (strat, direction),
                              "entry": d["c"][n], "stop": lv[0], "tp": lv[1],
                              "adx": d["adx"][n], "rsi": d["rsi"][n]})
    gates = {k: gate(v) for k, v in pool.items()}
    sigs = []
    for c in cands:
        g = gates.get(c["key"])
        if not g or not g["pass"]:
            continue
        cs = stats(per_coin.get((c["sym"], c["key"]), []))
        sigs.append({**c, "g": g, "coin": cs})
    sigs.sort(key=lambda s: (-s["g"]["exp"], -(s["coin"]["exp"] if s["coin"]["n"] >= 5 else 0), -s["vol"]))
    seen, uniq = set(), []
    for s in sigs:
        if s["sym"] not in seen:
            seen.add(s["sym"])
            uniq.append(s)
    return {"tf": tf, "used": used, "asof": asof, "btc_up": btc_up, "gates": gates,
            "signals": uniq[:5], "n_cands": len(cands)}


async def run_scan(tf="1d", top=60, force=False):
    if tf not in MAXH:
        raise ValueError("Timeframe: 1d atau 4h")
    key = (tf, top)
    c = _cache.get(key)
    if c and not force and time.time() - c[0] < 900:
        return c[1]
    async with httpx.AsyncClient(timeout=25) as client:
        syms = await universe(client, top)
        sem = asyncio.Semaphore(8)

        async def one(s, v):
            async with sem:
                try:
                    return s, v, await klines(client, s, tf)
                except Exception:
                    return s, v, None
        res = await asyncio.gather(*[one(s, v) for s, v in syms])
    data = await asyncio.to_thread(analyze, res, tf)
    _cache[key] = (time.time(), data)
    return data


# ------------------------------------------------------------------ tampilan
def fp(p):
    if p >= 1000:
        return f"{p:.1f}"
    if p >= 1:
        return f"{p:.4f}".rstrip("0").rstrip(".")
    return f"{p:.8f}".rstrip("0").rstrip(".")


def fq(q):
    if q >= 1000:
        return f"{q:.0f}"
    if q >= 1:
        return f"{q:.3f}".rstrip("0").rstrip(".")
    return f"{q:.6f}".rstrip("0").rstrip(".")


def sizing(s, equity, risk_pct):
    entry, stop = s["entry"], s["stop"]
    dist = abs(entry - stop)
    risk_amt = equity * risk_pct / 100
    qty = risk_amt / dist
    notional = qty * entry
    long = s["key"][1] == "long"
    note = ""
    if long and notional > equity:   # spot: tidak boleh melebihi modal
        qty = equity / entry
        notional = equity
        risk_amt = qty * dist
        note = " (dibatasi modal spot)"
    lev = notional / equity
    if not long:
        note = f" — butuh futures ±{lev:.1f}x" + (" ⚠️ tinggi" if lev > 3 else "")
    return (f"Risiko {risk_amt:.2f} USDT → {fq(qty)} {s['sym'][:-4]} ≈ {notional:.0f} USDT{note}")


NAMES = {"pullback": "pullback tren", "breakout": "breakout volume"}


def format_scan(data, equity=None, risk_pct=None):
    tf = data["tf"]
    when = ""
    if data["asof"]:
        when = datetime.fromtimestamp(data["asof"] / 1000, WIB).strftime("%d-%m %H:%M WIB")
    lines = [f"📊 Pemindaian {tf} · {data['used']} koin likuid · candle tutup {when}"]
    if data["btc_up"] is not None:
        lines.append("BTC: " + ("di atas EMA200 (tren naik)" if data["btc_up"]
                                else "di bawah EMA200 (tren turun) – long lebih berisiko"))
    lines.append("\nUji historis gabungan (setelah biaya):")
    for (strat, d_), g in sorted(data["gates"].items()):
        mark = "✅" if g["pass"] else "❌"
        lines.append(f"{mark} {NAMES[strat]} {d_}: {g['n']} trade, win {g['win']*100:.0f}%, "
                     f"{g['exp']:+.2f}R (awal {g['is']:+.2f} / akhir {g['oos']:+.2f})")
    sigs = data["signals"]
    if not sigs:
        lines.append("\nTidak ada setup yang lolos saat ini. Itu normal — tidak memaksa "
                     "entry adalah bagian dari disiplin.")
    for i, s in enumerate(sigs, 1):
        strat, d_ = s["key"]
        pct = abs(s["entry"] - s["stop"]) / s["entry"] * 100
        lines.append(f"\n{i}) {s['sym']} {d_.upper()} · {NAMES[strat]}\n"
                     f"Entry ≈ {fp(s['entry'])} | SL {fp(s['stop'])} (−{pct:.1f}%) | "
                     f"TP {fp(s['tp'])} (+{pct*RR:.1f}%) | RR 1:{RR:g}")
        if s["coin"]["n"] >= 5:
            lines.append(f"Riwayat koin ini: {s['coin']['n']} trade, {s['coin']['exp']:+.2f}R"
                         + (" ⚠️ negatif" if s["coin"]["exp"] < 0 else ""))
        if equity and risk_pct:
            lines.append(sizing(s, equity, risk_pct))
    if sigs and not (equity and risk_pct):
        lines.append("\nAtur modal & risiko: /risk 500 1 (modal 500 USDT, risiko 1%/trade)")
    lines.append("\n⚠️ Bukan nasihat keuangan. Backtest tidak menjamin hasil; koin yang sudah mati "
                 "tidak ikut diuji (bias optimis). Tetap pasang SL, risiko ≤1–2% per trade, "
                 "maks 3 posisi sekaligus.")
    return "\n".join(lines)

# ======================================================================
# PELACAK SINYAL
# ======================================================================
ICON = {"tp": "✅", "sl": "❌", "exp": "⏱"}


def record(uid, data):
    t = data.get("asof") or int(time.time() * 1000)
    n = 0
    for s in data["signals"]:
        n += add_signal(uid, s["sym"], s["key"][0], s["key"][1], data["tf"],
                           s["entry"], s["stop"], s["tp"], t)
    return n


async def update_open():
    rows = open_signals()
    if not rows:
        return 0
    need = {(r["sym"], r["tf"]) for r in rows}
    sem = asyncio.Semaphore(6)
    async with httpx.AsyncClient(timeout=25) as client:
        async def one(sym, tf):
            async with sem:
                try:
                    return (sym, tf), await klines(client, sym, tf, 100 if tf == "4h" else 40)
                except Exception:
                    return (sym, tf), None
        got = dict(await asyncio.gather(*[one(s, t) for s, t in need]))
    closed = 0
    for r in rows:
        k = got.get((r["sym"], r["tf"]))
        if not k:
            continue
        res = resolve(dict(r), k, r["tf"])
        if res:
            close_signal(r["id"], *res)
            closed += 1
    return closed


def summary(uid):
    rows = resolved_signals(uid)
    openn = open_count(uid)
    if not rows:
        return f"📈 Pelacak: belum ada sinyal yang selesai ({openn} masih berjalan)."
    rs = [r["r"] for r in rows]
    st = stats(rs)
    txt = (f"📈 Pelacak: {st['n']} sinyal selesai ({openn} berjalan) · win {st['win']*100:.0f}% · "
           f"rata-rata {st['exp']:+.2f}R · total {sum(rs):+.1f}R")
    if st["n"] < 30:
        txt += "\n(Sampel masih kecil, belum bisa disimpulkan. Tunggu ≥30 sinyal.)"
    return txt


def report(uid, n=8):
    lines = [summary(uid)]
    for r in resolved_signals(uid)[:n]:
        lines.append(f"{ICON.get(r['status'], '•')} {r['sym']} {r['direction'].upper()} "
                     f"({r['tf']}) {r['r']:+.2f}R")
    return "\n".join(lines)


def is_due(daily_time, now, last_daily, window_min=180):
    """Waktunya laporan harian? Boleh terlambat sampai 3 jam (bila bot sempat mati)."""
    if not daily_time or last_daily == now.strftime("%Y-%m-%d"):
        return False
    h, m = (int(x) for x in daily_time.split(":"))
    diff = now.hour * 60 + now.minute - (h * 60 + m)
    return 0 <= diff <= window_min

# ======================================================================
# GITHUB: API, FAILOVER (Gist) DAN UNGGAH OTOMATIS
# ======================================================================
NODE_ROLE = "phone"          # menjadi "github" pada mode --standby
GH_API = "https://api.github.com"
HA_STALE = int(os.environ.get("HA_STALE_SECONDS", "120"))
HANDOFF_WAIT = int(os.environ.get("HA_HANDOFF_WAIT", "30"))
SYNC_KEYS = ["TELEGRAM_BOT_TOKEN", "GROQ_API_KEY", "GEMINI_API_KEY", "CEREBRAS_API_KEY",
             "OPENROUTER_API_KEY", "MISTRAL_API_KEY", "NVIDIA_API_KEY", "GITHUB_TOKEN",
             "OWNER_IDS", "USER_IDS"]

REQUIREMENTS = "python-telegram-bot>=21.0\nhttpx>=0.27\npypdf>=4.0\n"
OBSOLETE = ["bot.py", "agent.py", "db.py", "ha.py", "ha_check.py", "providers.py", "tools.py",
            "scanner.py", "tracker.py", "run.sh", "deploy.sh", "requirements_termux.txt",
            ".gitignore", "Dockerfile", ".dockerignore"]

WORKFLOW = """name: standby-bot

on:
  schedule:
    - cron: "*/5 * * * *"
  workflow_dispatch:

concurrency:
  group: bot-standby
  cancel-in-progress: false

permissions:
  contents: read
  actions: write

jobs:
  standby:
    runs-on: ubuntu-latest
    timeout-minutes: 350
    steps:
      - uses: actions/checkout@v4

      - name: Cek apakah HP masih aktif
        id: check
        env:
          GIST_TOKEN: ${{ secrets.GIST_TOKEN }}
          HA_GIST_ID: ${{ vars.HA_GIST_ID || secrets.HA_GIST_ID }}
        run: python3 script.py --check

      - uses: actions/setup-python@v5
        if: steps.check.outputs.standby == 'true'
        with:
          python-version: "3.12"

      - name: Pasang dependensi
        if: steps.check.outputs.standby == 'true'
        run: pip install -r requirements.txt

      - name: Jalankan bot (cadangan)
        id: bot
        if: steps.check.outputs.standby == 'true'
        env:
          GIST_TOKEN: ${{ secrets.GIST_TOKEN }}
          HA_GIST_ID: ${{ vars.HA_GIST_ID || secrets.HA_GIST_ID }}
          HOST_MAX_SECONDS: "19800"
        run: |
          set +e
          echo "t0=$(date +%s)" >> "$GITHUB_OUTPUT"
          python script.py --standby
          echo "code=$?" >> "$GITHUB_OUTPUT"

      # Hanya menyambung bila langkah bot BENAR-BENAR berjalan, selesai karena batas waktu (kode 0),
      # dan sudah berjalan lama. (Langkah yang dilewati bernilai null, dan null == '0' dianggap benar
      # oleh GitHub, itu penyebab perulangan sebelumnya.)
      - name: Sambung ke run berikutnya
        if: steps.bot.outcome == 'success' && steps.bot.outputs.code == '0'
        env:
          GH_TOKEN: ${{ github.token }}
          T0: ${{ steps.bot.outputs.t0 }}
        run: |
          if [ $(( $(date +%s) - T0 )) -lt 3600 ]; then
            echo "Berjalan terlalu singkat, tidak menyambung (cegah perulangan)"
            exit 0
          fi
          gh workflow run standby.yml
"""


def _http(method, url, token, body=None, timeout=25):
    """Panggilan HTTP sinkron. Return (status, json|None); tidak melempar untuk status error."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, method=method, data=data, headers={
        "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "tg-ai-bot"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read().decode() or "null")
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read().decode() or "null")
        except Exception:
            payload = None
        return e.code, payload


# ---------------------------------------------------------------- Gist (papan giliran)
def ha_enabled():
    return bool(cfg_get("HA_GIST_ID") and cfg_get("GIST_TOKEN")
                and (NODE_ROLE == "github" or cfg_get("FAILOVER") == "1"))


def _gist(method="GET", body=None):
    st, js = _http(method, f"{GH_API}/gists/{cfg_get('HA_GIST_ID')}", cfg_get("GIST_TOKEN"), body)
    if st >= 300:
        raise RuntimeError(f"Gist HTTP {st}")
    return js


def _file_text(gist, name):
    f = (gist.get("files") or {}).get(name)
    if not f:
        return ""
    if f.get("truncated") and f.get("raw_url"):
        with urllib.request.urlopen(f["raw_url"], timeout=20) as r:
            return r.read().decode()
    return f.get("content") or ""


def _file_json(gist, name):
    try:
        return json.loads(_file_text(gist, name))
    except Exception:
        return {}


def ha_read_all():
    g = _gist()
    return {"lease": _file_json(g, "lease.json"), "state": _file_json(g, "state.json"),
            "config": _file_text(g, "config.enc")}


def ha_lease_fresh(lease, holder=None):
    return (bool(lease) and time.time() - lease.get("ts", 0) < HA_STALE
            and (holder is None or lease.get("holder") == holder))


def ha_write(holder=None, state=None, by=None, config=None):
    """holder: 'phone'|'github'|'none' (none = dilepas)."""
    files = {}
    if holder is not None:
        files["lease.json"] = {"content": json.dumps(
            {"holder": holder, "ts": 0 if holder == "none" else time.time()})}
    if state is not None:
        files["state.json"] = {"content": json.dumps({"by": by, "ts": time.time(), "data": state})}
    if config is not None:
        files["config.enc"] = {"content": config}
    if files:
        _gist("PATCH", {"files": files})


def ha_create():
    body = {"description": "tg-ai-bot failover", "public": False,
            "files": {"lease.json": {"content": "{}"}, "state.json": {"content": "{}"},
                      "config.enc": {"content": "-"}}}
    st, js = _http("POST", f"{GH_API}/gists", cfg_get("GIST_TOKEN"), body)
    if st >= 300:
        raise RuntimeError(f"Gagal membuat Gist (HTTP {st}). Token harus klasik dengan scope 'gist'.")
    return js["id"]


def config_blob():
    data = {k: _cfg[k] for k in SYNC_KEYS if _cfg.get(k)}
    return enc_blob(cfg_get("GIST_TOKEN"), json.dumps(data).encode())


def ha_pull_config(text):
    """Isi konfigurasi (di memori saja) dari Gist terenkripsi. Return True bila berhasil."""
    if not text or text.strip() == "-":
        return False
    try:
        data = json.loads(dec_blob(cfg_get("GIST_TOKEN"), text))
    except Exception as e:
        logging.warning("Gagal membuka konfigurasi Gist: %s", e)
        return False
    for k, v in data.items():
        if not os.environ.get(k):
            _cfg[k] = v
    if os.environ.get("GITHUB_ACTIONS") == "true":   # log repo publik: sembunyikan semua nilai rahasia
        for v in data.values():
            if isinstance(v, str) and len(v) >= 8:
                print(f"::add-mask::{v}", flush=True)
    return True


async def sync_config():
    """Dorong konfigurasi terbaru ke Gist (hanya di HP dan bila failover aktif)."""
    if NODE_ROLE == "phone" and ha_enabled():
        try:
            await asyncio.to_thread(ha_write, None, None, None, config_blob())
        except Exception as e:
            logging.warning("sync_config: %s", e)


def _ha_startup() -> bool:
    """True = lanjut jalan. False = node ini harus standby/keluar."""
    try:
        data = ha_read_all()
    except Exception as e:
        logging.warning("HA: gagal membaca gist: %s", e)
        return NODE_ROLE == "phone"        # HP tetap jalan; GitHub tidak (hindari bentrok)
    lease, state = data["lease"], data["state"]
    if NODE_ROLE == "github":
        if ha_lease_fresh(lease, "phone"):
            logging.info("HP aktif -> GitHub standby, keluar")
            return False
        if not ha_pull_config(data["config"]):
            raise RuntimeError("konfigurasi belum disinkronkan dari HP (jalankan bot di HP sekali)")
        ha_write(holder="github")
        if state.get("data"):
            import_state(state["data"])
        return True
    took_over = ha_lease_fresh(lease, "github")        # HP selalu prioritas
    ha_write(holder="phone")
    if took_over:
        logging.info("HP kembali: meminta GitHub berhenti, tunggu %ss", HANDOFF_WAIT)
        time.sleep(HANDOFF_WAIT)
        try:
            state = ha_read_all()["state"]
        except Exception:
            pass
    if state.get("by") == "github" and state.get("data"):
        import_state(state["data"])
    try:
        ha_write(config=config_blob())
    except Exception as e:
        logging.warning("HA: sinkron konfigurasi gagal: %s", e)
    return True


def ha_startup() -> bool:
    if not ha_enabled():
        return True
    try:
        return _ha_startup()
    except Exception as e:
        logging.warning("HA gagal (%s). %s", e,
                        "Bot HP tetap jalan tanpa failover." if NODE_ROLE == "phone"
                        else "GitHub tidak jalan.")
        return NODE_ROLE == "phone"


def _snapshot():
    snap = export_state()
    return snap, hashlib.md5(json.dumps(snap, sort_keys=True).encode()).hexdigest()


async def notify_owners(app, text):
    for uid in cfg_ids("OWNER_IDS"):
        try:
            await app.bot.send_message(uid, text)
        except Exception as e:
            logging.warning("notifikasi ke %s gagal: %s", uid, e)


async def ha_loop(app):
    role = NODE_ROLE
    max_seconds = int(os.environ.get("HOST_MAX_SECONDS", "0"))   # 0 = tanpa batas (HP)
    interval = 15 if role == "github" else 30
    started = time.time()
    last_hash, tick = None, 0
    while True:
        await asyncio.sleep(interval)
        tick += 1
        try:
            if time.time() - started > 60 and getattr(app.updater, "running", True) is False:
                logging.error("Polling berhenti, keluar agar dimulai ulang")
                os._exit(1)
            lease = (await asyncio.to_thread(ha_read_all))["lease"]
            if role == "github":
                if ha_lease_fresh(lease, "phone"):
                    snap, _ = _snapshot()
                    await asyncio.to_thread(ha_write, None, snap, "github")
                    await notify_owners(app, "📱 HP aktif lagi. Cadangan GitHub berhenti.")
                    os._exit(10)
                if max_seconds and time.time() - started > max_seconds:
                    snap, _ = _snapshot()
                    await asyncio.to_thread(ha_write, "none", snap, "github")
                    os._exit(0)
                if tick % 2:                 # tulis lease tiap ~30 dtk (hindari rate limit)
                    continue
            snap, h = _snapshot()
            await asyncio.to_thread(ha_write, role, snap if h != last_hash else None, role)
            last_hash = h
        except Exception as e:
            logging.warning("ha_loop: %s", e)


# ---------------------------------------------------------------- unggah ke GitHub
def _gh(method, path, body=None):
    return _http(method, GH_API + path, cfg_get("GH_PUSH_TOKEN"), body)


def gh_configured():
    return bool(cfg_get("GH_USER") and cfg_get("GH_REPO") and cfg_get("GH_PUSH_TOKEN"))


def set_repo_var(name, value):
    user, repo = cfg_get("GH_USER"), cfg_get("GH_REPO")
    st, _ = _gh("POST", f"/repos/{user}/{repo}/actions/variables", {"name": name, "value": value})
    if st in (409, 422):
        st, _ = _gh("PATCH", f"/repos/{user}/{repo}/actions/variables/{name}",
                    {"name": name, "value": value})
    return st < 300


def gh_workflow(enable: bool):
    user, repo = cfg_get("GH_USER"), cfg_get("GH_REPO")
    st, _ = _gh("PUT", f"/repos/{user}/{repo}/actions/workflows/standby.yml/"
                       f"{'enable' if enable else 'disable'}")
    return st < 300


def github_deploy():
    """Unggah script.py + workflow ke repo. Return (daftar_baris, url_repo)."""
    user, repo = cfg_get("GH_USER"), cfg_get("GH_REPO")
    if not gh_configured():
        raise RuntimeError("Atur dulu: /github <user> <repo> <token>")
    st, _ = _gh("GET", f"/repos/{user}/{repo}")
    if st == 404:
        st2, _ = _gh("POST", "/user/repos", {"name": repo, "private": False,
                                             "description": "Telegram AI bot"})
        if st2 >= 300:
            raise RuntimeError("Repo belum ada dan gagal dibuat (token fine-grained tidak bisa "
                               "membuat repo). Buat repo publik kosong di github.com/new, lalu ulangi.")
    elif st != 200:
        raise RuntimeError(f"Token atau nama repo salah (HTTP {st}).")
    with open(SELF_PATH, "rb") as f:
        src = f.read()
    files = {"script.py": src, "requirements.txt": REQUIREMENTS.encode(),
             ".github/workflows/standby.yml": WORKFLOW.encode()}
    out = []
    for path, content in files.items():
        st, cur = _gh("GET", f"/repos/{user}/{repo}/contents/{path}")
        sha = cur.get("sha") if st == 200 and isinstance(cur, dict) else None
        if sha and base64.b64decode((cur.get("content") or "").replace("\n", "")) == content:
            out.append(f"= {path} (sama)")
            continue
        body = {"message": f"Update {path}", "content": base64.b64encode(content).decode()}
        if sha:
            body["sha"] = sha
        st, _ = _gh("PUT", f"/repos/{user}/{repo}/contents/{path}", body)
        if st >= 300:
            need = "Workflows: write / scope 'workflow'" if path.startswith(".github") \
                else "Contents: write / scope 'repo'"
            raise RuntimeError(f"Gagal mengunggah {path} (HTTP {st}). Token perlu izin {need}.")
        out.append(f"✓ {path}")
    for path in OBSOLETE:                                   # buang file lama yang tak dipakai lagi
        st, cur = _gh("GET", f"/repos/{user}/{repo}/contents/{path}")
        if st == 200 and isinstance(cur, dict) and cur.get("sha"):
            st, _ = _gh("DELETE", f"/repos/{user}/{repo}/contents/{path}",
                        {"message": f"Hapus {path}", "sha": cur["sha"]})
            if st < 300:
                out.append(f"🗑 {path}")
    if cfg_get("HA_GIST_ID"):
        if set_repo_var("HA_GIST_ID", cfg_get("HA_GIST_ID")):
            out.append("✓ variabel HA_GIST_ID")
        elif not cfg_get("NOTE_VAR"):
            cfg_set("NOTE_VAR", "1")
            out.append("ℹ️ Variabel HA_GIST_ID tidak bisa diset otomatis (token tanpa izin Variables). "
                       "Tidak masalah bila secret HA_GIST_ID sudah kamu isi di GitHub. "
                       "(Catatan ini hanya muncul sekali.)")
    cfg_set("DEPLOYED_SHA", hashlib.sha1(src).hexdigest())
    return out, f"https://github.com/{user}/{repo}"

# ======================================================================
# BOT TELEGRAM
# ======================================================================
router = None   # dibuat di run_worker setelah konfigurasi dimuat
MAX_DOC_CHARS = 12000
MAX_FILE_BYTES = 10 * 1024 * 1024

HELP = (
    "🤖 *Bot AI Hybrid*\n\n"
    "Kirim pesan, foto (satu atau beberapa sekaligus), atau file (PDF/txt/csv/py/JPG/PNG).\n"
    "Balas jawaban gambar untuk bertanya lagi soal gambarnya.\n"
    "Minta pengingat dengan bahasa biasa, mis. _ingatkan aku 30 menit lagi minum obat_.\n\n"
    "/agent on|off – mode agent (tools) atau chat biasa\n"
    "/models – pilih provider & model AI (tombol)\n"
    "/model <provider> <id> – pilih model manual\n"
    "/use <provider|auto> – pilih provider saja\n"
    "/providers – status provider\n"
    "/scan [1d|4h] – pindai koin: sinyal + SL/TP + ukuran posisi\n"
    "/risk <modal USDT> <persen> – atur modal & risiko per trade\n"
    "/hasil – akurasi asli sinyal yang pernah dicatat\n"
    "/harian <JJ:MM|off> – laporan pindai otomatis tiap hari (WIB)\n"
    "/memory – lihat memori jangka panjang\n"
    "/forget <id|all> – hapus memori\n"
    "/reminders – lihat pengingat\n"
    "/reset – hapus riwayat percakapan\n"
    "/id – lihat Telegram ID kamu\n"
    "/setup – pengaturan (khusus pemilik)"
)


async def send_long(update: Update, text: str):
    sent = None
    for i in range(0, len(text) or 1, 4000):
        sent = await update.message.reply_text(text[i:i + 4000])
    return sent


async def typing(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await ctx.bot.send_chat_action(update.effective_chat.id, ChatAction.TYPING)


# ---------------- perintah ----------------
async def start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if allowed(update):
        await update.message.reply_text(HELP, parse_mode="Markdown")
    elif not owners():
        await update.message.reply_text(no_owner_hint())


async def id_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(f"ID kamu: {update.effective_user.id}")


async def reset(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if allowed(update):
        clear_history(update.effective_user.id)
        await update.message.reply_text("Riwayat percakapan dihapus ✅ (memori jangka panjang tetap ada)")


async def agent_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not allowed(update):
        return
    arg = (ctx.args[0].lower() if ctx.args else "")
    if arg not in ("on", "off"):
        return await update.message.reply_text("Pakai: /agent on atau /agent off")
    set_agent(update.effective_user.id, arg == "on")
    await update.message.reply_text(f"Mode agent: {arg.upper()}")


async def use_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not allowed(update):
        return
    arg = (ctx.args[0].lower() if ctx.args else "")
    uid = update.effective_user.id
    if arg == "auto":
        set_provider(uid, None)
        return await update.message.reply_text("Provider: auto (fallback otomatis)")
    if arg not in router.names():
        return await update.message.reply_text("Pilihan: auto, " + ", ".join(router.names()))
    set_provider(uid, arg)
    await update.message.reply_text(f"Provider diset ke {arg}")


async def providers_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not allowed(update):
        return
    lines = [f"{'🟢' if cd == 0 else '🟠'} {n} ({m})" + (f" – istirahat {cd}s" if cd else "")
             for n, m, cd in router.status()]
    await update.message.reply_text(
        f"Pilihanmu: {current_sel(update.effective_user.id)}\n\n" + "\n".join(lines))


async def memory_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not allowed(update):
        return
    rows = list_facts(update.effective_user.id)
    if not rows:
        return await update.message.reply_text(
            "Memori kosong. Coba bilang: \"ingat bahwa aku suka kopi tanpa gula\".")
    await send_long(update, "🧠 Memori:\n" + "\n".join(f"[{r['id']}] {r['fact']}" for r in rows))


async def forget_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not allowed(update):
        return
    uid = update.effective_user.id
    arg = (ctx.args[0].lower() if ctx.args else "")
    if arg == "all":
        clear_facts(uid)
        return await update.message.reply_text("Semua memori dihapus ✅")
    if arg.isdigit():
        ok = del_fact(uid, int(arg))
        return await update.message.reply_text("Terhapus ✅" if ok else "Id tidak ditemukan.")
    await update.message.reply_text("Pakai: /forget <id> atau /forget all (lihat id di /memory)")


async def reminders_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not allowed(update):
        return
    rows = list_reminders(update.effective_user.id)
    if not rows:
        return await update.message.reply_text("Tidak ada pengingat aktif.")
    await send_long(update, "⏰ Pengingat:\n" + "\n".join(
        f"#{r['id']} {fmt_ts(r['due'])}{' (' + r['repeat'] + ')' if r['repeat'] else ''}: {r['text']}"
        for r in rows) + "\n\nHapus: bilang \"hapus pengingat #id\"")


# ---------------- pilih model ----------------
PAGE = 8


def current_sel(uid) -> str:
    p = get_prefs(uid)
    if not p["provider"]:
        return "Auto (fallback otomatis)"
    return f"{p['provider']} / {p['model'] or 'model default'}"


def _provider_kb():
    rows = [[InlineKeyboardButton(n, callback_data=f"p:{n}")] for n in router.names()]
    rows.append([InlineKeyboardButton("🔄 Auto (fallback otomatis)", callback_data="a")])
    return InlineKeyboardMarkup(rows)


def _models_kb(name, ids, page):
    start = page * PAGE
    rows = [[InlineKeyboardButton(m[:60], callback_data=f"m:{name}:{start + i}")]
            for i, m in enumerate(ids[start:start + PAGE])]
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton("◀", callback_data=f"g:{name}:{page - 1}"))
    if start + PAGE < len(ids):
        nav.append(InlineKeyboardButton("▶", callback_data=f"g:{name}:{page + 1}"))
    if nav:
        rows.append(nav)
    rows.append([InlineKeyboardButton("⬅ Provider", callback_data="b")])
    return InlineKeyboardMarkup(rows)


async def models_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not allowed(update):
        return
    await update.message.reply_text(
        f"Pilihan sekarang: {current_sel(update.effective_user.id)}\nPilih provider:",
        reply_markup=_provider_kb())


async def model_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not allowed(update):
        return
    if len(ctx.args) < 2 or ctx.args[0].lower() not in router.names():
        return await update.message.reply_text(
            "Pakai: /model <provider> <id_model>\n"
            "Contoh: /model groq openai/gpt-oss-120b\n"
            "Provider: " + ", ".join(router.names()) + "\nAtau pakai tombol: /models")
    name, mid = ctx.args[0].lower(), ctx.args[1]
    set_provider(update.effective_user.id, name, mid)
    await update.message.reply_text(
        f"✅ Dipakai: {name} / {mid}\n(Kalau gagal, bot otomatis pindah ke provider lain.)")


async def on_choice(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    uid = q.from_user.id
    if not allowed_id(uid):
        return await q.answer("Tidak diizinkan", show_alert=True)
    await q.answer()
    parts = q.data.split(":")
    kind = parts[0]
    cache = ctx.bot_data.setdefault("models", {})
    if kind == "a":
        set_provider(uid, None)
        return await q.edit_message_text("✅ Provider & model: Auto (fallback otomatis)")
    if kind == "b":
        return await q.edit_message_text(
            f"Pilihan sekarang: {current_sel(uid)}\nPilih provider:",
            reply_markup=_provider_kb())
    name = parts[1]
    page = 0
    if kind == "p":
        await q.edit_message_text(f"Mengambil daftar model {name}...")
        try:
            cache[name] = await router.list_models(name)
        except Exception as e:
            return await q.edit_message_text(
                f"⚠️ Gagal mengambil daftar model {name}: {str(e)[:150]}\n"
                f"Coba manual: /model {name} <id_model>")
    elif kind == "g":
        page = int(parts[2])
    elif kind == "m":
        ids = cache.get(name) or []
        idx = int(parts[2])
        if idx >= len(ids):
            return await q.edit_message_text("Daftar kedaluwarsa, ulangi /models")
        set_provider(uid, name, ids[idx])
        return await q.edit_message_text(
            f"✅ Dipakai: {name} / {ids[idx]}\n"
            "(Kalau gagal, bot otomatis pindah ke provider lain.)")
    ids = cache.get(name) or []
    if not ids:
        return await q.edit_message_text(
            f"Tidak ada model untuk {name}, atau daftar kedaluwarsa. Ulangi /models "
            f"atau pakai /model {name} <id_model>")
    total = (len(ids) - 1) // PAGE + 1
    await q.edit_message_text(f"{name}: {len(ids)} model (hal {page + 1}/{total})\nPilih:",
                              reply_markup=_models_kb(name, ids, page))


# ---------------- pemindai koin ----------------
async def scan_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not allowed(update):
        return
    tf = (ctx.args[0].lower() if ctx.args else "1d")
    if tf not in ("1d", "4h"):
        return await update.message.reply_text("Pakai: /scan (harian) atau /scan 4h")
    msg = await update.message.reply_text("🔎 Memindai koin, tunggu ±20–40 detik...")
    try:
        data = await run_scan(tf)
    except Exception as e:
        logging.exception("scan gagal")
        return await msg.edit_text(f"⚠️ {e}")
    uid = update.effective_user.id
    p = get_prefs(uid)
    added = record(uid, data)
    try:
        await msg.delete()
    except Exception:
        pass
    text = format_scan(data, p["equity"], p["risk_pct"])
    if added:
        text += f"\n\n📝 {added} sinyal dicatat di /hasil untuk dilacak."
    await send_long(update, text)


async def hasil_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not allowed(update):
        return
    await typing(update, ctx)
    try:
        await update_open()
    except Exception as e:
        logging.warning("update_open: %s", e)
    await send_long(update, report(update.effective_user.id))


async def harian_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not allowed(update):
        return
    uid = update.effective_user.id
    arg = (ctx.args[0].lower() if ctx.args else "")
    if not arg:
        t = get_prefs(uid)["daily_time"]
        return await update.message.reply_text(
            f"Laporan harian: {t + ' WIB' if t else 'mati'}\n"
            "Atur: /harian 07:15 · Matikan: /harian off\n"
            "Candle harian tutup 07:00 WIB, jadi pilih ≥07:05.")
    if arg == "off":
        set_daily(uid, None, None)
        return await update.message.reply_text("Laporan harian dimatikan ✅")
    try:
        h, m = (int(x) for x in arg.split(":"))
        assert 0 <= h < 24 and 0 <= m < 60
    except Exception:
        return await update.message.reply_text("Format jam: JJ:MM, contoh /harian 07:15")
    hhmm = f"{h:02d}:{m:02d}"
    set_daily(uid, hhmm, update.effective_chat.id)
    warn = "\n⚠️ Sebelum 07:05 WIB candle harian belum tutup (data kemarin)." if hhmm < "07:05" else ""
    await update.message.reply_text(f"✅ Laporan pindai harian tiap {hhmm} WIB.{warn}")


async def risk_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not allowed(update):
        return
    uid = update.effective_user.id
    if not ctx.args:
        p = get_prefs(uid)
        if p["equity"] and p["risk_pct"]:
            return await update.message.reply_text(
                f"Modal: {p['equity']:g} USDT · risiko {p['risk_pct']:g}% per trade "
                f"(= {p['equity'] * p['risk_pct'] / 100:.2f} USDT)\nUbah: /risk 500 1")
        return await update.message.reply_text("Belum diatur. Contoh: /risk 500 1 (modal 500 USDT, risiko 1%)")
    try:
        equity, pct = float(ctx.args[0].replace(",", ".")), float(ctx.args[1].replace(",", "."))
    except (ValueError, IndexError):
        return await update.message.reply_text("Pakai: /risk <modal USDT> <persen>. Contoh: /risk 500 1")
    if equity <= 0 or not (0.1 <= pct <= 2):
        return await update.message.reply_text(
            "Modal harus > 0 dan risiko per trade dibatasi 0.1–2% demi keamanan.")
    set_risk(uid, equity, pct)
    await update.message.reply_text(
        f"✅ Modal {equity:g} USDT, risiko {pct:g}% per trade (= {equity * pct / 100:.2f} USDT)")


# ---------------- pesan teks (agent / chat) ----------------
async def on_message(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not allowed(update):
        return await update.message.reply_text(
            "⛔ Kamu tidak diizinkan." if owners() else no_owner_hint())
    uid = update.effective_user.id
    text = update.message.text
    refs, lost = followup_refs(update, text)
    if lost:
        return await update.message.reply_text(
            "Gambarnya sudah tidak tersimpan (bot sempat dimulai ulang). Kirim ulang fotonya.")
    if refs:
        return await answer_images(update, ctx, refs, text, label="[Bertanya soal gambar sebelumnya]")
    p = get_prefs(uid)
    hist = get_history(uid)
    await typing(update, ctx)
    try:
        if p["agent"]:
            answer, used, tools = await run_agent(
                router, hist, text,
                {"uid": uid, "chat_id": update.effective_chat.id}, p["provider"], p["model"])
        else:
            msgs = [{"role": "system", "content": basic_system(uid)}] + hist + [
                {"role": "user", "content": text}]
            answer, used = await router.chat(msgs, p["provider"], model=p["model"])
            tools = []
    except Exception as e:
        logging.exception("gagal")
        return await update.message.reply_text(f"⚠️ {e}")

    add_message(uid, "user", text)
    add_message(uid, "assistant", answer)
    footer = f"\n\n— {used}" + (f" · tools: {', '.join(tools)}" if tools else "")
    await send_long(update, answer + footer)


# ---------------- gambar: foto, file gambar, album, dan pertanyaan lanjutan ----------------
IMG_MIMES = ("image/jpeg", "image/png", "image/webp")
IMG_EXT_MIME = {".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".webp": "image/webp"}
MAX_ALBUM = 6                      # gambar yang dibaca per permintaan
MAX_IMG_BYTES = 4_000_000          # per gambar (foto Telegram jarang melebihi ini)
MAX_TOTAL_BYTES = 12_000_000       # total per permintaan
ALBUM_WAIT = 1.5                   # detik menunggu foto album lainnya
FOLLOWUP_WINDOW = 600              # detik: gambar terakhir masih "diingat" untuk teks yang merujuknya
FOLLOWUP_RE = re.compile(r"\b(gambar|foto|screenshot|tangkapan layar)\b|bagian (kiri|kanan|atas|bawah|tengah|pojok)"
                         r"|(teks|tulisan) (di|pada|dalam)", re.I)
DEFAULT_Q = "Jelaskan gambar ini dengan detail."
DEFAULT_ALBUM_Q = "Jelaskan gambar-gambar ini (berurutan) dan bandingkan bila relevan."
_img_by_msg = {}                   # (chat_id, id_pesan_bot) -> refs gambar; hilang bila bot dimulai ulang
_last_imgs = {}                    # uid -> (waktu, refs)


def _remember_images(chat_id, uid, sent, refs):
    _last_imgs[uid] = (time.time(), refs)
    if sent is not None:
        _img_by_msg[(chat_id, sent.message_id)] = refs
        while len(_img_by_msg) > 300:
            _img_by_msg.pop(next(iter(_img_by_msg)))


def _refs_in_message(m):
    """Gambar yang ada di sebuah pesan Telegram (foto, atau file gambar)."""
    if m is None:
        return []
    if getattr(m, "photo", None):
        return [{"file_id": m.photo[-1].file_id, "mime": "image/jpeg"}]
    d = getattr(m, "document", None)
    if d is not None and (d.mime_type or "").lower() in IMG_MIMES:
        return [{"file_id": d.file_id, "mime": d.mime_type.lower()}]
    return []


def followup_refs(update, text):
    """Return (refs, hilang). Gambar untuk pertanyaan lanjutan: dari pesan yang dibalas, atau
    gambar terakhir (10 menit) bila teksnya jelas merujuk gambar."""
    r = getattr(update.message, "reply_to_message", None)
    if r is not None:
        refs = _refs_in_message(r)
        if refs:
            return refs, False
        known = _img_by_msg.get((update.effective_chat.id, r.message_id))
        if known:
            return known, False
        if " (gambar" in (getattr(r, "text", None) or ""):
            return None, True                   # membalas jawaban gambar lama yang sudah terlupa
    last = _last_imgs.get(update.effective_user.id)
    if last and time.time() - last[0] <= FOLLOWUP_WINDOW and FOLLOWUP_RE.search(text or ""):
        return last[1], False
    return None, False


async def fetch_images(ctx, refs):
    parts, total = [], 0
    for ref in refs[:MAX_ALBUM]:
        tg_file = await ctx.bot.get_file(ref["file_id"])
        data = bytes(await tg_file.download_as_bytearray())
        if len(data) > MAX_IMG_BYTES:
            raise ValueError("Gambar terlalu besar (maks 4 MB per gambar). Kirim sebagai foto biasa "
                             "(dikompres Telegram) atau perkecil dulu.")
        total += len(data)
        if total > MAX_TOTAL_BYTES:
            raise ValueError("Total ukuran gambar terlalu besar (maks 12 MB). Kirim lebih sedikit gambar.")
        parts.append({"type": "image_url", "image_url": {
            "url": f"data:{ref['mime']};base64,{base64.b64encode(data).decode()}"}})
    return parts


async def answer_images(update, ctx, refs, question, label=None):
    uid = update.effective_user.id
    p = get_prefs(uid)
    await typing(update, ctx)
    n = min(len(refs), MAX_ALBUM)
    ask = question + (f" (Terlampir {n} gambar berurutan.)" if n > 1 and question != DEFAULT_ALBUM_Q else "")
    try:
        parts = await fetch_images(ctx, refs)
        content = [{"type": "text", "text": ask}] + parts
        msgs = [{"role": "system", "content": basic_system(uid)}] + get_history(uid) + [
            {"role": "user", "content": content}]
        answer, used = await router.chat(msgs, p["provider"], vision=True)
    except ValueError as e:                       # gambar terlalu besar: pesan jelas, tanpa memanggil AI
        return await update.message.reply_text(f"⚠️ {e}")
    except Exception as e:
        logging.exception("gambar gagal")
        return await update.message.reply_text(f"⚠️ {e}")
    add_message(uid, "user", f"{label or f'[Mengirim {n} gambar]'} {question}")
    add_message(uid, "assistant", answer)
    foot = f"\n\n— {used} (gambar{' ×' + str(n) if n > 1 else ''})"
    if len(refs) > MAX_ALBUM:
        foot += f"\n(Hanya {MAX_ALBUM} gambar pertama yang dibaca.)"
    foot += "\n↩️ Balas pesan ini untuk bertanya lagi soal gambarnya."
    sent = await send_long(update, answer + foot)
    _remember_images(update.effective_chat.id, uid, sent, refs[:MAX_ALBUM])


async def flush_album(ctx, gid):
    await asyncio.sleep(ALBUM_WAIT)
    a = ctx.application.bot_data.get("albums", {}).pop(gid, None)
    if not a:
        return
    try:
        await answer_images(a["update"], ctx, a["refs"], a["caption"] or DEFAULT_ALBUM_Q)
    except Exception:
        logging.exception("album gagal")


async def collect_media(update, ctx, ref):
    """Satu gambar langsung diproses; gambar dalam satu album dikumpulkan lalu dibaca bersamaan."""
    msg = update.message
    gid = msg.media_group_id
    if not gid:
        return await answer_images(update, ctx, [ref], msg.caption or DEFAULT_Q)
    albums = ctx.application.bot_data.setdefault("albums", {})
    a = albums.get(gid)
    if a is None:
        a = albums[gid] = {"refs": [], "caption": "", "update": update}
        a["task"] = asyncio.create_task(flush_album(ctx, gid))   # simpan rujukan agar tidak dibuang GC
    a["refs"].append(ref)
    if msg.caption and not a["caption"]:
        a["caption"] = msg.caption


async def on_photo(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not allowed(update):
        return
    await collect_media(update, ctx, {"file_id": update.message.photo[-1].file_id, "mime": "image/jpeg"})


# ---------------- dokumen ----------------
def extract_pdf(data: bytes) -> str:
    from pypdf import PdfReader
    reader = PdfReader(io.BytesIO(data))
    return "\n".join((pg.extract_text() or "") for pg in reader.pages[:40])


async def on_document(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not allowed(update):
        return
    uid = update.effective_user.id
    doc = update.message.document
    name = (doc.file_name or "").lower()
    mime = doc.mime_type or ""
    if mime.lower() in IMG_MIMES or name.endswith(tuple(IMG_EXT_MIME)):        # gambar yang dikirim sebagai file
        if doc.file_size and doc.file_size > MAX_IMG_BYTES:
            return await update.message.reply_text(
                "Gambar terlalu besar (maks 4 MB). Kirim sebagai foto biasa (dikompres Telegram) atau perkecil dulu.")
        m_ = mime.lower() if mime.lower() in IMG_MIMES else IMG_EXT_MIME[os.path.splitext(name)[1]]
        return await collect_media(update, ctx, {"file_id": doc.file_id, "mime": m_})
    if mime.startswith("image/") or name.endswith((".heic", ".heif", ".gif", ".bmp", ".tif", ".tiff")):
        return await update.message.reply_text(
            "Format gambar ini belum didukung. Kirim sebagai foto biasa, atau simpan sebagai JPG, PNG, atau WebP.")
    if doc.file_size and doc.file_size > MAX_FILE_BYTES:
        return await update.message.reply_text("File terlalu besar (maks 10 MB).")
    is_pdf = name.endswith(".pdf") or mime == "application/pdf"
    is_text = name.endswith((".txt", ".md", ".csv", ".py", ".json", ".log", ".html")) \
        or mime.startswith("text/")
    if not (is_pdf or is_text):
        return await update.message.reply_text("Format belum didukung. Kirim PDF, txt, md, csv, py, atau json.")
    p = get_prefs(uid)
    await typing(update, ctx)
    try:
        tg_file = await doc.get_file()
        data = bytes(await tg_file.download_as_bytearray())
        text = extract_pdf(data) if is_pdf else data.decode("utf-8", errors="replace")
        text = text.strip()
        if not text:
            return await update.message.reply_text(
                "Tidak ada teks yang bisa dibaca (mungkin PDF hasil scan/gambar). "
                "Coba kirim sebagai foto.")
        note = ""
        if len(text) > MAX_DOC_CHARS:
            text = text[:MAX_DOC_CHARS]
            note = f"\n(Catatan: hanya {MAX_DOC_CHARS} karakter pertama yang dibaca.)"
        question = update.message.caption or "Ringkas dokumen ini."
        prompt = (f"Isi dokumen '{doc.file_name}':\n\"\"\"\n{text}\n\"\"\"\n\n"
                  f"Permintaan pengguna: {question}")
        msgs = [{"role": "system", "content": basic_system(uid)}] + get_history(uid) + [
            {"role": "user", "content": prompt}]
        answer, used = await router.chat(msgs, p["provider"], model=p["model"])
    except Exception as e:
        logging.exception("dokumen gagal")
        return await update.message.reply_text(f"⚠️ {e}")
    add_message(uid, "user", f"[Mengirim dokumen {doc.file_name}] {question}")
    add_message(uid, "assistant", answer)
    await send_long(update, answer + f"\n\n— {used} (dokumen){note}")


# ---------------- pengingat terjadwal ----------------
async def reminder_loop(app):
    while True:
        try:
            now = time.time()
            for r in due_reminders(now):
                try:
                    await app.bot.send_message(r["chat_id"], f"⏰ Pengingat: {r['text']}")
                except Exception:
                    logging.exception("gagal kirim pengingat #%s", r["id"])
                advance_or_delete(r, now)
        except Exception:
            logging.exception("reminder_loop")
        await asyncio.sleep(15)


# ---------------- pemilik & pengaturan (semuanya lewat Telegram) ----------------
KEYMAP = {"groq": "GROQ_API_KEY", "gemini": "GEMINI_API_KEY", "cerebras": "CEREBRAS_API_KEY",
          "openrouter": "OPENROUTER_API_KEY", "mistral": "MISTRAL_API_KEY",
          "github": "GITHUB_TOKEN", "nvidia": "NVIDIA_API_KEY", "gist": "GIST_TOKEN"}
KEY_LINKS = {"groq": "console.groq.com/keys", "gemini": "aistudio.google.com/apikey",
             "cerebras": "cloud.cerebras.ai", "openrouter": "openrouter.ai/keys",
             "mistral": "console.mistral.ai/api-keys", "nvidia": "build.nvidia.com",
             "github": "token GitHub Models (izin Models: Read)",
             "gist": "token KLASIK dengan scope gist saja"}
_claim_fail = 0


def owners():
    return cfg_ids("OWNER_IDS")


def allowed_id(uid):
    return uid in owners() or uid in cfg_ids("USER_IDS")


def allowed(update) -> bool:
    return allowed_id(update.effective_user.id)


def owner(update) -> bool:
    return update.effective_user.id in owners()


def mask(s):
    return (s[:4] + "…" + s[-3:]) if len(s) > 10 else "***"


async def scrub(update):
    """Hapus pesan pengguna yang berisi kunci rahasia."""
    try:
        await update.message.delete()
    except Exception:
        pass


def delayed_exit(code, seconds=1.5):
    asyncio.get_running_loop().call_later(seconds, os._exit, code)


async def claim_cmd(update, ctx):
    global _claim_fail
    uid = update.effective_user.id
    if owners():
        return await update.message.reply_text("Bot ini sudah punya pemilik.")
    code = _cfg.get("CLAIM_CODE")
    if _claim_fail >= 5:
        return await update.message.reply_text("Terlalu banyak percobaan. Mulai ulang bot untuk mencoba lagi.")
    if not ctx.args or not code or not hmac.compare_digest(ctx.args[0], code):
        _claim_fail += 1
        return await update.message.reply_text("Kode salah.")
    cfg_set("OWNER_IDS", [uid])
    cfg_set("CLAIM_CODE", None)
    await scrub(update)
    await ctx.bot.send_message(update.effective_chat.id,
                               "✅ Kamu sekarang pemilik bot. Ketik /setup untuk mulai.")


async def setup_cmd(update, ctx):
    if not owner(update):
        return
    ai = router.names()
    miss = [n for n in KEYMAP if n != "gist" and not cfg_get(KEYMAP[n])]
    lines = ["⚙️ Status", f"Node: {'GitHub (cadangan)' if NODE_ROLE == 'github' else 'HP'}",
             f"AI aktif: {', '.join(ai) if ai else 'belum ada'}"]
    if miss:
        lines.append("Belum diisi: " + ", ".join(miss))
    if not ai:
        lines.append("\nMulai: /setkey groq <kunci>  (gratis di console.groq.com/keys)")
    lines.append(f"\nGitHub: {cfg_get('GH_USER') + '/' + cfg_get('GH_REPO') if gh_configured() else 'belum diatur'}"
                 f" · autodeploy {'on' if cfg_get('AUTODEPLOY') == '1' else 'off'}")
    lines.append(f"Failover: {'aktif' if ha_enabled() else 'mati'}")
    lines.append(f"Pengguna tambahan: {len(cfg_ids('USER_IDS'))}")
    lines.append("\nPerintah pemilik:\n/setkey /delkey /keys\n/github /deploy /autodeploy\n"
                 "/failover on|off|status\n/izin <id> /cabut <id>\n/watchdog /restart /stop")
    await update.message.reply_text("\n".join(lines))


async def setkey_cmd(update, ctx):
    if not owner(update):
        return
    if len(ctx.args) < 2 or ctx.args[0].lower() not in KEYMAP:
        rows = "\n".join(f"• {n}: {KEY_LINKS[n]}" for n in KEYMAP)
        return await update.message.reply_text(
            "Pakai: /setkey <nama> <kunci>\nPesanmu otomatis dihapus setelah disimpan.\n\n" + rows)
    name, key = ctx.args[0].lower(), ctx.args[1].strip()
    cfg_set(KEYMAP[name], key)
    await scrub(update)
    if name != "gist":
        router.reload()
    await sync_config()
    await ctx.bot.send_message(update.effective_chat.id,
                               f"✅ Kunci {name} tersimpan dan langsung aktif. Pesanmu sudah dihapus.")


async def delkey_cmd(update, ctx):
    if not owner(update):
        return
    name = ctx.args[0].lower() if ctx.args else ""
    if name not in KEYMAP:
        return await update.message.reply_text("Pakai: /delkey <nama>  (" + ", ".join(KEYMAP) + ")")
    cfg_set(KEYMAP[name], None)
    router.reload()
    await sync_config()
    await update.message.reply_text(f"🗑 Kunci {name} dihapus.")


async def keys_cmd(update, ctx):
    if not owner(update):
        return
    lines = [f"{'🟢' if cfg_get(KEYMAP[n]) else '⚪'} {n}: "
             f"{mask(cfg_get(KEYMAP[n])) if cfg_get(KEYMAP[n]) else 'kosong'}" for n in KEYMAP]
    await update.message.reply_text("🔑 Kunci\n" + "\n".join(lines))


async def github_cmd(update, ctx):
    if not owner(update):
        return
    if len(ctx.args) < 3:
        cur = (f"{cfg_get('GH_USER')}/{cfg_get('GH_REPO')}" if cfg_get("GH_USER") else "belum diatur")
        return await update.message.reply_text(
            f"Repo: {cur} · token: {'ada' if cfg_get('GH_PUSH_TOKEN') else 'belum'}\n"
            "Atur: /github <user> <repo> <token>\n"
            "Token fine-grained: Contents, Workflows, Variables = Read & write (hanya repo itu).\n"
            "Atau token klasik: scope public_repo + workflow.")
    user, repo, tok = ctx.args[:3]
    cfg_set("GH_USER", user, save=False)
    cfg_set("GH_REPO", repo, save=False)
    cfg_set("GH_PUSH_TOKEN", tok)
    await scrub(update)
    st, _ = await asyncio.to_thread(_gh, "GET", f"/repos/{user}/{repo}")
    note = {200: "✅ Repo ditemukan dan token valid.",
            404: "Repo belum ada. /deploy akan mencoba membuatnya (butuh token klasik), "
                 "atau buat repo publik kosong di github.com/new.",
            401: "⚠️ Token ditolak.", 403: "⚠️ Token tidak punya izin."}.get(st, f"⚠️ HTTP {st}")
    await ctx.bot.send_message(update.effective_chat.id,
                               f"Tersimpan: {user}/{repo} (pesanmu dihapus).\n{note}\nLanjut: /deploy")


async def deploy_cmd(update, ctx):
    if not owner(update):
        return
    msg = await update.message.reply_text("📤 Mengunggah ke GitHub...")
    try:
        out, url = await asyncio.to_thread(github_deploy)
    except Exception as e:
        return await msg.edit_text(f"⚠️ {e}")
    text = "✅ Selesai\n" + "\n".join(out) + f"\n{url}"
    if ha_enabled() and not cfg_get("NOTE_SECRETS"):
        cfg_set("NOTE_SECRETS", "1")
        text += ("\n\nFailover aktif. Pastikan di GitHub (Settings → Secrets and variables → Actions) "
                 "sudah ada secret GIST_TOKEN dan HA_GIST_ID. (Catatan ini hanya muncul sekali; "
                 "lihat lagi lewat /failover.)")
    await msg.edit_text(text)


async def autodeploy_cmd(update, ctx):
    if not owner(update):
        return
    arg = ctx.args[0].lower() if ctx.args else ""
    if arg not in ("on", "off"):
        return await update.message.reply_text(
            f"Autodeploy: {'on' if cfg_get('AUTODEPLOY') == '1' else 'off'}\nPakai: /autodeploy on|off")
    cfg_set("AUTODEPLOY", "1" if arg == "on" else None)
    await update.message.reply_text(
        "✅ Autodeploy " + arg + (": tiap bot dimulai dengan script.py baru, kode otomatis diunggah."
                                 if arg == "on" else "."))


async def failover_cmd(update, ctx):
    if not owner(update):
        return
    arg = ctx.args[0].lower() if ctx.args else "status"
    if arg == "on":
        if not cfg_get("GIST_TOKEN"):
            return await update.message.reply_text(
                "Perlu token Gist dulu. Buat token KLASIK (scope gist saja) di "
                "github.com/settings/tokens, lalu kirim /setkey gist <token>")
        wf = None
        try:
            if not cfg_get("HA_GIST_ID"):
                cfg_set("HA_GIST_ID", await asyncio.to_thread(ha_create))
            cfg_set("FAILOVER", "1")
            await asyncio.to_thread(ha_write, None, export_state(), "phone", config_blob())
            if gh_configured():
                await asyncio.to_thread(set_repo_var, "HA_GIST_ID", cfg_get("HA_GIST_ID"))
                wf = await asyncio.to_thread(gh_workflow, True)
        except Exception as e:
            return await update.message.reply_text(f"⚠️ {e}")
        warn = ("\n⚠️ Workflow GitHub tidak bisa diaktifkan otomatis (token tanpa izin Actions). "
                "Cek: Actions → standby-bot → Enable workflow.\n") if wf is False else ""
        await update.message.reply_text(
            "✅ Failover aktif. Bot restart sebentar.\n" + warn + "\nChecklist:\n"
            "1. /github <user> <repo> <token> (jika belum)\n2. /deploy\n"
            "3. Di GitHub: Settings → Secrets and variables → Actions → secret GIST_TOKEN "
            "(isi = token gist)\nSetelah itu HP mati → GitHub mengambil alih otomatis.")
        return delayed_exit(3)
    if arg == "off":
        cfg_set("FAILOVER", None)
        try:
            await asyncio.to_thread(ha_write, "none")
        except Exception:
            pass
        wf = await asyncio.to_thread(gh_workflow, False) if gh_configured() else None
        await update.message.reply_text(
            "Failover dimatikan di HP. Restart sebentar." + (
                "\nCadangan GitHub dinonaktifkan." if wf else
                "\n⚠️ Workflow GitHub belum bisa dinonaktifkan otomatis (token tanpa izin Actions). "
                "Matikan manual: Actions → standby-bot → ⋯ → Disable workflow."))
        return delayed_exit(3)
    info = ["Failover: " + ("aktif" if ha_enabled() else "mati")]
    if ha_enabled():
        info.append(f"Gist ID: {cfg_get('HA_GIST_ID')}")
        try:
            lease = (await asyncio.to_thread(ha_read_all))["lease"]
            age = int(time.time() - lease.get("ts", 0)) if lease.get("ts") else None
            info.append(f"Pemegang: {lease.get('holder', '-')}" + (f" ({age} dtk lalu)" if age is not None else ""))
        except Exception as e:
            info.append(f"Gist tidak terjangkau: {e}")
    info.append("Secret GitHub yang dibutuhkan: GIST_TOKEN dan HA_GIST_ID (secret atau variabel).")
    await update.message.reply_text("\n".join(info) + "\nPakai: /failover on|off")


async def watchdog_cmd(update, ctx):
    """/watchdog on|off|status : penjaga yang menghidupkan bot lagi bila mati (butuh Termux:API)."""
    if not owner(update):
        return
    if NODE_ROLE == "github":
        return await update.message.reply_text("Penjaga hanya untuk bot di HP.")
    arg = ctx.args[0].lower() if ctx.args else "status"
    if arg == "on":
        msg = (await asyncio.to_thread(wd_install))[1]
    elif arg == "off":
        msg = await asyncio.to_thread(wd_remove)
    else:
        msg = await asyncio.to_thread(wd_status) + "\nPakai: /watchdog on|off"
    await update.message.reply_text(msg)


async def stop_cmd(update, ctx):
    if not owner(update):
        return
    if NODE_ROLE == "github":
        return await update.message.reply_text(
            "Ini node cadangan GitHub. Untuk menonaktifkannya pakai /failover off.")
    await update.message.reply_text(
        "⏹ Menghentikan bot. Nyalakan lagi dengan: python bot.py"
        + (" Sementara itu cadangan GitHub akan mengambil alih." if ha_enabled() else ""))
    _set_stop_flag("/stop (Telegram)")
    # SIGTERM ke diri sendiri = shutdown rapi (lease dilepas, state disimpan)
    asyncio.get_running_loop().call_later(1.5, os.kill, os.getpid(), signal.SIGTERM)


async def restart_cmd(update, ctx):
    if not owner(update):
        return
    await update.message.reply_text("🔄 Memulai ulang...")
    delayed_exit(3)


def _parse_id(ctx):
    return int(ctx.args[0]) if ctx.args and ctx.args[0].isdigit() else None


async def izin_cmd(update, ctx):
    if not owner(update):
        return
    uid = _parse_id(ctx)
    if uid is None:
        return await update.message.reply_text("Pakai: /izin <id telegram>. Orangnya bisa kirim /id ke bot untuk melihat ID-nya.")
    cfg_set("USER_IDS", sorted(set(cfg_ids("USER_IDS")) | {uid}))
    await sync_config()
    await update.message.reply_text(f"✅ {uid} boleh memakai bot (bukan pengaturan).")


async def cabut_cmd(update, ctx):
    if not owner(update):
        return
    uid = _parse_id(ctx)
    if uid is None:
        return await update.message.reply_text("Pakai: /cabut <id telegram>")
    cfg_set("USER_IDS", sorted(set(cfg_ids("USER_IDS")) - {uid}))
    await sync_config()
    await update.message.reply_text(f"🗑 Izin {uid} dicabut.")


def no_owner_hint():
    return "Bot belum diklaim. Kirim /claim <kode> (kode tampil di terminal saat pertama kali jalan)."


async def on_error(update, ctx: ContextTypes.DEFAULT_TYPE):
    if isinstance(ctx.error, Conflict):
        logging.warning("Conflict: ada instance lain yang polling (menunggu serah-terima)")
        return
    logging.error("Error: %s", ctx.error)


async def daily_loop(app):
    last_try = {}
    while True:
        try:
            now = datetime.now(WIB)
            today = now.strftime("%Y-%m-%d")
            for u in daily_users():
                uid = u["uid"]
                if not is_due(u["daily_time"], now, u["last_daily"]):
                    continue
                if time.time() - last_try.get(uid, 0) < 900:   # gagal? coba lagi tiap 15 menit
                    continue
                last_try[uid] = time.time()
                try:
                    await update_open()
                    data = await run_scan("1d")
                    record(uid, data)
                    p = get_prefs(uid)
                    text = ("🌅 Laporan harian\n\n"
                            + format_scan(data, p["equity"], p["risk_pct"])
                            + "\n\n" + summary(uid))
                    for i in range(0, len(text), 4000):
                        await app.bot.send_message(u["daily_chat"], text[i:i + 4000])
                    mark_daily(uid, today)
                except Exception:
                    logging.exception("laporan harian gagal (uid %s)", uid)
        except Exception:
            logging.exception("daily_loop")
        await asyncio.sleep(60)


# ======================================================================
# MENJALANKAN: worker, supervisor, mode --check
# ======================================================================
async def post_shutdown(app):
    for k in ("reminder_task", "ha_task", "daily_task"):
        t = app.bot_data.get(k)
        if t:
            t.cancel()


async def autodeploy_check(app):
    if NODE_ROLE != "phone" or cfg_get("AUTODEPLOY") != "1" or not gh_configured():
        return
    with open(SELF_PATH, "rb") as f:
        sha = hashlib.sha1(f.read()).hexdigest()
    if sha == cfg_get("DEPLOYED_SHA"):
        return
    try:
        await asyncio.to_thread(github_deploy)
        await notify_owners(app, "📤 Kode terbaru otomatis diunggah ke GitHub.")
    except Exception as e:
        await notify_owners(app, f"⚠️ Autodeploy gagal: {e}")


async def post_init(app):
    app.bot_data["reminder_task"] = asyncio.create_task(reminder_loop(app))
    app.bot_data["daily_task"] = asyncio.create_task(daily_loop(app))
    if ha_enabled():
        app.bot_data["ha_task"] = asyncio.create_task(ha_loop(app))
    print("✅ Bot berjalan. Kelola semuanya lewat Telegram (/setup). CTRL+C untuk berhenti.", flush=True)
    if NODE_ROLE == "github":
        asyncio.create_task(notify_owners(
            app, "🛰 Cadangan GitHub aktif karena HP tidak terdeteksi. Otomatis kembali saat HP menyala."))
    elif os.environ.get("TGBOT_FIRST") == "1":
        asyncio.create_task(notify_owners(
            app, "🔁 Bot dihidupkan lagi oleh penjaga setelah sempat mati."
            if os.environ.get("TGBOT_REVIVED") == "1" else "✅ Bot aktif di HP."))
    app.bot_data["autodeploy_task"] = asyncio.create_task(autodeploy_check(app))


def run_worker(role):
    global NODE_ROLE, router
    NODE_ROLE = role
    logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)   # jangan tampilkan URL berisi token
    cfg_load()
    if not ha_startup():
        sys.exit(11)
    token = cfg_get("TELEGRAM_BOT_TOKEN")
    if not token:
        print("Token bot belum ada. Jalankan: python script.py --token", flush=True)
        sys.exit(2)
    router = Router()
    app = (ApplicationBuilder().token(token).post_init(post_init)
           .post_shutdown(post_shutdown).build())
    app.add_error_handler(on_error)
    for name, fn in [("start", start), ("help", start), ("id", id_cmd), ("reset", reset),
                     ("agent", agent_cmd), ("use", use_cmd), ("providers", providers_cmd),
                     ("memory", memory_cmd), ("forget", forget_cmd), ("reminders", reminders_cmd),
                     ("models", models_cmd), ("model", model_cmd), ("scan", scan_cmd),
                     ("risk", risk_cmd), ("hasil", hasil_cmd), ("harian", harian_cmd),
                     ("claim", claim_cmd), ("setup", setup_cmd), ("setkey", setkey_cmd),
                     ("delkey", delkey_cmd), ("keys", keys_cmd), ("github", github_cmd),
                     ("deploy", deploy_cmd), ("autodeploy", autodeploy_cmd),
                     ("failover", failover_cmd), ("restart", restart_cmd), ("stop", stop_cmd), ("watchdog", watchdog_cmd),
                     ("izin", izin_cmd), ("cabut", cabut_cmd)]:
        app.add_handler(CommandHandler(name, fn))
    app.add_handler(CallbackQueryHandler(on_choice))
    app.add_handler(MessageHandler(filters.PHOTO, on_photo))
    app.add_handler(MessageHandler(filters.Document.ALL, on_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_message))
    try:
        app.run_polling()
    except InvalidToken:
        print("Token bot ditolak Telegram. Jalankan: python script.py --token", flush=True)
        sys.exit(2)
    finally:
        if NODE_ROLE == "phone" and ha_enabled():   # berhenti baik-baik: lepas lease supaya GitHub cepat ambil alih
            try:
                snap, _ = _snapshot()
                ha_write("none", snap, "phone")
            except Exception:
                pass


def check_mode():
    """Dipakai workflow GitHub: perlukah GitHub mengambil alih? (hanya stdlib)"""
    global NODE_ROLE
    NODE_ROLE = "github"

    def out(v):
        p = os.environ.get("GITHUB_OUTPUT")
        if p:
            with open(p, "a") as f:
                f.write(f"standby={v}\n")
    try:
        lease = ha_read_all()["lease"]
    except Exception as e:
        print("Gagal membaca gist:", e)
        return out("false") or 0
    if ha_lease_fresh(lease, "phone"):
        print("HP aktif -> GitHub tidak perlu jalan")
        out("false")
    elif ha_lease_fresh(lease, "github"):
        print("Instance GitHub lain sedang jalan")
        out("false")
    else:
        print("HP tidak aktif -> GitHub mengambil alih")
        out("true")
    return 0


def ensure_deps():
    need = []
    for mod, pkg in (("telegram", "python-telegram-bot>=21.0"), ("httpx", "httpx>=0.27")):
        try:
            __import__(mod)
        except ImportError:
            need.append(pkg)
    if need:
        print("Memasang komponen (hanya sekali)...", flush=True)
        if subprocess.call([sys.executable, "-m", "pip", "install", "-q", *need]):
            print("Gagal memasang: " + " ".join(need), flush=True)
            sys.exit(1)
    try:
        __import__("pypdf")
    except ImportError:   # opsional (baca PDF)
        subprocess.call([sys.executable, "-m", "pip", "install", "-q", "pypdf>=4.0"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def first_run_setup():
    if not _cfg.get("ENV_IMPORTED"):
        import_dotenv()
        cfg_set("ENV_IMPORTED", "1")
    while not re.fullmatch(r"\d+:[\w-]{30,}", cfg_get("TELEGRAM_BOT_TOKEN") or ""):
        if cfg_get("TELEGRAM_BOT_TOKEN"):
            print("Format token salah.")
        else:
            print("Pertama kali jalan. Buat bot di @BotFather, lalu tempel tokennya.")
        cfg_set("TELEGRAM_BOT_TOKEN", input("Token bot: ").strip())
    if not cfg_ids("OWNER_IDS"):
        code = _cfg.get("CLAIM_CODE") or secrets.token_urlsafe(6)
        cfg_set("CLAIM_CODE", code)
        print(f"Kirim ke bot di Telegram:  /claim {code}", flush=True)


# ----------------------------------------------------------------------
# PROSES LATAR BELAKANG: peluncur (python bot.py) -> pendengar (--listen) -> pekerja (--worker)
# ----------------------------------------------------------------------
LOCK_PATH = os.path.join(APP_DIR, "bot.lock")
PID_PATH = os.path.join(APP_DIR, "bot.pid")
LOG_PATH = os.path.join(APP_DIR, "bot.log")
STOP_FLAG = os.path.join(APP_DIR, "stopped")          # ada = dihentikan SENGAJA, penjaga tidak menghidupkan lagi
WD_SCRIPT = os.path.join(APP_DIR, "watchdog.sh")
WD_LAST = os.path.join(APP_DIR, "watchdog.last")
WD_INSTALLED = os.path.join(APP_DIR, "watchdog.installed")
WD_LOG = os.path.join(APP_DIR, "watchdog.log")
WD_JOB_ID = "77"
WD_PERIOD_MS = "900000"                               # 15 menit = batas minimum Android
_LOCK_FD = None
_child = None
_stopping = False


def _set_stop_flag(reason):
    try:
        with open(STOP_FLAG, "w") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {reason}\n")
    except OSError:
        pass


def _clear_stop_flag():
    try:
        os.remove(STOP_FLAG)
    except OSError:
        pass


def _try_lock(path):
    """Kunci eksklusif. Return fd bila berhasil (tidak ada instance lain), None bila sudah dikunci.
    Kunci otomatis lepas bila prosesnya mati, jadi tidak ada file PID basi yang menipu."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except ImportError:                      # Windows
            import msvcrt
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    except OSError:
        os.close(fd)
        return None
    return fd


def _is_running():
    fd = _try_lock(LOCK_PATH)
    if fd is None:
        return True
    os.close(fd)
    return False


def _read_pid():
    try:
        with open(PID_PATH) as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def _is_listener(pid):
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return b"--listen" in f.read()
    except OSError:
        return True                              # tidak bisa memeriksa: anggap benar


def _tail(path, n=30):
    try:
        with open(path, "rb") as f:
            lines = f.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return "(belum ada log)"
    return "\n".join(lines[-n:]) or "(log kosong)"


def show_log(args):
    n = next((int(x) for x in args if x.isdigit()), 30)
    print(_tail(LOG_PATH, n))
    return 0


def status_bot():
    if not _is_running():
        print("Bot tidak berjalan." + (" (Dihentikan sengaja, penjaga tidak akan menghidupkannya. "
                                      "Jalankan: python bot.py)" if os.path.exists(STOP_FLAG) else ""))
        return 1
    pid = _read_pid()
    since = ""
    try:
        since = ", sejak " + datetime.fromtimestamp(os.path.getmtime(PID_PATH)).strftime("%d-%m %H:%M")
    except OSError:
        pass
    print(f"Bot berjalan di latar belakang (PID {pid}{since}).")
    return 0


def stop_bot():
    _set_stop_flag("python bot.py --stop")
    if not _is_running():
        print("Bot tidak sedang berjalan.")
        return 0
    pid = _read_pid()
    if not pid or not _is_listener(pid):
        print("PID bot tidak ditemukan. Hentikan manual atau matikan Termux.")
        return 1
    try:                                         # seluruh grup proses: pendengar + pekerja
        os.killpg(os.getpgid(pid), signal.SIGTERM)
    except (AttributeError, OSError):
        os.kill(pid, signal.SIGTERM)
    for _ in range(40):                          # tunggu shutdown rapi (maks 20 dtk)
        time.sleep(0.5)
        if not _is_running():
            print("Bot dihentikan.")
            return 0
    try:
        os.killpg(os.getpgid(pid), signal.SIGKILL)
    except (AttributeError, OSError):
        os.kill(pid, signal.SIGKILL)
    print("Bot dihentikan paksa.")
    return 0


def _on_term(sig, frame):
    global _stopping
    _stopping = True
    if _child is not None and _child.poll() is None:
        try:
            _child.send_signal(signal.SIGTERM)
        except Exception:
            pass


def _log(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), msg, flush=True)


def listen():
    """Proses sebenarnya (terlepas dari shell). Menjaga bot tetap hidup: restart bila crash."""
    global _LOCK_FD, _child, _stopping
    _LOCK_FD = _try_lock(LOCK_PATH)
    if _LOCK_FD is None:
        print("Bot sudah berjalan.", flush=True)
        return
    with open(PID_PATH, "w") as f:
        f.write(str(os.getpid()))
    cfg_load()
    signal.signal(signal.SIGTERM, _on_term)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, signal.SIG_IGN)          # terminal ditutup: abaikan
    first = "1"
    _log("pendengar mulai")
    while not _stopping:
        env = {**os.environ, "TGBOT_FIRST": first, "PYTHONUNBUFFERED": "1"}
        _child = subprocess.Popen([sys.executable, SELF_PATH, "--worker"], env=env)
        try:
            rc = _child.wait()
        except KeyboardInterrupt:                 # --listen dijalankan di terminal lalu CTRL+C
            _stopping = True
            _set_stop_flag("CTRL+C")
            try:
                _child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                _child.kill()
            break
        first = "0"
        if rc == 2:
            _set_stop_flag("konfigurasi fatal (kode 2)")
        if _stopping or rc in (0, 2, 130, -2, -15):  # berhenti normal / konfigurasi fatal / dihentikan
            _log(f"bot berhenti (kode {rc}), pendengar selesai")
            break
        if rc == 3:                               # /restart
            continue
        _log(f"bot berhenti (kode {rc}), mulai ulang 10 detik lagi")
        for _ in range(20):
            if _stopping:
                break
            time.sleep(0.5)
    try:
        os.remove(PID_PATH)
    except OSError:
        pass


def _spawn_listener(revived=False):
    """Luncurkan pendengar terpisah (terlepas dari sesi). Dipakai peluncur dan penjaga."""
    try:
        subprocess.run(["termux-wake-lock"], capture_output=True)   # Termux: cegah HP tidur
    except Exception:
        pass
    try:                                           # putar log bila sudah besar
        if os.path.getsize(LOG_PATH) > 1_000_000:
            os.replace(LOG_PATH, LOG_PATH + ".1")
    except OSError:
        pass
    env = {**os.environ, "PYTHONUNBUFFERED": "1"}
    if revived:
        env["TGBOT_REVIVED"] = "1"
    kw = {"creationflags": 0x00000008 | 0x00000200} if os.name == "nt" else {"start_new_session": True}
    with open(LOG_PATH, "ab") as log:
        return subprocess.Popen([sys.executable, SELF_PATH, "--listen"],
                                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                close_fds=True, cwd=os.path.dirname(SELF_PATH) or None, env=env, **kw)


# ---------------- penjaga (watchdog): hidupkan bot lagi bila mati ----------------
def _wlog(msg):
    print(time.strftime("%Y-%m-%d %H:%M:%S"), "[penjaga]", msg, flush=True)


def _read_float(path):
    try:
        with open(path) as f:
            return float(f.read().strip())
    except (OSError, ValueError):
        return None


def watchdog_run():
    """Dipanggil terjadwal oleh termux-job-scheduler (python bot.py --watchdog). Aman dijalankan berulang."""
    try:
        if os.path.getsize(WD_LOG) > 200_000:
            with open(WD_LOG, "r+b") as f:        # kosongkan tanpa memutus pengalihan keluaran
                f.truncate(0)
    except OSError:
        pass
    with open(WD_LAST, "w") as f:                  # detak: bukti job benar-benar berjalan
        f.write(str(time.time()))
    if _is_running():
        return 0
    if os.path.exists(STOP_FLAG):
        _wlog("bot mati tetapi dihentikan sengaja, dibiarkan")
        return 0
    cfg_load()
    if not cfg_get("TELEGRAM_BOT_TOKEN"):
        _wlog("token bot belum ada, tidak dimulai")
        return 2
    _wlog("bot mati -> dimulai ulang oleh penjaga")
    p = _spawn_listener(revived=True)
    time.sleep(1)
    rc = p.poll()
    if rc not in (None, 0):
        _wlog(f"gagal start (kode {rc})")
        return 1
    return 0


def _tjs(*args, timeout=25):
    exe = shutil.which("termux-job-scheduler")
    if not exe:
        return None, "NOT_FOUND"
    try:
        r = subprocess.run([exe, *args], capture_output=True, text=True, timeout=timeout,
                           stdin=subprocess.DEVNULL)
        return r.returncode, (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return None, "TIMEOUT"


def wd_install():
    """Return (berhasil, pesan)."""
    if not shutil.which("termux-job-scheduler"):
        return False, ("termux-job-scheduler tidak ditemukan. Pasang aplikasi Termux:API (dari sumber yang sama "
                       "dengan Termux), lalu jalankan di Termux: pkg install termux-api")
    shebang = shutil.which("bash") or "/system/bin/sh"
    script = (f"#!{shebang}\n"
              f"export HOME={shlex.quote(os.path.expanduser('~'))}\n"
              f"export PATH={shlex.quote(os.environ.get('PATH', ''))}\n"
              f"export TGBOT_HOME={shlex.quote(APP_DIR)}\n"
              f"exec {shlex.quote(sys.executable)} {shlex.quote(SELF_PATH)} --watchdog "
              f">> {shlex.quote(WD_LOG)} 2>&1\n")
    fd = os.open(WD_SCRIPT, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o700)
    with os.fdopen(fd, "w") as f:
        f.write(script)
    base = ["--script", WD_SCRIPT, "--job-id", WD_JOB_ID, "--period-ms", WD_PERIOD_MS, "--network", "any"]
    rc, out = _tjs(*base, "--persisted", "true")
    persisted = True
    if rc != 0 and out != "TIMEOUT":                # versi lama tanpa --persisted: coba tanpa
        rc, out = _tjs(*base)
        persisted = False
    if out == "TIMEOUT":
        return False, ("termux-job-scheduler tidak merespons dalam 25 detik (kendala yang dikenal di sebagian "
                       "versi Termux:API). Coba lagi, atau perbarui Termux:API.")
    if rc != 0 or "response 1" not in out.lower():
        return False, f"Gagal menjadwalkan: {out[:200] or 'tanpa keterangan'}"
    with open(WD_INSTALLED, "w") as f:
        f.write(str(time.time()))
    return True, ("✅ Penjaga dijadwalkan: dicek tiap ±15 menit (batas Android; bisa tertunda)."
                  + ("" if persisted else "\n⚠️ Versi Termux:API-mu tidak mendukung --persisted: job hilang "
                                          "setelah HP restart, jadwalkan ulang lewat /watchdog on.")
                  + "\nBuktikan jalan: tunggu ±30 menit lalu kirim /watchdog (lihat 'terakhir berjalan').")


def wd_remove():
    rc, out = _tjs("--cancel", "--job-id", WD_JOB_ID)
    for p in (WD_INSTALLED, WD_LAST):
        try:
            os.remove(p)
        except OSError:
            pass
    if out == "NOT_FOUND":
        return "termux-job-scheduler tidak ditemukan (Termux:API belum terpasang)."
    if out == "TIMEOUT":
        return "termux-job-scheduler tidak merespons. Job mungkin masih terdaftar; coba lagi."
    return "🗑 Penjaga dimatikan."


def wd_status():
    now = time.time()
    installed, last = _read_float(WD_INSTALLED), _read_float(WD_LAST)
    rc, out = _tjs("--pending", timeout=15)
    if out == "NOT_FOUND":
        reg = "tidak tersedia (Termux:API belum terpasang)"
    elif out == "TIMEOUT":
        reg = "tidak bisa membaca daftar job (termux-job-scheduler tidak merespons)"
    else:
        reg = "terdaftar" if WD_SCRIPT in out else "tidak terdaftar"
    lines = [f"Penjaga: {reg}",
             f"Bot: {'berjalan' if _is_running() else 'tidak berjalan'}"]
    if last:
        lines.append(f"Terakhir berjalan: {int((now - last) / 60)} menit lalu")
    else:
        lines.append("Terakhir berjalan: belum pernah")
    if reg == "terdaftar" and installed:
        if (last is None or last < installed) and now - installed > 2400:
            lines.append("⚠️ Terdaftar tetapi belum pernah berjalan setelah 40 menit. Android mungkin menahannya: "
                         "matikan penghemat baterai untuk Termux dan Termux:API.")
        elif last and now - last > 2700:
            lines.append("⚠️ Seharusnya jalan tiap ±15 menit, tetapi sudah lama tidak. Cek penghemat baterai.")
    if os.path.exists(STOP_FLAG):
        lines.append("Dihentikan sengaja: ya (penjaga tidak akan menghidupkan; jalankan python bot.py)")
    return "\n".join(lines)


def launch():
    """python bot.py: siapkan, luncurkan pendengar terpisah, cetak satu baris, selesai."""
    cfg_load()
    if _is_running():
        print("Bot sudah berjalan di latar belakang.")
        return 0
    if "--token" in sys.argv:
        cfg_set("TELEGRAM_BOT_TOKEN", None)
    ensure_deps()
    first_run_setup()
    _clear_stop_flag()                             # start manual = hapus tanda "dihentikan sengaja"
    p = _spawn_listener()
    time.sleep(1)                                  # deteksi crash seketika (mis. izin/Python rusak)
    rc = p.poll()
    if rc not in (None, 0):
        print(f"❌ Bot gagal dijalankan (kode {rc}). Log terakhir:\n{_tail(LOG_PATH, 15)}")
        return 1
    print("Bot berjalan di latar belakang...")
    return 0


def main():
    a = sys.argv[1:]
    if "--check" in a:
        sys.exit(check_mode())
    if "--standby" in a:
        run_worker("github")
    elif "--worker" in a:
        run_worker("phone")
    elif "--listen" in a:
        listen()
    elif "--stop" in a:
        sys.exit(stop_bot())
    elif "--status" in a:
        sys.exit(status_bot())
    elif "--log" in a:
        sys.exit(show_log(a))
    elif "--watchdog" in a:
        sys.exit(watchdog_run())
    elif "--watchdog-on" in a:
        ok, msg = wd_install()
        print(msg)
        sys.exit(0 if ok else 1)
    elif "--watchdog-off" in a:
        print(wd_remove())
    elif "--watchdog-status" in a:
        print(wd_status())
    else:
        sys.exit(launch())


if __name__ == "__main__":
    main()
