import ast
import html as htmlmod
import operator as op
import re
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import httpx

import db

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
    fid = db.add_fact(ctx["uid"], fact)
    return f"Tersimpan (id {fid})." if fid else "Memori penuh (maks 100). Hapus dulu beberapa."


async def forget_memory(args, ctx):
    try:
        fid = int(_arg(args, "id"))
    except ValueError:
        return "Error: id harus angka."
    return "Terhapus." if db.del_fact(ctx["uid"], fid) else "Id tidak ditemukan."


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
    rid = db.add_reminder(ctx["uid"], ctx["chat_id"], text, due, repeat)
    extra = f", berulang {repeat}" if repeat else ""
    return f"Pengingat #{rid} diset untuk {fmt_ts(due)}{extra}."


async def list_reminders(args, ctx):
    rows = db.list_reminders(ctx["uid"])
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
    return "Pengingat dihapus." if db.del_reminder(ctx["uid"], rid) else "Id tidak ditemukan."


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
    "list_reminders": (list_reminders, "Lihat semua pengingat aktif. args: {}"),
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
