"""Pelacak sinyal: mencatat sinyal dari pemindai lalu memeriksa hasilnya (TP/SL/kedaluwarsa)
sehingga akurasi ASLI (forward test) bisa dilihat dari waktu ke waktu."""
import asyncio
import time

import httpx

import db
import scanner

ICON = {"tp": "✅", "sl": "❌", "exp": "⏱"}


def record(uid, data):
    t = data.get("asof") or int(time.time() * 1000)
    n = 0
    for s in data["signals"]:
        n += db.add_signal(uid, s["sym"], s["key"][0], s["key"][1], data["tf"],
                           s["entry"], s["stop"], s["tp"], t)
    return n


async def update_open():
    rows = db.open_signals()
    if not rows:
        return 0
    need = {(r["sym"], r["tf"]) for r in rows}
    sem = asyncio.Semaphore(6)
    async with httpx.AsyncClient(timeout=25) as client:
        async def one(sym, tf):
            async with sem:
                try:
                    return (sym, tf), await scanner.klines(client, sym, tf, 100 if tf == "4h" else 40)
                except Exception:
                    return (sym, tf), None
        got = dict(await asyncio.gather(*[one(s, t) for s, t in need]))
    closed = 0
    for r in rows:
        k = got.get((r["sym"], r["tf"]))
        if not k:
            continue
        res = scanner.resolve(dict(r), k, r["tf"])
        if res:
            db.close_signal(r["id"], *res)
            closed += 1
    return closed


def summary(uid):
    rows = db.resolved_signals(uid)
    openn = db.open_count(uid)
    if not rows:
        return f"📈 Pelacak: belum ada sinyal yang selesai ({openn} masih berjalan)."
    rs = [r["r"] for r in rows]
    st = scanner.stats(rs)
    txt = (f"📈 Pelacak: {st['n']} sinyal selesai ({openn} berjalan) · win {st['win']*100:.0f}% · "
           f"rata-rata {st['exp']:+.2f}R · total {sum(rs):+.1f}R")
    if st["n"] < 30:
        txt += "\n(Sampel masih kecil, belum bisa disimpulkan. Tunggu ≥30 sinyal.)"
    return txt


def report(uid, n=8):
    lines = [summary(uid)]
    for r in db.resolved_signals(uid)[:n]:
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
