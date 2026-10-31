"""Pemindai koin (spot Binance, data publik tanpa API key).

HANYA memberi SINYAL & hitungan risiko. Tidak ada eksekusi order.
Prinsip: sinyal hanya ditampilkan bila strateginya lolos uji historis
(backtest gabungan semua koin, setelah biaya, in-sample DAN out-of-sample).
Tidak ada indikator yang menjamin untung; ini penyaring, bukan ramalan."""
import asyncio
import time
from datetime import datetime, timedelta, timezone

import httpx

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
