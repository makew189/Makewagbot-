"""Agent dengan protokol JSON sederhana (tidak butuh function-calling bawaan
provider, jadi jalan di model gratis apa pun)."""
import json
import re

import db
from tools import TOOLS, now_str, run_tool

MAX_STEPS = 4


def _facts_text(uid):
    rows = db.list_facts(uid)
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
