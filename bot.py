import asyncio
import base64
import hashlib
import io
import json
import logging
import os
import sys
import time

from dotenv import load_dotenv
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.constants import ChatAction
from telegram.error import Conflict
from telegram.ext import (ApplicationBuilder, CallbackQueryHandler, CommandHandler,
                          ContextTypes, MessageHandler, filters)

load_dotenv()

import db  # noqa: E402
import ha  # noqa: E402
from agent import basic_system, run_agent  # noqa: E402
from providers import Router  # noqa: E402
from tools import fmt_ts  # noqa: E402

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)  # jangan tampilkan URL berisi token

router = Router()
ALLOWED = {int(x) for x in os.getenv("ALLOWED_USER_IDS", "").split(",") if x.strip()}
MAX_DOC_CHARS = 12000
MAX_FILE_BYTES = 10 * 1024 * 1024

HELP = (
    "🤖 *Bot AI Hybrid*\n\n"
    "Kirim pesan, foto, atau file (PDF/txt/csv/py) untuk dibaca.\n"
    "Minta pengingat dengan bahasa biasa, mis. _ingatkan aku 30 menit lagi minum obat_.\n\n"
    "/agent on|off – mode agent (tools) atau chat biasa\n"
    "/models – pilih provider & model AI (tombol)\n"
    "/model <provider> <id> – pilih model manual\n"
    "/use <provider|auto> – pilih provider saja\n"
    "/providers – status provider\n"
    "/memory – lihat memori jangka panjang\n"
    "/forget <id|all> – hapus memori\n"
    "/reminders – lihat pengingat\n"
    "/reset – hapus riwayat percakapan\n"
    "/id – lihat Telegram ID kamu"
)


def allowed(update: Update) -> bool:
    return not ALLOWED or update.effective_user.id in ALLOWED


async def send_long(update: Update, text: str):
    for i in range(0, len(text) or 1, 4000):
        await update.message.reply_text(text[i:i + 4000])


async def typing(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await ctx.bot.send_chat_action(update.effective_chat.id, ChatAction.TYPING)


# ---------------- perintah ----------------
async def start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if allowed(update):
        await update.message.reply_text(HELP, parse_mode="Markdown")


async def id_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(f"ID kamu: {update.effective_user.id}")


async def reset(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if allowed(update):
        db.clear_history(update.effective_user.id)
        await update.message.reply_text("Riwayat percakapan dihapus ✅ (memori jangka panjang tetap ada)")


async def agent_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not allowed(update):
        return
    arg = (ctx.args[0].lower() if ctx.args else "")
    if arg not in ("on", "off"):
        return await update.message.reply_text("Pakai: /agent on atau /agent off")
    db.set_agent(update.effective_user.id, arg == "on")
    await update.message.reply_text(f"Mode agent: {arg.upper()}")


async def use_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not allowed(update):
        return
    arg = (ctx.args[0].lower() if ctx.args else "")
    uid = update.effective_user.id
    if arg == "auto":
        db.set_provider(uid, None)
        return await update.message.reply_text("Provider: auto (fallback otomatis)")
    if arg not in router.names():
        return await update.message.reply_text("Pilihan: auto, " + ", ".join(router.names()))
    db.set_provider(uid, arg)
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
    rows = db.list_facts(update.effective_user.id)
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
        db.clear_facts(uid)
        return await update.message.reply_text("Semua memori dihapus ✅")
    if arg.isdigit():
        ok = db.del_fact(uid, int(arg))
        return await update.message.reply_text("Terhapus ✅" if ok else "Id tidak ditemukan.")
    await update.message.reply_text("Pakai: /forget <id> atau /forget all (lihat id di /memory)")


async def reminders_cmd(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not allowed(update):
        return
    rows = db.list_reminders(update.effective_user.id)
    if not rows:
        return await update.message.reply_text("Tidak ada pengingat aktif.")
    await send_long(update, "⏰ Pengingat:\n" + "\n".join(
        f"#{r['id']} {fmt_ts(r['due'])}{' (' + r['repeat'] + ')' if r['repeat'] else ''}: {r['text']}"
        for r in rows) + "\n\nHapus: bilang \"hapus pengingat #id\"")


# ---------------- pilih model ----------------
PAGE = 8


def current_sel(uid) -> str:
    p = db.get_prefs(uid)
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
    db.set_provider(update.effective_user.id, name, mid)
    await update.message.reply_text(
        f"✅ Dipakai: {name} / {mid}\n(Kalau gagal, bot otomatis pindah ke provider lain.)")


async def on_choice(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    q = update.callback_query
    uid = q.from_user.id
    if ALLOWED and uid not in ALLOWED:
        return await q.answer("Tidak diizinkan", show_alert=True)
    await q.answer()
    parts = q.data.split(":")
    kind = parts[0]
    cache = ctx.bot_data.setdefault("models", {})
    if kind == "a":
        db.set_provider(uid, None)
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
        db.set_provider(uid, name, ids[idx])
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


# ---------------- pesan teks (agent / chat) ----------------
async def on_message(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not allowed(update):
        return await update.message.reply_text("⛔ Kamu tidak diizinkan.")
    uid = update.effective_user.id
    text = update.message.text
    p = db.get_prefs(uid)
    hist = db.get_history(uid)
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

    db.add_message(uid, "user", text)
    db.add_message(uid, "assistant", answer)
    footer = f"\n\n— {used}" + (f" · tools: {', '.join(tools)}" if tools else "")
    await send_long(update, answer + footer)


# ---------------- foto ----------------
async def on_photo(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if not allowed(update):
        return
    uid = update.effective_user.id
    p = db.get_prefs(uid)
    await typing(update, ctx)
    try:
        tg_file = await update.message.photo[-1].get_file()
        data = bytes(await tg_file.download_as_bytearray())
        b64 = base64.b64encode(data).decode()
        caption = update.message.caption or "Jelaskan gambar ini dengan detail."
        content = [{"type": "text", "text": caption},
                   {"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{b64}"}}]
        msgs = [{"role": "system", "content": basic_system(uid)}] + db.get_history(uid) + [
            {"role": "user", "content": content}]
        answer, used = await router.chat(msgs, p["provider"], vision=True)
    except Exception as e:
        logging.exception("foto gagal")
        return await update.message.reply_text(f"⚠️ {e}")
    db.add_message(uid, "user", f"[Mengirim gambar] {caption}")
    db.add_message(uid, "assistant", answer)
    await send_long(update, answer + f"\n\n— {used} (gambar)")


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
    if doc.file_size and doc.file_size > MAX_FILE_BYTES:
        return await update.message.reply_text("File terlalu besar (maks 10 MB).")
    is_pdf = name.endswith(".pdf") or mime == "application/pdf"
    is_text = name.endswith((".txt", ".md", ".csv", ".py", ".json", ".log", ".html")) \
        or mime.startswith("text/")
    if not (is_pdf or is_text):
        return await update.message.reply_text("Format belum didukung. Kirim PDF, txt, md, csv, py, atau json.")
    p = db.get_prefs(uid)
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
        msgs = [{"role": "system", "content": basic_system(uid)}] + db.get_history(uid) + [
            {"role": "user", "content": prompt}]
        answer, used = await router.chat(msgs, p["provider"], model=p["model"])
    except Exception as e:
        logging.exception("dokumen gagal")
        return await update.message.reply_text(f"⚠️ {e}")
    db.add_message(uid, "user", f"[Mengirim dokumen {doc.file_name}] {question}")
    db.add_message(uid, "assistant", answer)
    await send_long(update, answer + f"\n\n— {used} (dokumen){note}")


# ---------------- pengingat terjadwal ----------------
async def reminder_loop(app):
    while True:
        try:
            now = time.time()
            for r in db.due_reminders(now):
                try:
                    await app.bot.send_message(r["chat_id"], f"⏰ Pengingat: {r['text']}")
                except Exception:
                    logging.exception("gagal kirim pengingat #%s", r["id"])
                db.advance_or_delete(r, now)
        except Exception:
            logging.exception("reminder_loop")
        await asyncio.sleep(15)


# ---------------- failover HP <-> GitHub ----------------
HANDOFF_WAIT = int(os.getenv("HA_HANDOFF_WAIT", "30"))
MAX_SECONDS = int(os.getenv("HOST_MAX_SECONDS", "0"))  # 0 = tanpa batas (HP)


def _ha_startup() -> bool:
    """True = lanjut jalan. False = node ini harus standby/keluar."""
    if not ha.ENABLED:
        return True
    try:
        data = ha.read_all()
    except Exception as e:
        logging.warning("HA: gagal membaca gist: %s", e)
        return ha.ROLE == "phone"  # HP tetap jalan; GitHub tidak (hindari bentrok)
    lease, state = data["lease"], data["state"]
    if ha.ROLE == "github":
        if ha.lease_fresh(lease, "phone"):
            logging.info("HP aktif -> GitHub standby, keluar")
            return False
        ha.write(holder="github")
        if state.get("data"):
            db.import_state(state["data"])
        return True
    # peran HP: selalu prioritas
    took_over = ha.lease_fresh(lease, "github")
    ha.write(holder="phone")
    if took_over:
        logging.info("HP kembali: meminta GitHub berhenti, tunggu %ss", HANDOFF_WAIT)
        time.sleep(HANDOFF_WAIT)
        try:
            state = ha.read_all()["state"]
        except Exception:
            pass
    if state.get("by") == "github" and state.get("data"):
        db.import_state(state["data"])
    return True


def ha_startup() -> bool:
    if not ha.ENABLED:
        return True
    try:
        return _ha_startup()
    except Exception as e:
        logging.warning(
            "HA gagal (%s). Periksa GIST_TOKEN (klasik, scope gist) dan HA_GIST_ID. %s", e,
            "Bot HP tetap jalan tanpa failover." if ha.ROLE == "phone" else "GitHub tidak jalan.")
        return ha.ROLE == "phone"


def _snapshot():
    snap = db.export_state()
    return snap, hashlib.md5(json.dumps(snap, sort_keys=True).encode()).hexdigest()


async def ha_loop(app):
    role = ha.ROLE
    interval = 15 if role == "github" else 30
    started = time.time()
    last_hash = None
    tick = 0
    while True:
        await asyncio.sleep(interval)
        tick += 1
        try:
            if time.time() - started > 60 and getattr(app.updater, "running", True) is False:
                logging.error("Polling berhenti, keluar agar dimulai ulang")
                os._exit(1)
            lease = (await asyncio.to_thread(ha.read_all))["lease"]
            if role == "github":
                if ha.lease_fresh(lease, "phone"):
                    snap, _ = _snapshot()
                    await asyncio.to_thread(ha.write, None, snap, "github")
                    logging.info("HP aktif lagi -> GitHub menyerahkan tugas")
                    os._exit(10)
                if MAX_SECONDS and time.time() - started > MAX_SECONDS:
                    snap, _ = _snapshot()
                    await asyncio.to_thread(ha.write, "none", snap, "github")
                    logging.info("Batas waktu job tercapai -> sambung run berikutnya")
                    os._exit(0)
                if tick % 2:  # tulis lease tiap ~30 dtk (hindari rate limit)
                    continue
            snap, h = _snapshot()
            await asyncio.to_thread(ha.write, role, snap if h != last_hash else None, role)
            last_hash = h
        except Exception as e:
            logging.warning("ha_loop: %s", e)


async def on_error(update, ctx: ContextTypes.DEFAULT_TYPE):
    if isinstance(ctx.error, Conflict):
        logging.warning("Conflict: ada instance lain yang polling (menunggu serah-terima)")
        return
    logging.error("Error: %s", ctx.error)


async def post_shutdown(app):
    for k in ("reminder_task", "ha_task"):
        t = app.bot_data.get(k)
        if t:
            t.cancel()


async def post_init(app):
    app.bot_data["reminder_task"] = asyncio.create_task(reminder_loop(app))
    if ha.ENABLED:
        app.bot_data["ha_task"] = asyncio.create_task(ha_loop(app))


def main():
    if not ha_startup():
        sys.exit(11)
    app = ApplicationBuilder().token(os.environ["TELEGRAM_BOT_TOKEN"]).post_init(post_init).post_shutdown(post_shutdown).build()
    app.add_error_handler(on_error)
    for name, fn in [("start", start), ("help", start), ("id", id_cmd), ("reset", reset),
                     ("agent", agent_cmd), ("use", use_cmd), ("providers", providers_cmd),
                     ("memory", memory_cmd), ("forget", forget_cmd), ("reminders", reminders_cmd),
                     ("models", models_cmd), ("model", model_cmd)]:
        app.add_handler(CommandHandler(name, fn))
    app.add_handler(CallbackQueryHandler(on_choice))
    app.add_handler(MessageHandler(filters.PHOTO, on_photo))
    app.add_handler(MessageHandler(filters.Document.ALL, on_document))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, on_message))
    try:
        app.run_polling()
    finally:
        if ha.ENABLED and ha.ROLE == "phone":  # berhenti baik-baik: lepas lease supaya GitHub cepat ambil alih
            try:
                snap, _ = _snapshot()
                ha.write("none", snap, "phone")
            except Exception:
                pass


if __name__ == "__main__":
    main()
