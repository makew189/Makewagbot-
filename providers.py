"""Router multi-provider: semua provider memakai format OpenAI-compatible.
- Jika satu provider kena limit/error, otomatis pindah ke provider berikutnya.
- Jika nama model sudah dihapus (404/410), router otomatis mencari model
  yang tersedia lewat endpoint /models, jadi tidak perlu edit kode manual."""
import os
import time
import logging
import httpx

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
        for p in PROVIDERS:
            key = os.getenv(p["key"])
            if not key:
                continue
            pinned = os.getenv(p["name"].upper() + "_MODEL")
            self.providers.append({**p, "api_key": key,
                                   "model": pinned or p["model"],
                                   "pinned": bool(pinned), "down_until": 0.0})
        if not self.providers:
            raise RuntimeError("Belum ada API key AI yang diisi di .env")
        self.client = httpx.AsyncClient(timeout=60)

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
        order = [p for p in self.providers if p.get("vision")] if vision \
            else list(self.providers)
        if vision and not order:
            raise RuntimeError("Tidak ada provider yang mendukung gambar. "
                               "Isi GEMINI_API_KEY, MISTRAL_API_KEY atau GITHUB_TOKEN di .env")
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
                    text = r.json()["choices"][0]["message"]["content"]
                    if not text:
                        raise RuntimeError("respons kosong")
                    return text.strip(), p["name"]
                except Exception as e:
                    log.warning("%s gagal: %s", p["name"], e)
                    p["down_until"] = time.time() + COOLDOWN
                    errors.append(f"{p['name']}"
                                  f"{' (' + override + ')' if override else ''}: {str(e)[:120]}")
                    break
        raise RuntimeError("Semua provider gagal:\n" + "\n".join(errors))
