"""Koordinasi failover HP <-> cadangan lewat GitHub Gist (hanya stdlib).
Gist berisi 2 file: lease.json (siapa yang sedang 'memegang' bot) dan
state.json (snapshot memori/pengingat/pengaturan)."""
import json
import os
import sys
import time
import urllib.request

try:  # opsional, hanya untuk perintah `python ha.py create`
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

GIST_ID = os.getenv("HA_GIST_ID", "")
TOKEN = os.getenv("GIST_TOKEN", "")
ROLE = os.getenv("NODE_ROLE", "phone")          # "phone" atau "github"
STALE = int(os.getenv("HA_STALE_SECONDS", "120"))
ENABLED = bool(GIST_ID and TOKEN)
API = "https://api.github.com/gists"


def _req(method, url, body=None):
    req = urllib.request.Request(
        url, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": f"Bearer {TOKEN}",
                 "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28",
                 "User-Agent": "tg-ai-bot-ha"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode())


def _file_json(gist, name):
    f = gist.get("files", {}).get(name)
    if not f:
        return {}
    content = f.get("content") or ""
    if f.get("truncated") and f.get("raw_url"):
        with urllib.request.urlopen(f["raw_url"], timeout=20) as r:
            content = r.read().decode()
    try:
        return json.loads(content)
    except Exception:
        return {}


def read_all():
    g = _req("GET", f"{API}/{GIST_ID}")
    return {"lease": _file_json(g, "lease.json"), "state": _file_json(g, "state.json")}


def lease_fresh(lease, holder=None):
    return (bool(lease) and time.time() - lease.get("ts", 0) < STALE
            and (holder is None or lease.get("holder") == holder))


def write(holder=None, state=None, by=None):
    """holder: 'phone'|'github'|'none' (none = dilepas). state: dict snapshot."""
    files = {}
    if holder is not None:
        files["lease.json"] = {"content": json.dumps(
            {"holder": holder, "ts": 0 if holder == "none" else time.time()})}
    if state is not None:
        files["state.json"] = {"content": json.dumps(
            {"by": by, "ts": time.time(), "data": state})}
    if files:
        _req("PATCH", f"{API}/{GIST_ID}", {"files": files})


def create():
    body = {"description": "tg-ai-bot failover", "public": False,
            "files": {"lease.json": {"content": "{}"}, "state.json": {"content": "{}"}}}
    return _req("POST", API, body)["id"]


if __name__ == "__main__":
    if sys.argv[1:] == ["create"]:
        print("HA_GIST_ID=" + create())
    else:
        print("Pakai: python ha.py create")
