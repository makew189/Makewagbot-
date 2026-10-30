"""Dipanggil workflow GitHub: apakah GitHub perlu mengambil alih? (hanya stdlib)"""
import os
import sys

import ha


def out(v):
    p = os.getenv("GITHUB_OUTPUT")
    if p:
        with open(p, "a") as f:
            f.write(f"standby={v}\n")


try:
    lease = ha.read_all()["lease"]
except Exception as e:
    print("Gagal membaca gist:", e)
    out("false")
    sys.exit(0)

if ha.lease_fresh(lease, "phone"):
    print("HP aktif -> GitHub tidak perlu jalan")
    out("false")
elif ha.lease_fresh(lease, "github"):
    print("Instance GitHub lain sedang jalan")
    out("false")
else:
    print("HP tidak aktif -> GitHub mengambil alih")
    out("true")
