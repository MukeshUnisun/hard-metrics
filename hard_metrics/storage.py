"""Disk usage analyzer: du-based folder breakdown, biggest files, Docker usage. Scans run in the background at low priority."""
import os, shutil, subprocess, threading, time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from django.conf import settings
from . import files, utils

_ipool, _bpool = ThreadPoolExecutor(2), ThreadPoolExecutor(2)
_jobs, _lock, TTL = {}, threading.Lock(), 900


def _nice():
    return (["nice", "-n", "19"] if shutil.which("nice") else []) + (["ionice", "-c3"] if shutil.which("ionice") else [])


def _view(j):
    return {"state": j["state"], "error": j["error"], "result": j["result"], "age": int(time.time() - j["finished"]) if j["finished"] else None}


def _job(key, fn, force=False, pool=None, ttl=TTL):
    with _lock:
        j = _jobs.get(key)
        if j and j["state"] == "running":
            return _view(j)
        if j and j["state"] == "done" and not force and time.time() - j["finished"] < ttl:
            return _view(j)
        nj = {"state": "running", "finished": 0, "result": j["result"] if j else None, "error": ""}
        _jobs[key] = nj

    def work():
        try:
            nj["result"] = fn()
            nj["state"] = "done"
        except Exception as e:
            nj["error"], nj["state"] = str(e)[:300], "error"
        nj["finished"] = time.time()
    (pool or _ipool).submit(work)
    return _view(nj)


def _run(cmd):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=settings.HM_DU_TIMEOUT).stdout
        return out, False
    except subprocess.TimeoutExpired as e:
        o = e.stdout or ""
        return (o.decode(errors="replace") if isinstance(o, bytes) else o), True


def _du(path):
    p = path.rstrip("/") or "/"
    out, partial = _run(_nice() + ["du", "-x", "-k", "--max-depth=1", p])
    rows = []
    for line in out.splitlines():
        kb, _, name = line.partition("\t")
        if kb.isdigit():
            rows.append((int(kb), name))
    total = next((kb for kb, n in rows if n == p), None)
    kids = sorted([(kb, n) for kb, n in rows if n != p], reverse=True)
    base = total or sum(k for k, _ in kids) or 1
    return {"path": p, "total_kb": total or base, "partial": partial or total is None,
            "loose_kb": max((total or 0) - sum(k for k, _ in kids), 0),
            "children": [{"name": os.path.basename(n) or n, "path": n, "kb": kb, "pct": round(kb / base * 100, 1), "dir": os.path.isdir(n)} for kb, n in kids[:60]]}


def _big(path):
    out, partial = _run(_nice() + ["find", path, "-xdev", "-type", "f", "-size", f"+{settings.HM_BIG_FILE_MB}M", "-printf", "%s\t%T@\t%p\n"])
    rows = []
    for line in out.splitlines():
        a = line.split("\t", 2)
        if len(a) == 3 and a[0].isdigit():
            rows.append({"size": int(a[0]), "mtime": datetime.fromtimestamp(float(a[1])).strftime("%Y-%m-%d"), "path": a[2]})
    rows.sort(key=lambda r: -r["size"])
    return {"path": path, "files": rows[:30], "partial": partial, "min_mb": settings.HM_BIG_FILE_MB}


def _docker():
    df = utils._client().df()
    proj = {}

    def add(name, n):
        if name:
            proj[name] = proj.get(name, 0) + max(n, 0)
    vols, cons, imgs = [], [], []
    for v in df.get("Volumes") or []:
        u = v.get("UsageData") or {}
        pj = (v.get("Labels") or {}).get("com.docker.compose.project", "")
        vols.append({"name": v.get("Name", ""), "size": max(u.get("Size", 0), 0), "project": pj, "in_use": (u.get("RefCount", 0) or 0) > 0})
        add(pj, u.get("Size", 0))
    for c in df.get("Containers") or []:
        pj = (c.get("Labels") or {}).get("com.docker.compose.project", "")
        nm = (c.get("Names") or [c.get("Id", "")[:12]])[0].lstrip("/")
        cons.append({"name": nm, "rw": c.get("SizeRw") or 0, "state": c.get("State", ""), "project": pj})
        add(pj, c.get("SizeRw") or 0)
    for i in df.get("Images") or []:
        imgs.append({"name": (i.get("RepoTags") or ["<none>"])[0], "size": i.get("Size", 0), "unused": i.get("Containers", 0) == 0})
    cache = df.get("BuildCache") or []
    cache_total = sum(b.get("Size", 0) for b in cache)
    cache_free = sum(b.get("Size", 0) for b in cache if not b.get("InUse"))
    unused = sum(i["size"] for i in imgs if i["unused"])
    vols.sort(key=lambda x: -x["size"]); cons.sort(key=lambda x: -x["rw"]); imgs.sort(key=lambda x: -x["size"])
    return {"images": df.get("LayersSize") or sum(i["size"] for i in imgs), "containers": sum(c["rw"] for c in cons),
            "volumes": sum(v["size"] for v in vols), "build_cache": cache_total, "reclaimable": unused + cache_free,
            "projects": sorted(({"name": k, "size": v} for k, v in proj.items()), key=lambda x: -x["size"]),
            "volume_list": vols[:15], "container_list": cons[:15], "image_list": imgs[:15]}


def scan(path, force=False):
    rp = files.safe_path(path)
    return _job(("du", rp), lambda: _du(rp), force)


def big(path, force=False):
    rp = files.safe_path(path)
    return _job(("big", rp), lambda: _big(rp), force, ttl=600)


def docker_usage(force=False):
    return _job(("docker",), _docker, force, ttl=300)


def top(force=False):
    roots, seen = [], set()
    for r in settings.HM_DU_ROOTS:
        rp = os.path.realpath(r)
        if os.path.isdir(rp) and rp not in seen:
            seen.add(rp); roots.append(rp)
    items, pending = [], 0
    for rp in roots:
        v = _job(("du", rp), lambda rp=rp: _du(rp), force, _bpool)
        pending += v["state"] == "running"
        res = v["result"]
        if not res:
            continue
        for c in res["children"]:
            if os.path.realpath(c["path"]) not in seen:
                items.append({"name": c["name"], "path": c["path"], "kb": c["kb"], "root": rp, "dir": c["dir"]})
        if res["loose_kb"] > 0:
            items.append({"name": "(loose files)", "path": rp, "kb": res["loose_kb"], "root": rp, "dir": False})
    items.sort(key=lambda i: -i["kb"])
    d = shutil.disk_usage("/")
    return {"items": items[:30], "pending": pending, "disk": {"total": d.total, "used": d.used, "free": d.free}}
