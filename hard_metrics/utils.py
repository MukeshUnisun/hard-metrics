"""System data collectors for Hard Metrics (psutil + subprocess + Docker SDK)."""
import glob, os, shutil, socket, stat, subprocess, threading, time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import psutil
from django.conf import settings

try:
    import docker
except ImportError:  # docker SDK optional
    docker = None

HISTORY = deque(maxlen=720)  # 720 samples x 5s = 1 hour
LATEST = {}
_net = {"t": None, "rx": 0, "tx": 0}
_started = False
_cache = {}


def run(cmd, timeout=6, priv=False):
    """Run a command, return (returncode, output). priv -> sudo -n when not root."""
    if priv and hasattr(os, "geteuid") and os.geteuid() != 0:
        cmd = ["sudo", "-n"] + cmd
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or p.stderr or "").strip()
    except Exception as e:
        return 1, str(e)


def hostname():
    return socket.gethostname()


# ---------------- resource metrics ----------------
def cpu():
    try:
        load = [round(x, 2) for x in os.getloadavg()]
    except (AttributeError, OSError):
        load = [0, 0, 0]
    temps = {}
    try:
        for name, entries in (psutil.sensors_temperatures() or {}).items():
            temps[name] = round(max(e.current for e in entries), 1)
    except Exception:
        pass
    return {"total": psutil.cpu_percent(interval=None), "per_core": psutil.cpu_percent(interval=None, percpu=True),
            "cores": psutil.cpu_count(), "load": load, "temps": temps}


def memory():
    m = psutil.virtual_memory()
    return {"total": m.total, "used": m.used, "free": m.free, "available": m.available, "percent": m.percent}


def disks():
    out = []
    for path in settings.HM_DISK_PATHS:
        if not os.path.exists(path):
            continue
        try:
            u = shutil.disk_usage(path)
            s = os.statvfs(path)
            used_i = s.f_files - s.f_ffree
            out.append({"mount": path, "total": u.total, "used": u.used, "free": u.free,
                        "percent": round(u.used / u.total * 100, 1) if u.total else 0,
                        "inode_total": s.f_files, "inode_used": used_i,
                        "inode_percent": round(used_i / s.f_files * 100, 1) if s.f_files else 0})
        except Exception:
            continue
    return out


def sample():
    """Take one sample; computes network speed from the previous sample."""
    c = psutil.net_io_counters()
    now = time.time()
    rx = tx = 0.0
    if _net["t"]:
        dt = max(now - _net["t"], 0.001)
        rx, tx = (c.bytes_recv - _net["rx"]) / dt, (c.bytes_sent - _net["tx"]) / dt
    _net.update(t=now, rx=c.bytes_recv, tx=c.bytes_sent)
    cp, mem = cpu(), memory()
    LATEST.update(cpu=cp, memory=mem, network={"rx_bps": round(rx), "tx_bps": round(tx),
                                                "rx_total": c.bytes_recv, "tx_total": c.bytes_sent})
    HISTORY.append({"t": datetime.now().strftime("%H:%M:%S"), "cpu": cp["total"], "ram": mem["percent"]})


def start_sampler():
    global _started
    if _started:
        return
    _started = True
    psutil.cpu_percent(percpu=True)  # warm-up

    def loop():
        while True:
            try:
                sample()
            except Exception:
                pass
            time.sleep(settings.HM_SAMPLE_SECONDS)
    threading.Thread(target=loop, daemon=True, name="hm-sampler").start()


def metrics():
    if not LATEST:
        sample()
        time.sleep(0.3)
        sample()
    return {**LATEST, "disks": disks(), "history": list(HISTORY),
            "uptime": int(time.time() - psutil.boot_time()), "ts": datetime.now().strftime("%H:%M:%S")}


# ---------------- services ----------------
def _service(item):
    label, units = item
    first = None
    for u in units.split("|"):
        _, out = run(["systemctl", "is-active", u])
        st = (out.splitlines() or ["unknown"])[0]
        st = st if st in ("active", "failed", "inactive") else "unknown"
        if st == "active":
            return {"name": label, "unit": u, "state": st}
        first = first or {"name": label, "unit": u, "state": st}
    return first


def services():
    with ThreadPoolExecutor(7) as ex:
        return list(ex.map(_service, settings.HM_SERVICES))


# ---------------- security ----------------
def fail2ban():
    rc, out = run(["fail2ban-client", "status"], priv=True)
    if rc != 0:
        return {"available": False, "error": out[:200], "jails": []}
    names = []
    for line in out.splitlines():
        if "Jail list" in line:
            names = [j.strip() for j in line.split(":", 1)[1].split(",") if j.strip()]
    jails = []
    for j in names:
        _, o = run(["fail2ban-client", "status", j], priv=True)
        d = {"name": j, "failed": 0, "total_failed": 0, "banned": 0, "total_banned": 0, "ips": []}
        for line in o.splitlines():
            val = line.split(":", 1)[-1].strip()
            if "Currently failed" in line: d["failed"] = int(val or 0)
            elif "Total failed" in line: d["total_failed"] = int(val or 0)
            elif "Currently banned" in line: d["banned"] = int(val or 0)
            elif "Total banned" in line: d["total_banned"] = int(val or 0)
            elif "Banned IP list" in line: d["ips"] = val.split()
        jails.append(d)
    return {"available": True, "jails": jails,
            "total_failed": sum(j["total_failed"] for j in jails),
            "banned_now": sum(j["banned"] for j in jails)}


def sessions():
    users = [{"user": u.name, "tty": u.terminal or "-", "host": u.host or "local",
              "since": datetime.fromtimestamp(u.started).strftime("%Y-%m-%d %H:%M")} for u in psutil.users()]
    rc, out = run(["last", "-n", "8", "-w"])
    return {"active": users, "recent": out.splitlines()[:8] if rc == 0 else []}


def env_audit():
    seen, rows = set(), []
    for pat in settings.HM_ENV_PATHS:
        for p in glob.glob(pat):
            if p in seen or not os.path.isfile(p):
                continue
            seen.add(p)
            try:
                mode = stat.S_IMODE(os.stat(p).st_mode)
                debug = None
                with open(p, errors="ignore") as f:
                    for line in f:
                        if line.strip().upper().startswith("DEBUG"):
                            debug = line.split("=", 1)[-1].strip().strip("'\"").lower()
                            break
                rows.append({"path": p, "mode": oct(mode)[2:], "perm_ok": mode == 0o600,
                             "debug": debug, "debug_ok": None if debug is None else debug not in ("true", "1", "yes", "on")})
            except PermissionError:
                rows.append({"path": p, "mode": "?", "perm_ok": False, "debug": None, "debug_ok": None})
    return rows


# ---------------- backup ----------------
def backup():
    import json
    f = settings.HM_BACKUP_STATUS_FILE
    if f and os.path.isfile(f):
        try:
            d = json.load(open(f))
            code = int(d.get("status_code", 1))
            return {"found": True, "timestamp": d.get("timestamp"), "size": d.get("size", 0),
                    "path": d.get("path", ""), "code": code, "ok": code == 0}
        except Exception:
            pass
    from . import backups
    items = backups.list_backups()
    if not items:
        return {"found": False}
    n = items[0]
    ok = n["size"] > 0 and n["age_h"] <= settings.HM_BACKUP_MAX_AGE_HOURS
    return {"found": True, "timestamp": n["time"], "size": n["size"], "path": n["path"], "code": 0 if ok else 1, "ok": ok}


def system_status():
    with ThreadPoolExecutor(5) as ex:
        s, f, ss, e, b = (ex.submit(fn) for fn in (services, fail2ban, sessions, env_audit, backup))
        return {"services": s.result(), "fail2ban": f.result(), "sessions": ss.result(),
                "env": e.result(), "backup": b.result()}


# ---------------- docker ----------------
def _client():
    if docker is None:
        raise RuntimeError("docker SDK not installed (pip install docker)")
    return docker.from_env()


def _stats(c):
    try:
        s = c.stats(stream=False)
        cu, pu = s["cpu_stats"], s["precpu_stats"]
        cd = cu["cpu_usage"]["total_usage"] - pu["cpu_usage"]["total_usage"]
        sd = cu.get("system_cpu_usage", 0) - pu.get("system_cpu_usage", 0)
        n = cu.get("online_cpus") or len(cu["cpu_usage"].get("percpu_usage") or [1])
        pct = cd / sd * n * 100 if sd > 0 and cd > 0 else 0
        ms = s["memory_stats"]
        used = ms.get("usage", 0) - ms.get("stats", {}).get("inactive_file", 0)
        return round(pct, 2), max(used, 0), ms.get("limit", 0)
    except Exception:
        return 0, 0, 0


def _uptime(c):
    st = c.attrs.get("State", {})
    if st.get("Status") != "running":
        return ""
    try:
        t = datetime.strptime(st["StartedAt"][:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
        sec = int((datetime.now(timezone.utc) - t).total_seconds())
        d, r = divmod(sec, 86400); h, r = divmod(r, 3600)
        return f"{d}d {h}h {r // 60}m" if d else f"{h}h {r // 60}m"
    except Exception:
        return ""


def docker_containers():
    hit = _cache.get("docker")
    if hit and time.time() - hit[0] < 4:
        return hit[1]
    try:
        cs = _client().containers.list(all=True)
    except Exception as e:
        return {"available": False, "error": str(e)[:300], "containers": []}
    running = [c for c in cs if c.status == "running"]
    with ThreadPoolExecutor(8) as ex:
        st = dict(zip([c.id for c in running], ex.map(_stats, running)))
    rows = []
    for c in cs:
        cpu_p, mu, ml = st.get(c.id, (0, 0, 0))
        ports = c.attrs.get("NetworkSettings", {}).get("Ports") or {}
        pm = [f"{b['HostPort']}→{k}" for k, v in ports.items() if v for b in v]
        rows.append({"name": c.name, "project": c.labels.get("com.docker.compose.project", ""), "service": c.labels.get("com.docker.compose.service", ""), "workdir": c.labels.get("com.docker.compose.project.working_dir", ""), "image": (c.attrs.get("Config", {}).get("Image") or ""),
                     "image_id": c.attrs.get("Image", "")[7:19], "status": c.status, "uptime": _uptime(c),
                     "ports": sorted(set(pm)), "cpu": cpu_p, "mem_used": mu, "mem_limit": ml,
                     "mem_pct": round(mu / ml * 100, 2) if ml else 0})
    rows.sort(key=lambda r: r["name"])
    data = {"available": True, "containers": rows}
    _cache["docker"] = (time.time(), data)
    return data


def container_action(name, action):
    if action not in ("start", "stop", "restart", "remove"):
        return {"ok": False, "error": "Unknown action"}
    try:
        c = _client().containers.get(name)
        c.remove(force=True) if action == "remove" else getattr(c, action)()
        _cache.pop("docker", None)
        return {"ok": True, "message": f"{name}: {action} done"}
    except Exception as e:
        return {"ok": False, "error": str(e)[:300]}


def container_logs(name, tail=300):
    try:
        raw = _client().containers.get(name).logs(tail=tail, timestamps=True)
        return {"ok": True, "logs": raw.decode(errors="replace")}
    except Exception as e:
        return {"ok": False, "logs": "", "error": str(e)[:300]}
