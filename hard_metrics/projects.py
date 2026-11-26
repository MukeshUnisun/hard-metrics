import glob, os, re
from collections import defaultdict
import psutil
from . import files, utils

DB_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch", 11211: "Memcached"}


def listeners(owner):
    seen = {}
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        return []
    for c in conns:
        if c.status != "LISTEN" or not c.laddr:
            continue
        ip, port = c.laddr.ip, c.laddr.port
        exp = "public" if ip in ("0.0.0.0", "::") else "local" if ip.startswith("127.") or ip == "::1" else "interface"
        if (port, exp) in seen:
            continue
        proc = cmd = ""
        if c.pid:
            try:
                p = psutil.Process(c.pid)
                proc, cmd = p.name(), " ".join(p.cmdline())[:110]
            except Exception:
                pass
        o = owner.get(port)
        seen[(port, exp)] = {"port": port, "exposure": exp, "process": proc, "cmd": cmd,
                             "container": o[0] if o else "", "project": o[1] if o else "",
                             "service": DB_PORTS.get(port, ""), "risk": port in DB_PORTS and exp == "public"}
    return sorted(seen.values(), key=lambda r: r["port"])


def nginx_sites(owner, lports):
    rows = []
    for f in sorted(glob.glob("/etc/nginx/sites-enabled/*") + glob.glob("/etc/nginx/conf.d/*.conf")):
        try:
            txt = re.sub(r"#.*", "", open(f, errors="ignore").read())
        except OSError:
            continue
        for blk in re.split(r"\bserver\s*\{", txt)[1:]:
            names = " ".join(re.findall(r"server_name\s+([^;]+);", blk)).split()
            listen = " ".join(re.findall(r"listen\s+([^;]+);", blk))
            roots = re.findall(r"\broot\s+([^;]+);", blk)
            tg = []
            for pr in sorted(set(re.findall(r"proxy_pass\s+([^;\s]+)", blk))):
                m = re.search(r":(\d+)", pr)
                port = int(m.group(1)) if m else None
                o = owner.get(port)
                tg.append({"url": pr, "container": o[0] if o else "", "project": o[1] if o else "", "process": lports.get(port, "")})
            rows.append({"file": os.path.basename(f), "names": names, "ssl": "ssl" in listen or "443" in listen,
                         "targets": tg, "root": roots[0].strip() if roots else ""})
    return rows


def overview():
    d = utils.docker_containers()
    groups, owner = defaultdict(list), {}
    for c in d["containers"]:
        proj = c.get("project") or "(standalone)"
        for p in c["ports"]:
            try:
                owner[int(p.split("→")[0])] = (c["name"], proj)
            except ValueError:
                pass
        groups[proj].append(c)
    out = []
    for name, cs in sorted(groups.items()):
        wd = next((c["workdir"] for c in cs if c.get("workdir")), "")
        ok = False
        if wd:
            try:
                files.safe_path(wd)
                ok = True
            except Exception:
                pass
        out.append({"name": name, "workdir": wd, "browsable": ok, "total": len(cs),
                    "running": sum(1 for c in cs if c["status"] == "running"), "services": cs})
    ls = listeners(owner)
    return {"docker_ok": d["available"], "docker_error": d.get("error", ""), "projects": out,
            "listeners": ls, "nginx": nginx_sites(owner, {l["port"]: l["process"] for l in ls})}
