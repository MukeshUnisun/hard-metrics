"""Attack detection (SSH auth log + nginx access log) and IP blocking (ufw / fail2ban)."""
import ipaddress, os, re, time
from collections import Counter
from datetime import datetime, timedelta
import psutil
from django.conf import settings
from . import utils

CACHE = {}
RE_FAIL = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+)")
RE_OK = re.compile(r"Accepted (\w+) for (\S+) from (\S+)")
RE_NGX = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (\S+) "[^"]*" "([^"]*)"')
SUSP = re.compile(r"(\.env|\.git/|wp-login|wp-admin|xmlrpc|phpmyadmin|/etc/passwd|\.\./|cgi-bin|phpunit|eval\(|union(\s|%20|\+)+select|<script|/actuator|/boaform|\.aws|/config\.json)", re.I)


def tail(path, max_bytes=6_000_000):
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            f.seek(max(0, size - max_bytes))
            return f.read().decode(errors="replace").splitlines()
    except OSError:
        return None


def _t_auth(line, now):
    try:
        if line[:4].isdigit():
            return datetime.fromisoformat(line.split()[0]).astimezone().replace(tzinfo=None)
        d = datetime.strptime(line[:15], "%b %d %H:%M:%S").replace(year=now.year)
        return d.replace(year=now.year - 1) if d > now + timedelta(days=1) else d
    except ValueError:
        return None


def _series(counter, now):
    return [{"h": (now - timedelta(hours=i)).strftime("%H:00"), "n": counter[(now - timedelta(hours=i)).strftime("%Y-%m-%d %H")]} for i in range(23, -1, -1)]


def analyze_auth():
    lines = tail(settings.HM_AUTH_LOG)
    if lines is None:
        return {"available": False, "path": settings.HM_AUTH_LOG, "ips": {}}
    now = datetime.now()
    since = now - timedelta(hours=24)
    ips, users, hourly, logins, f10 = {}, Counter(), Counter(), [], 0
    for line in lines:
        if "sshd" not in line:
            continue
        t = _t_auth(line, now)
        if not t or t < since:
            continue
        m = RE_FAIL.search(line)
        if m:
            u, ip = m.groups()
            d = ips.setdefault(ip, {"n": 0, "users": Counter(), "last": t})
            d["n"] += 1; d["users"][u] += 1; d["last"] = max(d["last"], t)
            users[u] += 1; hourly[t.strftime("%Y-%m-%d %H")] += 1
            f10 += t >= now - timedelta(minutes=10)
            continue
        m = RE_OK.search(line)
        if m:
            logins.append({"method": m.group(1), "user": m.group(2), "ip": m.group(3), "time": t.strftime("%d %b %H:%M")})
    return {"available": True, "failed": sum(d["n"] for d in ips.values()), "failed_10m": f10, "ips": ips,
            "users": users.most_common(10), "hourly": _series(hourly, now), "logins": logins[-12:][::-1]}


def analyze_nginx():
    lines = tail(settings.HM_NGINX_LOG)
    if lines is None:
        return {"available": False, "path": settings.HM_NGINX_LOG, "ips": {}}
    now = datetime.now()
    since = now - timedelta(hours=24)
    classes, ips, hourly, paths, total = Counter(), {}, Counter(), Counter(), 0
    for line in lines:
        m = RE_NGX.match(line)
        if not m:
            continue
        ip, ts, method, path, code, _, ua = m.groups()
        try:
            t = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z").astimezone().replace(tzinfo=None)
        except ValueError:
            continue
        if t < since:
            continue
        total += 1
        classes[code[0] + "xx"] += 1
        hourly[t.strftime("%Y-%m-%d %H")] += 1
        d = ips.setdefault(ip, {"n": 0, "susp": 0, "e404": 0, "last": t})
        d["n"] += 1; d["last"] = max(d["last"], t)
        d["e404"] += code == "404"
        if SUSP.search(path) or SUSP.search(ua):
            d["susp"] += 1
            paths[path[:100]] += 1
    top = sorted(ips.items(), key=lambda kv: (-kv[1]["susp"], -kv[1]["n"]))[:10]
    return {"available": True, "total": total, "classes": dict(classes), "hourly": _series(hourly, now), "ips": ips,
            "top_paths": paths.most_common(8), "top_ips": [{"ip": k, "n": v["n"], "susp": v["susp"], "e404": v["e404"]} for k, v in top]}


def ufw_rules():
    rc, out = utils.run(["ufw", "status"], priv=True)
    active = rc == 0 and "Status: active" in out
    ips = []
    for line in out.splitlines():
        m = re.search(r"DENY(?:\s+IN)?\s+([0-9a-fA-F:.]+)(?:\s+#.*)?\s*$", line.strip())
        if m:
            try:
                ipaddress.ip_address(m.group(1)); ips.append(m.group(1))
            except ValueError:
                pass
    return active, ips


def is_blockable(ip):
    try:
        return ipaddress.ip_address(ip).is_global and ip not in settings.HM_NEVER_BLOCK
    except ValueError:
        return False


def protected_ips(request_ip=None):
    s = set(settings.HM_NEVER_BLOCK)
    if request_ip:
        s.add(request_ip)
    s |= {u.host for u in psutil.users() if u.host}
    return s


def overview():
    hit = CACHE.get("o")
    if hit and time.time() - hit[0] < 20:
        return hit[1]
    a, n, f2b = analyze_auth(), analyze_nginx(), utils.fail2ban()
    ufw_active, ufw_ips = ufw_rules()
    blocked = [{"ip": ip, "source": "ufw"} for ip in ufw_ips]
    for j in f2b.get("jails", []):
        blocked += [{"ip": ip, "source": "fail2ban:" + j["name"]} for ip in j["ips"]]
    bset = {b["ip"] for b in blocked}
    th = {}
    T = lambda ip: th.setdefault(ip, {"ip": ip, "ssh": 0, "web": 0, "e404": 0, "users": [], "last": None})
    for ip, d in a["ips"].items():
        t = T(ip); t["ssh"] = d["n"]; t["users"] = [u for u, _ in d["users"].most_common(3)]; t["last"] = d["last"]
    for ip, d in n["ips"].items():
        if d["susp"] or d["e404"] >= 15:
            t = T(ip); t["web"] = d["susp"]; t["e404"] = d["e404"]
            t["last"] = max(x for x in (t["last"], d["last"]) if x)
    threats = []
    for t in th.values():
        score = t["ssh"] + t["web"] * 2 + t["e404"] // 5
        if score < 5:
            continue
        why = ([f'{t["ssh"]} failed SSH logins'] if t["ssh"] else []) + ([f'{t["web"]} scanner requests'] if t["web"] else []) + ([f'{t["e404"]} not-found hits'] if t["e404"] >= 15 else [])
        threats.append({"ip": t["ip"], "ssh": t["ssh"], "web": t["web"], "score": score, "users": t["users"], "reasons": why,
                        "level": "high" if score >= 30 else "medium" if score >= 10 else "low",
                        "banned": t["ip"] in bset, "last": t["last"].strftime("%d %b %H:%M") if t["last"] else ""})
    threats.sort(key=lambda x: -x["score"])
    open_high = [t for t in threats if t["level"] == "high" and not t["banned"]]
    f10 = a.get("failed_10m", 0)
    if f10 >= 20:
        status, msg = "attack", f"SSH brute force in progress: {f10} failed logins in the last 10 minutes."
    elif open_high:
        status, msg = "elevated", f"{len(open_high)} high-risk IP address(es) are not blocked."
    else:
        status, msg = "quiet", "No active attack detected."
    res = {"status": status, "message": msg, "ufw_active": ufw_active, "blocked": blocked, "threats": threats[:30],
           "ssh": {**{k: v for k, v in a.items() if k != "ips"}, "unique_ips": len(a["ips"])},
           "web": {k: v for k, v in n.items() if k != "ips"}}
    CACHE["o"] = (time.time(), res)
    return res


def ban(ip, protected=()):
    try:
        ip = str(ipaddress.ip_address((ip or "").strip()))
    except ValueError:
        return {"ok": False, "error": "Invalid IP address"}
    if not is_blockable(ip):
        return {"ok": False, "error": "Only public IPs can be blocked (private and whitelisted IPs are protected)."}
    if ip in protected:
        return {"ok": False, "error": "This is your own IP or a logged-in session. It is protected."}
    active, ips = ufw_rules()
    if ip in ips:
        return {"ok": True, "message": "Already blocked"}
    if active:
        rc, out = utils.run(["ufw", "insert", "1", "deny", "from", ip, "to", "any", "comment", "hardmetrics"], priv=True)
        if rc != 0:
            rc, out = utils.run(["ufw", "deny", "from", ip, "to", "any", "comment", "hardmetrics"], priv=True)
    else:
        rc, out = utils.run(["fail2ban-client", "set", "sshd", "banip", ip], priv=True)
    CACHE.clear()
    return {"ok": rc == 0, "message": f"{ip} blocked", "error": "" if rc == 0 else out[:300]}


def unban(ip):
    try:
        ip = str(ipaddress.ip_address((ip or "").strip()))
    except ValueError:
        return {"ok": False, "error": "Invalid IP address"}
    done = utils.run(["ufw", "--force", "delete", "deny", "from", ip, "to", "any"], priv=True)[0] == 0
    for j in utils.fail2ban().get("jails", []):
        done |= utils.run(["fail2ban-client", "set", j["name"], "unbanip", ip], priv=True)[0] == 0
    CACHE.clear()
    return {"ok": done, "message": f"{ip} unblocked", "error": "" if done else "No block found for this IP"}
