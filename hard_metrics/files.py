"""Read-only file browser. Roots come from HM_FILE_ROOTS ("/" = whole server). Secrets are masked."""
import os, re, stat
from datetime import datetime
from django.conf import settings

BLOCKED = ("/proc", "/sys", "/dev")
DENY = re.compile(r"(^|/)(id_(rsa|dsa|ecdsa|ed25519)[^/]*|shadow-?|gshadow-?|ssh_host_[a-z0-9]+_key|\.(pgpass|netrc|git-credentials|my\.cnf|mylogin\.cnf|bash_history|zsh_history|mysql_history|psql_history|rediscli_history)|[^/]*\.(pem|key|p12|pfx|kdbx))$", re.I)
DENY_PATH = re.compile(r"(/\.aws/credentials|/\.docker/config\.json|/etc/ssl/private/|/\.ssh/id_)", re.I)
SECRET_FILE = re.compile(r"(^|/)(\.env[^/]*|[^/]*\.env|secrets?\.[a-z]+|credentials[^/]*)$", re.I)
SECRET_KEY = re.compile(r"(PASS|SECRET|TOKEN|KEY|PWD|CREDENTIAL|DSN|AUTH)", re.I)


def roots():
    return [os.path.realpath(r) for r in settings.HM_FILE_ROOTS if os.path.isdir(r)]


def _blocked(rp):
    return any(rp == b or rp.startswith(b + os.sep) for b in BLOCKED)


def safe_path(p):
    rp = os.path.realpath(p)
    if _blocked(rp):
        raise PermissionError("Virtual system folders (/proc, /sys, /dev) are not browsable")
    for r in roots():
        if r == "/" or rp == r or rp.startswith(r + os.sep):
            return rp
    raise PermissionError("Path is outside the allowed folders")


def listing(path=""):
    rs = roots()
    if not path:
        if len(rs) == 1:
            path = rs[0]
        else:
            return {"path": "", "parent": None, "entries": [{"name": r, "path": r, "dir": True, "size": 0, "mtime": "", "mode": ""} for r in rs]}
    rp = safe_path(path)
    if not os.path.isdir(rp):
        raise NotADirectoryError("Not a folder")
    out = []
    for e in sorted(os.scandir(rp), key=lambda x: (not x.is_dir(follow_symlinks=False), x.name.lower()))[:1500]:
        full = os.path.join(rp, e.name)
        if _blocked(full):
            continue
        try:
            st = e.stat(follow_symlinks=False)
            out.append({"name": e.name, "path": full, "dir": e.is_dir(follow_symlinks=False), "link": e.is_symlink(),
                        "size": st.st_size, "mode": oct(stat.S_IMODE(st.st_mode))[2:],
                        "mtime": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")})
        except OSError:
            continue
    parent = None if (rp in rs and len(rs) == 1) else ("" if rp in rs else os.path.dirname(rp))
    return {"path": rp, "parent": parent, "entries": out}


def read_file(path, tail=False):
    rp = safe_path(path)
    if not os.path.isfile(rp):
        raise FileNotFoundError("Not a file")
    if DENY.search(rp) or DENY_PATH.search(rp):
        raise PermissionError("Private keys, password files and shell histories cannot be opened")
    size, mx = os.path.getsize(rp), settings.HM_FILE_MAX_VIEW
    with open(rp, "rb") as f:
        if tail and size > mx:
            f.seek(size - mx)
            raw = f.read().split(b"\n", 1)[-1]
        else:
            raw = f.read(mx)
    if b"\0" in raw[:4096]:
        return {"name": os.path.basename(rp), "size": size, "binary": True, "text": ""}
    text = raw.decode("utf-8", errors="replace")
    masked = bool(SECRET_FILE.search(rp))
    if masked:
        def mask(line):
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                if SECRET_KEY.search(k) and v.strip():
                    return k + "=••••••••"
            return line
        text = "\n".join(mask(l) for l in text.splitlines())
    return {"name": os.path.basename(rp), "size": size, "truncated": size > mx, "tail": bool(tail and size > mx), "masked": masked, "binary": False, "text": text}
