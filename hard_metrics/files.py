"""Read-only file browser limited to HM_FILE_ROOTS. Secrets are masked."""
import os, re, stat
from datetime import datetime
from django.conf import settings

DENY = re.compile(r"(^|/)(id_(rsa|dsa|ecdsa|ed25519)[^/]*|shadow-?|gshadow-?|[^/]*\.(pem|key|p12|pfx|kdbx))$", re.I)
SECRET_FILE = re.compile(r"(^|/)(\.env[^/]*|[^/]*\.env|secrets?\.[a-z]+|credentials[^/]*)$", re.I)
SECRET_KEY = re.compile(r"(PASS|SECRET|TOKEN|KEY|PWD|CREDENTIAL|DSN|AUTH)", re.I)


def roots():
    return [os.path.realpath(r) for r in settings.HM_FILE_ROOTS if os.path.isdir(r)]


def safe_path(p):
    rp = os.path.realpath(p)
    for r in roots():
        if rp == r or rp.startswith(r + os.sep):
            return rp
    raise PermissionError("Path is outside the allowed folders")


def listing(path=""):
    if not path:
        return {"path": "", "parent": None, "entries": [{"name": r, "path": r, "dir": True, "size": 0, "mtime": "", "mode": ""} for r in roots()]}
    rp = safe_path(path)
    if not os.path.isdir(rp):
        raise NotADirectoryError("Not a folder")
    out = []
    for e in sorted(os.scandir(rp), key=lambda x: (not x.is_dir(follow_symlinks=False), x.name.lower()))[:1000]:
        try:
            st = e.stat(follow_symlinks=False)
            out.append({"name": e.name, "path": os.path.join(rp, e.name), "dir": e.is_dir(follow_symlinks=False),
                        "link": e.is_symlink(), "size": st.st_size, "mode": oct(stat.S_IMODE(st.st_mode))[2:],
                        "mtime": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")})
        except OSError:
            continue
    parent = "" if rp in roots() else os.path.dirname(rp)
    return {"path": rp, "parent": parent, "entries": out}


def read_file(path):
    rp = safe_path(path)
    if not os.path.isfile(rp):
        raise FileNotFoundError("Not a file")
    if DENY.search(rp):
        raise PermissionError("Viewing private keys and password files is blocked")
    size = os.path.getsize(rp)
    with open(rp, "rb") as f:
        raw = f.read(settings.HM_FILE_MAX_VIEW)
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
    return {"name": os.path.basename(rp), "size": size, "truncated": size > len(raw), "masked": masked, "binary": False, "text": text}
