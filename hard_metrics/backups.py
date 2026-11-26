import os, re, time
from datetime import datetime
from django.conf import settings

IGNORE = re.compile(r"^(dpkg|apt|alternatives|passwd|shadow|group|gshadow|subuid|subgid|\.)", re.I)


def wanted(name):
    n = name.lower()
    return n.endswith(tuple(settings.HM_BACKUP_EXTS)) and not IGNORE.match(n)


def _bases():
    return [os.path.realpath(d) for d in settings.HM_BACKUP_DIRS if os.path.isdir(d)]


def list_backups(depth=2):
    out = []
    for base in _bases():
        for dp, dn, fn in os.walk(base):
            if dp[len(base):].count(os.sep) >= depth:
                dn[:] = []
            for f in fn:
                p = os.path.join(dp, f)
                if not wanted(f) or os.path.islink(p):
                    continue
                try:
                    st = os.stat(p)
                except OSError:
                    continue
                out.append({"name": f, "path": p, "dir": dp, "size": st.st_size, "mtime": st.st_mtime,
                            "time": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                            "age_h": round((time.time() - st.st_mtime) / 3600, 1)})
    out.sort(key=lambda x: -x["mtime"])
    return out[:500]


def safe(path):
    rp = os.path.realpath(path)
    if not any(rp.startswith(b + os.sep) for b in _bases()):
        raise PermissionError("Not inside a backup folder")
    if not os.path.isfile(rp) or os.path.islink(path) or not wanted(os.path.basename(rp)):
        raise PermissionError("Not a backup file")
    return rp
