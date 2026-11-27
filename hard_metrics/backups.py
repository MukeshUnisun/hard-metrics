"""Backup discovery: database dumps, media archives, media folders and other archives."""
import os, re, subprocess, time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from django.conf import settings

IGNORE = re.compile(r"^(dpkg|apt|alternatives|passwd|shadow|group|gshadow|subuid|subgid|\.)", re.I)
MEDIA = re.compile(r"(media|uploads?|assets|images|static|storage|attachments|documents|photos|files)", re.I)
DB_EXT = (".sql", ".sql.gz", ".sql.zip", ".sql.bz2", ".sql.xz", ".dump", ".rdb")
DB_WORD = re.compile(r"(db|database|sql|postgres|mysql|mongo)", re.I)
_size_cache = {}


def wanted(name):
    n = name.lower()
    return n.endswith(tuple(settings.HM_BACKUP_EXTS)) and not IGNORE.match(n)


def kind_of(name):
    n = name.lower()
    if n.endswith(DB_EXT):
        return "database"
    if MEDIA.search(n):
        return "media"
    return "database" if DB_WORD.search(n) else "archive"


def _bases():
    return [os.path.realpath(d) for d in settings.HM_BACKUP_DIRS if os.path.isdir(d)]


def _is_media_dir(path):
    name = os.path.basename(path)
    if name.startswith(".") or not MEDIA.search(name):
        return False
    try:
        names = os.listdir(path)
    except OSError:
        return False
    return bool(names) and not any(wanted(n) for n in names)


def _dir_size(path):
    hit = _size_cache.get(path)
    if hit and time.time() - hit[0] < 600:
        return hit[1]
    try:
        out = subprocess.run(["du", "-sk", path], capture_output=True, text=True, timeout=8).stdout
        size = int(out.split()[0]) * 1024
    except Exception:
        size = None
    _size_cache[path] = (time.time(), size)
    return size


def _item(name, path, parent, size, mtime, kind, is_dir):
    return {"name": name, "path": path, "dir": parent, "size": size, "mtime": mtime, "kind": kind, "is_dir": is_dir,
            "time": datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S"), "age_h": round((time.time() - mtime) / 3600, 1)}


def list_backups(depth=2):
    out = []
    for base in _bases():
        stack = [(base, 0)]
        while stack:
            d, lvl = stack.pop()
            try:
                entries = list(os.scandir(d))
            except OSError:
                continue
            for e in entries:
                try:
                    if e.is_symlink():
                        continue
                    if e.is_file(follow_symlinks=False) and wanted(e.name):
                        st = e.stat()
                        out.append(_item(e.name, e.path, d, st.st_size, st.st_mtime, kind_of(e.name), False))
                    elif e.is_dir(follow_symlinks=False):
                        if _is_media_dir(e.path):
                            out.append(_item(e.name, e.path, d, None, e.stat().st_mtime, "media", True))
                        elif lvl < depth:
                            stack.append((e.path, lvl + 1))
                except OSError:
                    continue
    folders = [i for i in out if i["is_dir"]]
    if folders:
        with ThreadPoolExecutor(4) as ex:
            for i, sz in zip(folders, ex.map(lambda i: _dir_size(i["path"]), folders)):
                i["size"] = sz
    out.sort(key=lambda x: -x["mtime"])
    return out[:600]


def safe(path):
    """Return (realpath, is_dir) if path is a real backup strictly inside a backup folder."""
    if os.path.islink(path):
        raise PermissionError("Links are not allowed")
    rp = os.path.realpath(path)
    if not any(rp.startswith(b + os.sep) for b in _bases()):
        raise PermissionError("Not inside a backup folder")
    if os.path.isfile(rp) and wanted(os.path.basename(rp)):
        return rp, False
    if os.path.isdir(rp) and _is_media_dir(rp):
        return rp, True
    raise PermissionError("Not a backup file or media folder")
