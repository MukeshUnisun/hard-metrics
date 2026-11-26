"""Read-only database explorer (PostgreSQL / MySQL on host or in Docker). Only fixed SELECTs are run."""
import csv, io, os, re, shutil
from . import utils

IDENT = re.compile(r"^[A-Za-z0-9_$\-]{1,100}$")
SENS = re.compile(r"(pass|pwd|secret|token|hash|salt|api_?key|otp|cvv|card|aadhaar)", re.I)
DBLIKE = ("postgres", "postgis", "mysql", "mariadb")


def targets():
    t = []
    if shutil.which("psql"):
        t.append({"id": "host:pg", "label": "Host PostgreSQL"})
    if shutil.which("mysql"):
        t.append({"id": "host:my", "label": "Host MySQL"})
    try:
        for c in utils._client().containers.list():
            img = (c.attrs.get("Config", {}).get("Image") or "").lower()
            if any(k in img for k in DBLIKE):
                t.append({"id": "docker:" + c.name, "label": f"Docker: {c.name} ({img})"})
    except Exception:
        pass
    return t


def _kind(target):
    k, _, n = target.partition(":")
    if k == "host" and n in ("pg", "my"):
        return n
    if k == "docker" and n:
        img = (utils._client().containers.get(n).attrs["Config"]["Image"] or "").lower()
        if not any(x in img for x in DBLIKE):
            raise ValueError("Not a database container")
        return "pg" if ("postgres" in img or "postgis" in img) else "my"
    raise ValueError("Unknown target")


def _run(target, kind, db, sql):
    k, _, n = target.partition(":")
    if k == "host":
        if kind == "pg":
            cmd = ["psql", "-X", "--csv", "-d", db or "postgres", "-c", sql]
            cmd = (["runuser", "-u", "postgres", "--"] if os.geteuid() == 0 else ["sudo", "-n", "-u", "postgres"]) + cmd
        else:
            cmd = ["mysql", "-B"] + (["-D", db] if db else []) + ["-e", sql]
        rc, out = utils.run(cmd, timeout=25)
        return rc == 0, out
    c = utils._client().containers.get(n)
    env = dict(e.split("=", 1) for e in c.attrs["Config"].get("Env", []) if "=" in e)
    if kind == "pg":
        user = env.get("POSTGRES_USER", "postgres")
        cmds = [["psql", "-X", "--csv", "-U", user, "-d", db or "postgres", "-c", sql]]
        envp = {"PGPASSWORD": env.get("POSTGRES_PASSWORD", "")}
    else:
        pw = env.get("MYSQL_ROOT_PASSWORD") or env.get("MARIADB_ROOT_PASSWORD") or ""
        base = ["-B", "-uroot"] + (["-D", db] if db else []) + ["-e", sql]
        cmds = [["mysql"] + base, ["mariadb"] + base]
        envp = {"MYSQL_PWD": pw}
    for cmd in cmds:
        r = c.exec_run(cmd, environment=envp, demux=True)
        o, e = r.output if r.output else (b"", b"")
        if r.exit_code in (126, 127):
            continue
        return r.exit_code == 0, ((o or b"") if r.exit_code == 0 else (e or b"")).decode(errors="replace")
    return False, "Database client not found inside the container"


def _rows(out, kind):
    r = list(csv.reader(io.StringIO(out))) if kind == "pg" else [l.split("\t") for l in out.splitlines()]
    return (r[0], r[1:]) if r else ([], [])


def _int(v):
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return 0


def _go(target, db, pg_sql, my_sql):
    try:
        kind = _kind(target)
        ok, out = _run(target, kind, db, pg_sql if kind == "pg" else my_sql)
        if not ok:
            return {"ok": False, "error": out.strip()[:400]}, kind
        return {"ok": True, "cols": _rows(out, kind)[0], "rows": _rows(out, kind)[1]}, kind
    except Exception as e:
        return {"ok": False, "error": str(e)[:400]}, ""


def databases(target):
    r, _ = _go(target, "",
               "SELECT datname, pg_database_size(datname) FROM pg_database WHERE NOT datistemplate ORDER BY 2 DESC",
               "SELECT table_schema, COALESCE(SUM(data_length+index_length),0) FROM information_schema.tables WHERE table_schema NOT IN ('information_schema','performance_schema','mysql','sys') GROUP BY table_schema ORDER BY 2 DESC")
    if r["ok"]:
        r = {"ok": True, "databases": [{"name": x[0], "size": _int(x[1])} for x in r["rows"] if len(x) > 1]}
    return r


def tables(target, db):
    if not IDENT.match(db or ""):
        return {"ok": False, "error": "Invalid database name"}
    r, _ = _go(target, db,
               "SELECT schemaname, relname, n_live_tup, pg_total_relation_size(relid) FROM pg_stat_user_tables ORDER BY 4 DESC",
               f"SELECT table_schema, table_name, COALESCE(table_rows,0), COALESCE(data_length+index_length,0) FROM information_schema.tables WHERE table_schema='{db}' ORDER BY 4 DESC")
    if r["ok"]:
        r = {"ok": True, "tables": [{"schema": x[0], "name": x[1], "rows": _int(x[2]), "size": _int(x[3])} for x in r["rows"] if len(x) > 3]}
    return r


def preview(target, db, schema, table, limit=50):
    if not all(IDENT.match(x or "") for x in (db, schema, table)):
        return {"ok": False, "error": "Invalid name"}
    r, _ = _go(target, db, f'SELECT * FROM "{schema}"."{table}" LIMIT {int(limit)}',
               f"SELECT * FROM `{schema}`.`{table}` LIMIT {int(limit)}")
    if r["ok"]:
        bad = {i for i, c in enumerate(r["cols"]) if SENS.search(c)}
        r["rows"] = [[("••••" if i in bad else (v[:200])) for i, v in enumerate(row)] for row in r["rows"]]
        r["masked"] = [r["cols"][i] for i in sorted(bad)]
    return r
