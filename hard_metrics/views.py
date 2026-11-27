import os, shutil, subprocess
from functools import wraps

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import FileResponse, HttpResponseBadRequest, HttpResponseForbidden, JsonResponse, StreamingHttpResponse
from django.utils.http import content_disposition_header
from django.shortcuts import render
from django.views.decorators.http import require_GET, require_POST

from . import backups, dbs, files, projects, security, storage, utils
from .models import AuditLog


def client_ip(request):
    xf = request.META.get("HTTP_X_FORWARDED_FOR", "")
    return (xf.split(",")[0].strip() if xf else request.META.get("REMOTE_ADDR", ""))[:64]


def audit(request, action, target="", ok=True, detail=""):
    AuditLog.objects.create(user=request.user.get_username(), action=action, target=str(target)[:500],
                            ip=client_ip(request), ok=ok, detail=str(detail)[:500])


def staff_required(view):
    @wraps(view)
    @login_required
    def wrapper(request, *a, **k):
        if not request.user.is_staff:
            return HttpResponseForbidden("Staff access required")
        return view(request, *a, **k)
    return wrapper


# ---------------- overview ----------------
@login_required
def dashboard(request):
    return render(request, "hard_metrics/dashboard.html", {
        "actions_enabled": settings.HM_ENABLE_DOCKER_ACTIONS and request.user.is_staff,
        "hostname": utils.hostname(), "page": "dashboard"})


@login_required
@require_GET
def api_metrics(request):
    return JsonResponse(utils.metrics())


@login_required
@require_GET
def api_system(request):
    return JsonResponse(utils.system_status())


@login_required
@require_GET
def api_docker(request):
    return JsonResponse(utils.docker_containers())


@login_required
@require_GET
def api_container_logs(request, name):
    tail = min(int(request.GET.get("tail", 300) or 300), 2000)
    return JsonResponse(utils.container_logs(name, tail))


@login_required
@require_POST
def api_container_action(request, name, action):
    if not (settings.HM_ENABLE_DOCKER_ACTIONS and request.user.is_staff):
        return JsonResponse({"ok": False, "error": "Container actions are disabled or need a staff user."}, status=403)
    res = utils.container_action(name, action)
    audit(request, "container_" + action, name, res.get("ok", False), res.get("error", ""))
    return JsonResponse(res)


# ---------------- pages ----------------
def _page(template, page, **extra):
    @staff_required
    def view(request):
        return render(request, f"hard_metrics/{template}.html", {"page": page, **extra})
    return view


projects_page = _page("projects", "projects")
files_page = _page("files", "files")
databases_page = _page("databases", "databases")


@staff_required
def backups_page(request):
    return render(request, "hard_metrics/backups.html", {"page": "backups", "can_delete": settings.HM_ENABLE_BACKUP_DELETE})


@staff_required
def security_page(request):
    return render(request, "hard_metrics/security.html", {"page": "security", "can_block": settings.HM_ENABLE_IP_BLOCK})


@staff_required
def audit_page(request):
    return render(request, "hard_metrics/audit.html", {"page": "audit", "logs": AuditLog.objects.all()[:300]})


# ---------------- projects / files / databases ----------------
@staff_required
@require_GET
def api_projects(request):
    return JsonResponse(projects.overview())


@staff_required
@require_GET
def api_files(request):
    try:
        return JsonResponse(files.listing(request.GET.get("path", "")))
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)


@staff_required
@require_GET
def api_file_read(request):
    try:
        return JsonResponse(files.read_file(request.GET.get("path", ""), request.GET.get("tail") == "1"))
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)


@staff_required
@require_GET
def api_db_targets(request):
    return JsonResponse({"targets": dbs.targets()})


@staff_required
@require_GET
def api_db_databases(request):
    return JsonResponse(dbs.databases(request.GET.get("target", "")))


@staff_required
@require_GET
def api_db_tables(request):
    return JsonResponse(dbs.tables(request.GET.get("target", ""), request.GET.get("db", "")))


@staff_required
@require_GET
def api_db_preview(request):
    g = request.GET
    res = dbs.preview(g.get("target", ""), g.get("db", ""), g.get("schema", ""), g.get("table", ""))
    audit(request, "db_preview", f'{g.get("target")}/{g.get("db")}/{g.get("schema")}.{g.get("table")}', res.get("ok", False))
    return JsonResponse(res)


# ---------------- backups ----------------
@staff_required
@require_GET
def api_backups(request):
    items = backups.list_backups()
    return JsonResponse({"backups": items, "dirs": settings.HM_BACKUP_DIRS, "can_delete": settings.HM_ENABLE_BACKUP_DELETE})


def _tar_stream(p):
    proc = subprocess.Popen(["tar", "-czf", "-", "-C", os.path.dirname(p), os.path.basename(p)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        while True:
            chunk = proc.stdout.read(1 << 20)
            if not chunk:
                break
            yield chunk
    finally:
        proc.stdout.close()
        if proc.poll() is None:
            proc.kill()
        proc.wait()


@staff_required
@require_GET
def api_backup_download(request):
    try:
        p, is_dir = backups.safe(request.GET.get("path", ""))
    except Exception as e:
        return HttpResponseBadRequest(str(e))
    audit(request, "backup_download", p)
    if is_dir:
        r = StreamingHttpResponse(_tar_stream(p), content_type="application/gzip")
        r["Content-Disposition"] = content_disposition_header(True, os.path.basename(p) + ".tar.gz")
        return r
    return FileResponse(open(p, "rb"), as_attachment=True, filename=os.path.basename(p))


@staff_required
@require_POST
def api_backup_delete(request):
    if not settings.HM_ENABLE_BACKUP_DELETE:
        return JsonResponse({"ok": False, "error": "Backup delete is disabled (set HM_ENABLE_BACKUP_DELETE=True)."}, status=403)
    try:
        p, is_dir = backups.safe(request.POST.get("path", ""))
        shutil.rmtree(p) if is_dir else os.remove(p)
        audit(request, "backup_delete", p)
        return JsonResponse({"ok": True})
    except Exception as e:
        audit(request, "backup_delete", request.POST.get("path", ""), False, e)
        return JsonResponse({"ok": False, "error": str(e)}, status=400)


# ---------------- storage ----------------
storage_page = _page("storage", "storage")


def _force(request):
    return request.GET.get("force") == "1"


@staff_required
@require_GET
def api_storage_top(request):
    return JsonResponse(storage.top(_force(request)))


@staff_required
@require_GET
def api_storage_scan(request):
    try:
        return JsonResponse(storage.scan(request.GET.get("path", "/"), _force(request)))
    except Exception as e:
        return JsonResponse({"state": "error", "error": str(e), "result": None}, status=400)


@staff_required
@require_GET
def api_storage_big(request):
    try:
        return JsonResponse(storage.big(request.GET.get("path", "/"), _force(request)))
    except Exception as e:
        return JsonResponse({"state": "error", "error": str(e), "result": None}, status=400)


@staff_required
@require_GET
def api_storage_docker(request):
    return JsonResponse(storage.docker_usage(_force(request)))


# ---------------- security ----------------
@staff_required
@require_GET
def api_security(request):
    d = dict(security.overview())
    prot = security.protected_ips(client_ip(request))
    d["threats"] = [{**t, "protected": t["ip"] in prot or not security.is_blockable(t["ip"])} for t in d["threats"]]
    d["can_block"] = settings.HM_ENABLE_IP_BLOCK
    return JsonResponse(d)


@staff_required
@require_POST
def api_ban(request):
    if not settings.HM_ENABLE_IP_BLOCK:
        return JsonResponse({"ok": False, "error": "IP blocking is disabled (set HM_ENABLE_IP_BLOCK=True)."}, status=403)
    ip = request.POST.get("ip", "")
    res = security.ban(ip, security.protected_ips(client_ip(request)))
    audit(request, "ip_block", ip, res.get("ok", False), res.get("error", ""))
    return JsonResponse(res)


@staff_required
@require_POST
def api_unban(request):
    if not settings.HM_ENABLE_IP_BLOCK:
        return JsonResponse({"ok": False, "error": "IP blocking is disabled (set HM_ENABLE_IP_BLOCK=True)."}, status=403)
    ip = request.POST.get("ip", "")
    res = security.unban(ip)
    audit(request, "ip_unblock", ip, res.get("ok", False), res.get("error", ""))
    return JsonResponse(res)
