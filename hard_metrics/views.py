from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.http import require_GET, require_POST

from . import utils


@login_required
def dashboard(request):
    return render(request, "hard_metrics/dashboard.html", {
        "actions_enabled": settings.HM_ENABLE_DOCKER_ACTIONS and request.user.is_staff,
        "hostname": utils.hostname(),
    })


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
    return JsonResponse(utils.container_action(name, action))
