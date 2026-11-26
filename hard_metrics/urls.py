from django.urls import path
from . import views

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("api/metrics/", views.api_metrics),
    path("api/system/", views.api_system),
    path("api/docker/", views.api_docker),
    path("api/docker/<str:name>/logs/", views.api_container_logs),
    path("api/docker/<str:name>/<str:action>/", views.api_container_action),
]
