import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
env = os.environ.get

SECRET_KEY = env("DJANGO_SECRET_KEY", "change-me-in-production")
DEBUG = env("DJANGO_DEBUG", "False") == "True"
ALLOWED_HOSTS = env("DJANGO_ALLOWED_HOSTS", "127.0.0.1,localhost").split(",")
CSRF_TRUSTED_ORIGINS = [o for o in env("DJANGO_CSRF_ORIGINS", "").split(",") if o]

INSTALLED_APPS = [
    "django.contrib.admin", "django.contrib.auth", "django.contrib.contenttypes",
    "django.contrib.sessions", "django.contrib.messages", "django.contrib.staticfiles",
    "hard_metrics.apps.HardMetricsConfig",
]
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]
ROOT_URLCONF = "config.urls"
TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates", "DIRS": [], "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.request",
        "django.contrib.auth.context_processors.auth",
        "django.contrib.messages.context_processors.messages"]},
}]
WSGI_APPLICATION = "config.wsgi.application"
DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": BASE_DIR / "db.sqlite3"}}
USE_TZ = True
TIME_ZONE = env("DJANGO_TZ", "Asia/Kolkata")
STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
LOGIN_URL = "/accounts/login/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/accounts/login/"
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

# ---------------- Hard Metrics configuration ----------------
# (label, "systemd-unit" or "unitA|unitB" fallbacks)
HM_SERVICES = [
    ("Nginx", "nginx"), ("PostgreSQL (5432)", "postgresql"), ("MySQL (3306)", "mysql|mariadb"),
    ("Redis (6379)", "redis-server|redis"), ("PHP-FPM (8.1)", "php8.1-fpm"),
    ("Fail2ban", "fail2ban"), ("UFW Firewall", "ufw"),
]
HM_DISK_PATHS = ["/", "/opt/docker"]
# .env files to audit (glob patterns allowed)
HM_ENV_PATHS = ["/opt/*/.env", "/opt/docker/*/.env", "/root/*.env", "/root/.*.env", str(BASE_DIR / ".env")]
# Backup detection: newest file in these dirs, or a JSON status file written by your backup script:
# {"timestamp": "2026-01-01 02:00:00", "size": 123456, "path": "/backups/x.tar.gz", "status_code": 0}
HM_BACKUP_DIRS = ["/var/backups", "/opt/backups", "/root/backups"]
HM_BACKUP_STATUS_FILE = env("HM_BACKUP_STATUS_FILE", "/var/log/backup_status.json")
HM_BACKUP_MAX_AGE_HOURS = 26
HM_ENABLE_DOCKER_ACTIONS = env("HM_ENABLE_DOCKER_ACTIONS", "False") == "True"  # staff users only
HM_SAMPLE_SECONDS = 5

# ---------------- v2: files, databases, backups, security ----------------
HM_BACKUP_DIRS = [d for d in env("HM_BACKUP_DIRS", "/root/backups,/opt/backups,/opt/docker/backups,/var/backups").split(",") if d]
HM_BACKUP_EXTS = (".sql", ".sql.gz", ".gz", ".tar", ".tgz", ".tar.gz", ".zip", ".dump", ".bak", ".7z", ".bz2", ".xz", ".rdb")
HM_FILE_ROOTS = [d for d in env("HM_FILE_ROOTS", "/opt,/var/www,/srv,/home").split(",") if d]  # file browser is read-only and limited to these
HM_FILE_MAX_VIEW = 512 * 1024
HM_ENABLE_BACKUP_DELETE = env("HM_ENABLE_BACKUP_DELETE", "False") == "True"
HM_ENABLE_IP_BLOCK = env("HM_ENABLE_IP_BLOCK", "False") == "True"
HM_NEVER_BLOCK = [i for i in env("HM_NEVER_BLOCK", "").split(",") if i]  # IPs that can never be blocked
HM_AUTH_LOG = env("HM_AUTH_LOG", "/var/log/auth.log")
HM_NGINX_LOG = env("HM_NGINX_LOG", "/var/log/nginx/access.log")
