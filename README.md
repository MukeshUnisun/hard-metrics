# Hard Metrics: Django server and Docker monitor

## Quick start
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
export DJANGO_DEBUG=True            # for local testing only
python manage.py migrate
python manage.py createsuperuser    # staff user can run container actions
python manage.py runserver 127.0.0.1:8000
```
Open http://127.0.0.1:8000 and sign in.

## Settings (config/settings.py, bottom section)
HM_SERVICES, HM_DISK_PATHS, HM_ENV_PATHS, HM_BACKUP_DIRS, HM_BACKUP_STATUS_FILE.
Container Start/Stop/Restart/Remove is OFF by default: `export HM_ENABLE_DOCKER_ACTIONS=True` (staff users only).

## Backup status file (optional)
Have your backup script write `/var/log/backup_status.json`:
`{"timestamp":"2026-01-01 02:00:00","size":123456,"path":"/backups/x.tar.gz","status_code":0}`

## Permissions
- Docker: add the service user to the `docker` group.
- Fail2ban needs root. Non-root users call `sudo -n fail2ban-client`; add in `visudo`:
  `hmuser ALL=(root) NOPASSWD: /usr/bin/fail2ban-client status, /usr/bin/fail2ban-client status *`
- `last`, `systemctl is-active`, psutil need no extra rights.

## Production
```bash
export DJANGO_SECRET_KEY=... DJANGO_DEBUG=False DJANGO_ALLOWED_HOSTS=monitor.example.com
gunicorn config.wsgi:application --bind 127.0.0.1:8000 --workers 1 --threads 4
```
Nginx: `location / { proxy_pass http://127.0.0.1:8000; proxy_set_header Host $host; proxy_set_header X-Forwarded-Proto $scheme; auth_basic "Restricted"; auth_basic_user_file /etc/nginx/.htpasswd; }`
Use 1 worker so the 1-hour history sampler lives in one process.

## v2 pages (staff users only)
| Page | What it does |
|---|---|
| Projects | Docker compose projects and their services, open ports (exposed DB ports flagged), nginx domain to project map |
| Files | Read-only browser for HM_FILE_ROOTS (/opt, /var/www, /srv, /home). .env secrets are hidden, private keys blocked |
| Databases | PostgreSQL/MySQL on the host or in Docker: databases, tables, first 50 rows. Read-only, password columns hidden |
| Backups | List, download and (optional) delete backups from HM_BACKUP_DIRS |
| Security | SSH brute force and nginx scanner detection, suspicious IP list, one-click block/unblock |
| Audit log | Logins, failed logins, blocks, deletes, downloads, container actions |

Dangerous actions are OFF by default. Turn on in `hm.env`:
```
HM_ENABLE_DOCKER_ACTIONS=True
HM_ENABLE_BACKUP_DELETE=True
HM_ENABLE_IP_BLOCK=True
HM_NEVER_BLOCK=your.office.ip,your.home.ip
HM_BACKUP_DIRS=/root/backups,/opt/backups
```
Blocking uses UFW (or Fail2ban if UFW is inactive). Your own IP, logged-in session IPs and private IPs can never be blocked.
Docker-published ports bypass UFW, so do not publish DB ports (use `127.0.0.1:5432:5432`).

After updating: `git pull && pip install -r requirements.txt && python manage.py migrate && systemctl restart hardmetrics`
