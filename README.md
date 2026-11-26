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
