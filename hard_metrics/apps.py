import os, sys
from django.apps import AppConfig


class HardMetricsConfig(AppConfig):
    name = "hard_metrics"

    def ready(self):
        from . import signals  # noqa: F401  (login audit)
        skip = ("migrate", "makemigrations", "collectstatic", "check", "createsuperuser", "test", "shell")
        if any(a in sys.argv for a in skip):
            return
        if "runserver" in sys.argv and os.environ.get("RUN_MAIN") != "true":
            return
        from . import utils
        utils.start_sampler()
