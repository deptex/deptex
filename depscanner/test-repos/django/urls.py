from django.urls import path
from . import views
from . import vuln_views

urlpatterns = [
    path("msg", views.render_message),
    path("static", views.render_static),
    # Intentionally vulnerable views (one clean reachable taint flow each).
    path("search", vuln_views.search_users),
    path("ping", vuln_views.ping_host),
    path("run", vuln_views.run_command),
    path("download", vuln_views.download_file),
    path("report", vuln_views.serve_report),
    path("fetch", vuln_views.fetch_url),
    path("avatar", vuln_views.proxy_avatar),
    path("next", vuln_views.go_next),
    path("session", vuln_views.load_session),
    path("config", vuln_views.import_config),
    path("calc", vuln_views.calculate),
    path("logs", vuln_views.filter_logs),
]
