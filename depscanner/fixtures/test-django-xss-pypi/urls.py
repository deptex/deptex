from django.urls import path
from . import views

urlpatterns = [
    path("msg", views.render_message),
    path("static", views.render_static),
]
