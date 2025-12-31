from django.urls import path
from . import views

urlpatterns = [
    path("orgs/", views.my_orgs_view, name="my_orgs"),
    path("orgs/create/", views.create_org_view, name="create_org"),
]