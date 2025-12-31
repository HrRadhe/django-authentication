from django.urls import path
from . import views

urlpatterns = [
    path("orgs/", views.my_orgs_view, name="my_orgs"),
    path("orgs/create/", views.create_org_view, name="create_org"),
    
    path("orgs/<slug:slug>/members/", views.list_members_view),
    path("orgs/<slug:slug>/members/invite/", views.invite_member_view),
    path("orgs/<slug:slug>/members/<uuid:member_id>/role/", views.change_member_role_view),
    path("orgs/<slug:slug>/members/<uuid:member_id>/remove/", views.remove_member_view),
]