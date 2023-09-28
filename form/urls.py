from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.registration, name='registration'),
    path('success/', views.success, name='success'),
    path('logout/',views.logout,name='logout'),
    #SuperUser URLs
    path('superuser/login/',views.superuser_login,name='superuser_login'),
    path('superuser/dashboard/',views.superuser_dashboard,name='superuser_dashboard'),
    path('superuser/add_coordinator/',views.add_coordinator,name='add_coordinator'),
    path('superuser/send_invite/',views.send_invite,name='send_invite'),
    path('superuser/invite_success/',views.send_invitations,name='invite_success'),
    path('superuser/view_coordinators/',views.view_coordinators,name='view_coordinators'),
    path('superuser/edit_coordinator/<int:coordinator_id>',views.edit_coordinator,name='edit_coordinator'),
    path('superuser/view_participants/',views.view_participants_super,name='view_participants_super'),
    path('superuser/edit_participant/<int:participant_id>',views.edit_participant_super,name='edit_participant_super'),
    #Coordinator URLs
    path('setup/<str:uidb64>/<str:token>/', views.setup_coordinator_account, name='setup_coordinator_account'),
    path('invalid_activation_link/', views.invalid_activation_link, name='invalid_activation_link'),
    path('coordinator/login/',views.coordinator_login,name='coordinator_login'),
    path('coordinator/dashboard/',views.coordinator_dashboard,name='coordinator_dashboard'),
    path('coordinator/view_participants/', views.view_participants_coordinator, name='view_participants_coordinator'),
    path('coordinator/edit_participant/<int:participant_id>', views.edit_participant_coordinator, name='edit_participant_coordinator'),
]
