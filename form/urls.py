from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.registration, name='registration'),
    path('register/email-validate/', views.EmailValidation.as_view(), name="email-validate"),
    path('register/mobile-validate/', views.MobileValidation.as_view(), name="mobile-validate"),
    path('register/team-name-validate/', views.TeamNameValidation.as_view(), name='team-name-validate'),
    path('success/', views.success, name='success'),
    path('logout/',views.logout,name='logout'),
    #SuperUser URLs
    path('superuser/login/',views.superuser_login,name='superuser_login'),
    path('superuser/dashboard/',views.superuser_dashboard,name='superuser_dashboard'),
    path('superuser/dashboard/email-validate/', views.SuperUserEmailValidation.as_view(),name='superuser_email_validate_dashboard'),
    path('superuser/add_coordinator/',views.add_coordinator,name='add_coordinator'),
    path('superuser/dashboard/add_coordinator/', views.add_coordinator, name='add_coordinator'),
    path('superuser/send_invite/',views.send_invite,name='send_invite'),
    path('superuser/invite_success/',views.send_invitations,name='invite_success'),
    path('superuser/view_coordinators/',views.view_coordinators,name='view_coordinators'),
    path('superuser/edit_coordinator/<int:coordinator_id>',views.edit_coordinator,name='edit_coordinator'),
    path('superuser/view_participants/',views.view_participants_super,name='view_participants_super'),
    path('superuser/edit_participant/<int:participant_id>',views.edit_participant_super,name='edit_participant_super'),
    path('superuser/delete_coordinator/<int:coordinator_id>',views.delete_coordinator_super,name='delete_coordinator_super'),
    path('superuser/add_coordinator/email-validate',views.SuperUserEmailValidation.as_view(),name='superuser_email_validate'),
    path('superuser/view_coordinator_session/', views.super_coordinator_session,name='super_session'),
    path('superuser/edit_coordinator_session/<int:coordinator_id>', views.edit_coordinator_session, name='edit_coordinator_session'),

    #Coordinator URLs
    path('setup/<str:uidb64>/<str:token>/', views.link_coordinator_validation, name='link_coordinator_validation'),
    path('coordinator/',views.setup_coordinator_account,name='setup_coordinator_account'),
    path('coordinator/mobile-validate/',views.CoordinatorMobileValidation.as_view(),name='coordinator_mobile_validate'),
    path('coordinator/username-validate/', views.CoordinatorUsernameValidation.as_view(),name='coordinator_username_validate'),
    path('coordinator/aadhar-validate/', views.CoordinatorAadharValidation.as_view(),name='coordinator_aadhar_validate'),
    path('invalid_activation_link/', views.invalid_activation_link, name='invalid_activation_link'),
    path('coordinator/login/',views.coordinator_login,name='coordinator_login'),
    path('coordinator/dashboard/',views.coordinator_dashboard,name='coordinator_dashboard'),
    path('coordinator/view_participants/', views.view_participants_coordinator, name='view_participants_coordinator'),
    path('coordinator/edit_participant/<str:encoded_id>', views.edit_participant_coordinator, name='edit_participant_coordinator'),
    path('coordinator/checkin/',views.part_check_in,name='part_checkin'),
    path('coordinator/checkin_list/', views.part_check_in_success, name='part_checkin_success'),
    path('verify_otp/<str:encoded_id>/', views.verify_otp, name='verify_otp'),
]
