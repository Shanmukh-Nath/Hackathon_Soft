from django.urls import include, path
from rest_framework import routers
from form.api import views

urlpatterns = [
    path('', views.getRoutes),
    path('participants/', views.getParticipants),
    path('participant/<int:pk>/', views.getParticipants_withid),
]