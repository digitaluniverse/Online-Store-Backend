from django.contrib import admin
from django.urls import path
from base.views import user_views as views

urlpatterns = [

    path('login/', views.CustomTokenView.as_view(), name="token"),
    path('profile/', views.getUserProfile, name="users-profile"),
    path('', views.getUsers, name="users"),
    path('register/', views.CustomRegisterTokenView.as_view(), name="register"),
    path('profile/update/', views.updateUserProfileView.as_view(), name="users-profile-update"),

]
