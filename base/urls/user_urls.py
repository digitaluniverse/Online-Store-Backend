from django.contrib import admin
from django.urls import path
from base.views import user_views as views

urlpatterns = [
    path('login/', views.userLoginView.as_view(), name="token"),
    path('profile/', views.getUserProfile, name="users-profile"),
    path('', views.getUsers, name="users"),
    path('register/', views.userRegisterView.as_view(), name="register"),
     path('register/new/', views.newRegisterView.as_view(), name="new-register"),

    path('profile/update/', views.updateUserProfileView.as_view(),
         name="users-profile-update"),
    path('phone/update/', views.updateUserNumber.as_view(),
         name="users-phone-update"),
    path('phone/verify/', views.verifyUserNumber.as_view(),
         name="users-phone-verify"),
    path('email/verify/', views.verifyUserEmail.as_view(),
         name="users-email-verify"),
    path('email/confirm/', views.confirmUserEmail.as_view(),
         name="users-email-confirm"),
    path('profile/reset-password/', views.resetPassword.as_view(),
         name="users-reset-password"),
    path('authy/verify-phone/', views.PhoneVerificationView.as_view(),
         name="authy-verify-phone"),
    path('authy/register-phone/', views.PhoneRegistrationView.as_view(),
         name="authy-register-phone"),
    path('authy/token/', views.CustomTokenObtainPairView.as_view(),
        name="authy-token"),
    path('authy/verify/', views.AuthyTokenVerifyView.as_view(),
    name="authy-verify"),
        path('authy/login/', views.AuthyLogin.as_view(),
    name="authy-login"),
    path('test/token/', views.testToken.as_view(),
    name="test-token"),
    
]
