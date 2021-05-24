from django.contrib import admin
from django.urls import path
from . import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('products/', views.getProducts, name="products"),
    path('products/<str:product_id>/', views.getProduct, name="product"),
    path('users/login/', views.CustomTokenView.as_view(), name="token"),
    path('users/profile/', views.getUserProfile, name="user-profile"),
    path('users/', views.getUsers, name="users"),
    # path('users/register/', views.registerUser, name="register"),
    path('users/register/', views.CustomRegisterTokenView.as_view(), name="register"),

]
