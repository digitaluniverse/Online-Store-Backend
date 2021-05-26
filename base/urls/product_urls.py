from django.contrib import admin
from django.urls import path
from base.views import product_views as views

urlpatterns = [
    
    path('', views.getProducts, name="products"),
    path('<str:product_id>/', views.getProduct, name="product"),

]
