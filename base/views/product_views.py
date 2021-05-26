from django.core.exceptions import ValidationError
from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status as statuscode
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from rest_framework.response import Response
from base import models
from base import serializers
import json

@api_view(['Get'])
# @permission_classes([IsAuthenticated])
def getProducts(request):
    products = models.Product.objects.all()
    serializer = serializers.ProductSerializer(products, many=True)
    return Response(serializer.data)


@api_view(['Get'])
def getProduct(request, product_id):
    product = models.Product.objects.get(_id=product_id)
    serializer = serializers.ProductSerializer(product, many=False)
    return Response(serializer.data)
