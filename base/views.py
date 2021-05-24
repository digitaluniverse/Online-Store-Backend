from django.shortcuts import render
from django.db.models import query
from django.http import JsonResponse
from rest_framework import generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from oauth2_provider.settings import oauth2_settings
from braces.views import CsrfExemptMixin
from oauth2_provider.views.mixins import OAuthLibMixin


import json
from rest_framework.response import Response
from drf_social_oauth2.views import TokenView
from oauth2_provider.models import get_access_token_model, get_application_model
from oauth2_provider.signals import app_authorized

from django.http import HttpResponse
from django.views.generic import View
from django.views.decorators.debug import sensitive_post_parameters
from django.utils.translation import gettext_lazy as _
from django.db import transaction

from .products import products
from . import models
from . import serializers


@api_view(['Get'])
def getProducts(request):
    products = models.Product.objects.all()
    serializer = serializers.ProductSerializer(products, many=True)
    return Response(serializer.data)


@api_view(['Get'])
def getProduct(request, product_id):
    product = models.Product.objects.get(_id=product_id)
    serializer = serializers.ProductSerializer(product, many=False)
    return Response(serializer.data)


# class Products(APIView):
    serializer_class = serializers.ProductSerializer
    queryset = models.Product.objects.all()

    def get_queryset(self, product_id):
        return self.queryset

    def get(self, request):
        queryset = models.Product.objects.all()
        serializer = serializers.ProductSerializer(queryset, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, format=None):
        serializer = serializers.ProductSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# class Product(APIView):
    serializer_class = serializers.ProductSerializer
    queryset = models.Product.objects.all()

    def get_object(self, product_id):
        try:
            product = models.Product.objects.get(_id=product_id)
            return product
        except Product.DoesNotExist:
            raise Http404

    def get(self, request, product_id, format=None):
        product = self.get_object(product_id)
        serializer = serializers.ProductSerializer(product, many=False)
        return Response(serializer.data)

    def put(self, request, product_id):
        data = request.data
        product = self.get_object(product_id)
        product.name = data['name']
        product.price = data['price']
        product.brand = data['brand']
        product.countInStock = data['countInStock']
        product.category = data['category']
        product.description = data['description']

        product.save()

        serializer = serializers.ProductSerializer(product, many=False)
        return Response(serializer.data)


@api_view(['Get'])
@permission_classes([IsAuthenticated])
def getUserProfile(request):
    user = request.user
    serializer = serializers.UserSerializer(user, many=False)
    return Response(serializer.data)


@api_view(['Get'])
@permission_classes([IsAdminUser])
def getUsers(request):
    users = models.User.objects.all()
    serializer = serializers.UserSerializer(users, many=True)
    return Response(serializer.data)


@api_view(['Post'])
def registerUser(request):
    data = request.data
    user = models.User.objects.create(
        first_name=data['name'],
        username=data['email'],
        email=data['email'],
        password=make_password(data['password'])
    )
    serializer = serializers.UserSerializer(user, many=False)
    return Response(serializer.data)


# class UserRegister(CsrfExemptMixin, OAuthLibMixin, APIView):
#     permission_classes = (permissions.AllowAny,)

#     server_class = oauth2_settings.OAUTH2_SERVER_CLASS
#     validator_class = oauth2_settings.OAUTH2_VALIDATOR_CLASS
#     oauthlib_backend_class = oauth2_settings.OAUTH2_BACKEND_CLASS

#     def post(self, request):
#         if request.auth is None:
#             data = request.data


#             serializer = serializers.RegisterSerializer(data=data)
#             user = models.User.objects.create(
#                 first_name=data['name'],
#                 username=data['email'],
#                 email=data['email'],
#                 password=make_password(data['password'])
#             )
#             if serializer.is_valid():
#                 try:
#                     with transaction.atomic():

#                         user = serializer.save()

#                         url, headers, body, token_status = self.create_token_response(
#                             request)
#                         if token_status != 200:
#                             raise Exception(json.loads(body).get(
#                                 "error_description", ""))

#                         return Response(json.loads(body), status=token_status)
#                 except Exception as e:
#                     return Response(data={"error": e.message}, status=status.HTTP_400_BAD_REQUEST)
#             return Response(data=serializer.errors, status=status.HTTP_400_BAD_REQUEST)
#         return Response(status=status.HTTP_403_FORBIDDEN)


class CustomRegisterTokenView(TokenView):
    def post(self, request, *args, **kwargs):
        # Use the rest framework `.data` to fake the post body of the django request.
        mutable_data = request.data.copy()
        request._request.POST = request._request.POST.copy()
        data = mutable_data
        email = data['email']
        print(email)
        user = models.User.objects.filter(username=email)
        print(user)
        # user = models.User.objects.create(
        #     first_name=data['name'],
        #     username=data['email'],
        #     email=data['email'],
        #     password=make_password(data['password'])
        # )                                 
        if len(user)>0:
            for key, value in mutable_data.items():
                request._request.POST[key] = value 
            url, headers, body, status = self.create_token_response(
                request._request)
            if status == 200:
                body = json.loads(body)
                access_token = body.get("access_token")
                if access_token is not None:
                    token = get_access_token_model().objects.get(
                        token=access_token)
                    app_authorized.send(
                        sender=self, request=request,
                        token=token)
                    body['username'] = token.user.username
                    body['email'] = token.user.email
                    body = json.dumps(body)
            response = Response(data=json.loads(body), status=status)

            for k, v in headers.items():
                response[k] = v
            return response
        else:
            return Response("Email Already Exists")




# drf_social_oauth2
class CustomTokenView(TokenView):
    def post(self, request, *args, **kwargs):
        # Use the rest framework `.data` to fake the post body of the django request.
        mutable_data = request.data.copy()
        request._request.POST = request._request.POST.copy()
        for key, value in mutable_data.items():
            request._request.POST[key] = value
        url, headers, body, status = self.create_token_response(
            request._request)
        if status == 200:
            body = json.loads(body)
            access_token = body.get("access_token")
            if access_token is not None:
                token = get_access_token_model().objects.get(
                    token=access_token)
                app_authorized.send(
                    sender=self, request=request,
                    token=token)
                body['username'] = token.user.username
                body['email'] = token.user.email
                body = json.dumps(body)
        response = Response(data=json.loads(body), status=status)

        for k, v in headers.items():
            response[k] = v
        return response
