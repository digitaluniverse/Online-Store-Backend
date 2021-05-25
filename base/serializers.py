from os import read
from rest_framework import serializers
# from django.contrib.auth.models import User
from rest_framework.fields import ReadOnlyField
from . import models
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.hashers import make_password
import json
from oauth2_provider.models import get_access_token_model, get_application_model


class UserSerializer(serializers.ModelSerializer):
    name = serializers.SerializerMethodField(read_only=True)
    _id = serializers.SerializerMethodField(read_only=True)
    isAdmin = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = models.User
        fields = ['id', '_id', 'username', 'email', 'name', 'isAdmin']

    def get__id(self, obj):
        return obj.id

    def get_isAdmin(self, obj):
        return obj.is_staff

    def get_name(self, obj):
        name = obj.first_name
        if name == '':
            name = obj.email
        return name


class RegisterSerializerWithToken(serializers.ModelSerializer):
    grant_type = serializers.CharField()
    client_id = serializers.CharField()
    client_secret = serializers.CharField()
    name = serializers.CharField()
    username = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = models.User
        fields = ('grant_type', 'client_id',
                  'client_secret', 'name', 'email', 'password', 'username')
        extra_kwargs = {
            'grant_type': {'read_only': True},
            'client_id': {'read_only': True},
            'client_secret': {'read_only': True},
            'name': {'read_only': True}
        }

    def validate(self, data):
        queryset = models.User.objects.all()
        try:
            email = data.get('email')
            filtered = queryset.get(username=email)
            raise serializers.ValidationError(
                {"Error": "Email Already Exists"})
        except models.User.DoesNotExist:
            pass
        if not data.get('name'):
            raise serializers.ValidationError(
                {"Error": "Name can not be empty"})
        if not data.get('email'):
            raise serializers.ValidationError(
                {"Error": "Email can not be empty"})
        if not data.get('password'):
            raise serializers.ValidationError(
                {"Error": "Password can not be empty"})
        return data

    def get_username(self, obj):
        username = obj['email']
        return username



class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Product
        fields = '__all__'
