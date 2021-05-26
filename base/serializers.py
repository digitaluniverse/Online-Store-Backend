from os import read
from rest_framework import serializers
# from django.contrib.auth.models import User
from rest_framework.fields import ReadOnlyField
from . import models
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.hashers import make_password
import json
from oauth2_provider.models import get_access_token_model, get_application_model
from authy.api import AuthyApiClient
from django.conf import settings
import phonenumbers
from phonenumber_field.serializerfields import PhoneNumberField
from rest_framework.fields import CharField
from rest_framework.exceptions import ValidationError


authy_api = AuthyApiClient(settings.AUTHY_API_KEY)


class UserSerializer(serializers.ModelSerializer):
    name = serializers.SerializerMethodField(read_only=True)
    _id = serializers.SerializerMethodField(read_only=True)
    isAdmin = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = models.User
        fields = ['id', '_id', 'username', 'email', 'name', 'number',
            'phone_verified', 'email_verified', 'authy_phone', 'authy_id', 'isAdmin']

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


class CustomUserSerializer(serializers.ModelSerializer):
    name = serializers.SerializerMethodField(read_only=True)
    _id = serializers.SerializerMethodField(read_only=True)
    isAdmin = serializers.SerializerMethodField(read_only=True)
    class Meta:
        model = models.User
        fields = "__all__" 
        

    def get__id(self, obj):
        return obj.id

    def get_isAdmin(self, obj):
        return obj.is_staff

    def get_name(self, obj):
        name = obj.first_name
        if name == '':
            name = obj.email
        return name


class PhoneSerializer(serializers.Serializer):  # noqa
    authy_phone = PhoneNumberField(required=True)

    def validate(self, data):
        phone = phonenumbers.parse(str(data.get("authy_phone")), None)
        authy_phone = authy_api.phones.verification_start(
            phone.national_number, phone.country_code
        )
        if authy_phone.ok():
            return data
        else:
            raise ValidationError(authy_phone.errors())


class PhoneTokenSerializer(serializers.Serializer):  # noqa
    authy_phone = PhoneNumberField(required=True)
    token = CharField(min_length=4, required=True, write_only=True)

    def validate(self, data):
        # test received phone 4 digit verification token from Twilio API
        phone = phonenumbers.parse(str(data.get("authy_phone")), None)
        authy_phone = authy_api.phones.verification_check(
            phone.national_number, phone.country_code, data.get("token")
        )
        if authy_phone.ok():
            return data
        else:
            raise ValidationError(authy_phone.errors())

