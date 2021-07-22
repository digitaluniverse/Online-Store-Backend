from enum import unique
from os import access, error, read
from django.core import validators
from django.core.validators import validate_email
from rest_framework import serializers
# from django.contrib.auth.models import User
from rest_framework.fields import EmailField, ReadOnlyField
from . import models
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.hashers import make_password
import json
from oauth2_provider.models import get_access_token_model, get_application_model, get_refresh_token_model
from authy.api import AuthyApiClient
from django.conf import settings
from twilio.rest import Client

from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password


import phonenumbers
from phonenumber_field.serializerfields import PhoneNumberField
from rest_framework.fields import CharField
from rest_framework.exceptions import ValidationError
from oauthlib import common
from django.utils import timezone
from datetime import datetime, timedelta
from oauth2_provider.settings import oauth2_settings


Application = get_application_model()
AccessToken = get_access_token_model()
RefreshToken = get_refresh_token_model()


authy_api = AuthyApiClient(settings.AUTHY_API_KEY)

client = Client(settings.TWILIO_ACCOUNT_SID,
                settings.TWILIO_AUTH_TOKEN)


def verifications(user_destination, via):
    return client.verify \
        .services(settings.TWILIO_VERIFICATION_SID) \
        .verifications \
        .create(to=user_destination, channel=via)


def verification_checks(user_destination, token):
    return client.verify \
        .services(settings.TWILIO_VERIFICATION_SID) \
        .verification_checks \
        .create(to=user_destination, code=token)


class UserSerializer(serializers.ModelSerializer):
    name = serializers.SerializerMethodField(read_only=True)
    _id = serializers.SerializerMethodField(read_only=True)
    isAdmin = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = models.User
        fields = ['id', '_id', 'username', 'email', 'name', 'number',
                  'phone_verified', 'email_verified', 'newsletter', 'text_alerts', 'authy_phone', 'authy_id', 'isAdmin']

    def get__id(self, obj):
        return obj.id

    def get_isAdmin(self, obj):
        return obj.is_staff

    def get_name(self, obj):
        name = obj.first_name
        if name == '':
            name = obj.email
        return name


class RegistrationSerializer(serializers.Serializer):
    name = serializers.CharField(write_only=True)
    email = serializers.EmailField(
        )
    password = serializers.CharField(
        write_only=True,
        validators=[validate_password]
        )
        
    def validate(self,data):

            first_name = data.get('name')
            username = data['email']
            email = data['email']
            password = data['password']
            
            email_query = models.User.objects.filter(email__iexact=email)
            if email_query.exists():
                verified = email_query.values_list('email_verified',flat=True).first()
                print(verified)
                if verified:
                    raise serializers.ValidationError({"type": "exists","detail": "That Email address is already associated with a secureshop account"})
                else:
                    raise serializers.ValidationError({"type": "verify","detail": "That Email address is already associated with a secureshop account but isnt verified"})
                
            try:
                validate_password(password)

            except Exception as error:
                print(error)
                raise serializers.ValidationError({"type": "password","detail": str(error)})


            new_data = {
                'first_name': first_name,
                'username': username,
                'email': email,
                'password': password,
            }
            return new_data



class ProductSerializer(serializers.ModelSerializer):
    # image = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = models.Product
        fields = '__all__'

    # def get_image(self, obj):
    #     image = settings.BACKEND_URL + obj.image.url
    #     return image


class TokenSerializer(serializers.Serializer):
    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user')
        super().__init__(*args, **kwargs)

    def validate(self, data):
        print("Start Validation")
        user = self.user
        application = Application.objects.get()
        expires = timezone.now() + timedelta(seconds=oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)
        access_token = AccessToken(
            user=user,
            scope='',
            expires=expires,
            token=common.generate_token(),
            application=application
        )
        access_token.save()
        # print(data)
        data['access_token'] = str(access_token)
        return data


class CustomUserSerializer(serializers.ModelSerializer):
    name = serializers.SerializerMethodField(read_only=True)
    _id = serializers.SerializerMethodField(read_only=True)
    isAdmin = serializers.SerializerMethodField(read_only=True)
    access_token = serializers.SerializerMethodField(read_only=True)
    refresh_token = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = models.User
        fields = ['id', '_id', 'username', 'email', 'name', 'number',
                  'phone_verified', 'email_verified', 'text_alerts', 'newsletter', 'authy_phone', 'authy_id', 'isAdmin', 'access_token', 'refresh_token']

    def get__id(self, obj):
        return obj.id

    def get_isAdmin(self, obj):
        return obj.is_staff

    def get_name(self, obj):
        name = obj.first_name
        if name == '':
            name = obj.email
        return name

    def accessToken(self, obj):
        application = Application.objects.get()
        expires = timezone.now() + timedelta(seconds=oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)
        access_token = AccessToken(
            user=obj,
            scope='',
            expires=expires,
            token=common.generate_token(),
            application=application
        )
        access_token.save()
        return access_token

    def get_access_token(self, obj):
        access_token = self.accessToken(obj)
        access_token = str(access_token)
        return access_token

    def get_refresh_token(self, obj):
        access_token = self.accessToken(obj)
        application = Application.objects.get(name='auth')
        refresh_token = RefreshToken(
            user=obj,
            token=common.generate_token(),
            application=application,
            access_token=access_token
        )
        refresh_token.save()
        refresh_token = str(refresh_token)
        return refresh_token



class UpdateUserSerializer(CustomUserSerializer):
    # id = ReadOnlyField()
    # name = CharField()
    email = EmailField()
    # authy_phone = PhoneNumberField(required=False)

    def validate_email(self, value):
        print("VALIDATE EMAIL")

        print(value)
        return value


class PhoneSerializer(serializers.Serializer):  # noqa
    authy_phone = PhoneNumberField(required=True)

    def validate(self, data):
        try:
            phone = phonenumbers.parse(str(data.get("authy_phone")), None)
            authy_phone = authy_api.phones.verification_start(
                phone.national_number, phone.country_code
            )
            if authy_phone.ok():
                return data
            else:
                #raise ValidationError(authy_phone.errors())
                raise ValidationError({"detail": authy_phone.errors()})

        except Exception as error:
            print(error)
            raise ValidationError({"detail": error})



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


# class AuthyPhoneLoginSerializer(serializers.Serizlizer):

class ShippingAddressSerializer(serializers.ModelSerializer):

    class Meta:
        model = models.ShippingAddress
        fields = '__all__'


class OrderItemSerializer(serializers.ModelSerializer):

    class Meta:
        model = models.OrderItem
        fields = '__all__'


class OrderSerializer(serializers.ModelSerializer):
    orderItems = serializers.SerializerMethodField(read_only=True)
    shippingAddress = serializers.SerializerMethodField(read_only=True)
    user = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = models.Order
        fields = '__all__'

    def get_orderItems(self, obj):
        items = obj.orderitem_set.all()
        serializer = OrderItemSerializer(items, many=True)
        return serializer.data

    def get_shippingAddress(self, obj):
        try:
            address = ShippingAddressSerializer(
                obj.shippingaddress, many=False).data
        except:
            address = False
        return address

    def get_user(self, obj):
        user = obj.user
        serializer = UserSerializer(user, many=False)
        return serializer.data
