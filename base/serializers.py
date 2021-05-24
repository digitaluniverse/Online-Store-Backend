from rest_framework import serializers
from django.contrib.auth.models import User
from rest_framework.fields import ReadOnlyField
from . import models
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.hashers import make_password
import json

class UserSerializer(serializers.ModelSerializer):
    name = serializers.SerializerMethodField(read_only=True)
    _id = serializers.SerializerMethodField(read_only=True)
    isAdmin = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = User
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

# class UserSerializerWithToken(UserSerializer):
#     token = serializers.SerializerMethodField(read_only=True)

#     class Meta:
#         model = User
#         fields = ['id', '_id', 'username', 'email', 'name', 'isAdmin', 'token']

#     def get_token(self, obj):
#         token = RefreshToken.for_user(obj)
#         return str(token.access_token)


class RegisterSerializer(serializers.ModelSerializer):
    grant_type = serializers.CharField()
    client_id = serializers.CharField()
    client_secret = serializers.CharField()
    username = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = models.User
        fields = ('username','grant_type', 'client_id', 'client_secret','username', 'email', 'password')
        extra_kwargs ={
            'grant_type': {'read_only': True},
            'client_id': {'read_only': True},
            'client_secret': {'read_only': True}
        }

    def validate(self, data):
        email = data.get('email')
        # email = json.dumps(email)
        print(email)
        try:
            print("trying to filter username")
            user = User.objects.filter(username=email)
            print(user)

            if User.objects.filter(email=email).exists():
                raise serializers.ValidationError(_("Email already exists"))
        except User.DoesNotExist:
            pass
        if not data.get('name'):
            raise serializers.ValidationError(_("Empty Name"))
        if not data.get('email'):
            raise serializers.ValidationError(_("Empty Email"))
        if not data.get('password'):
            raise serializers.ValidationError(_("Empty Password"))
        
        print("Error Not Raised")
        return data
    def get_username(self,obj):
        username = obj.email
        return username



class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Product
        fields = '__all__'
