from django.db import models
from django.contrib.auth.models import AbstractBaseUser
from django.contrib.auth.models import BaseUserManager
from django.contrib.auth.models import PermissionsMixin

from phonenumber_field.modelfields import PhoneNumberField
import phonenumbers

# Create your models here.
class ProfileManager(BaseUserManager):
    def create_user(self, first_name, last_name, email, username, password=None):
        email = self.normalize_email(email)
        account = self.model(first_name=first_name, last_name=last_name, username=username, email=email)
        account.set_password(password)
        account.save(using=self._db)

        return account 

    def create_superuser(self, first_name, last_name, email, username, password):
        """create and saves new superuser"""
        user = self.create_user(first_name, last_name, email, username, password)
        user.is_superuser = True
        user.is_staff = True

        user.save(using=self._db)
        return user


class User(AbstractBaseUser, PermissionsMixin):
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    email = models.EmailField(unique=True)
    authy_phone = PhoneNumberField(
        null=True,
        blank=True,
        unique=True,
        help_text="This phone number is dedicated to Twilio 2FA Authentication.",
    )
    authy_id = models.CharField(
        max_length=12,
        blank=True,
        help_text="Authentication ID received from Twilio 2FA Api.",
    )
    username = models.CharField(max_length=50, unique=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = ProfileManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ["first_name", "last_name", "username"]

    class Meta:
        ordering = ('id','username', 'first_name','last_name','email','authy_phone','is_active','is_staff', 'password')
        verbose_name_plural = "users"

    def __str__(self):
        return self.email
    
    

