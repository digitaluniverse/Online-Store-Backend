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
        account = self.model(
            first_name=first_name, last_name=last_name, username=username, email=email)
        account.set_password(password)
        account.save(using=self._db)

        return account

    def create_superuser(self, first_name, last_name, email, username, password):
        """create and saves new superuser"""
        user = self.create_user(first_name, last_name,
                                email, username, password)
        user.is_superuser = True
        user.is_staff = True

        user.save(using=self._db)
        return user


class User(AbstractBaseUser, PermissionsMixin):
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    email = models.EmailField(unique=True)
    number = PhoneNumberField(
        null=True,
        blank=True,
        unique=True,
        help_text="This phone number is dedicated to Twilio 2FA Authentication.",
    )
    phone_verified = models.BooleanField(default=False)
    email_verified = models.BooleanField(default=False)
    reset_authorized = models.BooleanField(default=False)
    authy_id = models.CharField(
        max_length=12,
        blank=True,
        help_text="Authentication ID received from Twilio 2FA Api.",
    )

    authy_phone = PhoneNumberField(
        null=True,
        blank=True,
        unique=True,
        help_text="This phone number is dedicated to Twilio 2FA Authentication.",
    )

    username = models.CharField(max_length=50, unique=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = ProfileManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ["first_name", "last_name", "username"]


    def get_phone(self):
        try:
            parsed = phonenumbers.parse(str(self.number), None)
        except phonenumbers.NumberParseException:
            return None
        return parsed

    def is_phone_verified(self):
        if self.get_phone() is not None and self.phone_verified:
            return True
        else:
            return False

    def get_authy_phone(self):
        try:
            parsed = phonenumbers.parse(str(self.authy_phone), None)
        except phonenumbers.NumberParseException:
            return None
        return parsed

    def is_twofa_on(self):
        if self.get_authy_phone() is not None and self.authy_id.isdigit():
            return True
        else:
            return False

    class Meta:
        ordering = ('id', 'username', 'first_name', 'last_name', 'email',
                    'number', 'phone_verified', 'is_active', 'is_staff', 'password')
        verbose_name_plural = "users"

    def __str__(self):
        return self.email
