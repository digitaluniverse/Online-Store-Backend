from rest_framework import permissions
from django.core.exceptions import ValidationError
from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status as statuscode
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from rest_framework.views import APIView
from oauth2_provider.settings import oauth2_settings
from braces.views import CsrfExemptMixin
from oauth2_provider.views.mixins import OAuthLibMixin
from rest_framework.response import Response
from drf_social_oauth2.views import TokenView
from oauth2_provider.models import get_access_token_model, get_application_model, get_refresh_token_model
from oauth2_provider.signals import app_authorized
from base import models
from base import serializers
from accounts.models import User, VerifyToken
import secrets

import json
from twilio.rest import Client
from django.conf import settings
from authy.api import AuthyApiClient
import phonenumbers
from phonenumber_field.serializerfields import PhoneNumberField
from rest_framework.generics import CreateAPIView, GenericAPIView
from oauthlib import common
from django.utils import timezone
from datetime import datetime, timedelta
from base.twilio_verify.verify import phone_verifications, email_verifications, verification_checks


Application = get_application_model()
AccessToken = get_access_token_model()
RefreshToken = get_refresh_token_model()


authy_api = AuthyApiClient(settings.AUTHY_API_KEY)


@api_view(['Get'])
@permission_classes([IsAuthenticated])
def getUserProfile(request):
    user = request.user
    serializer = serializers.CustomUserSerializer(user, many=False)
    return Response(serializer.data)


@api_view(['Get'])
@permission_classes([IsAdminUser])
def getUsers(request):
    users = models.User.objects.all()
    serializer = serializers.UserSerializer(users, many=True)
    return Response(serializer.data)


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def updateUserProfile(request):
    user = request.user
    # serializer = serializers.CustomUserSerializer(user, many=False)
    data = request.data

    # user.first_name = data['name']
    # user.username = data['email']
    # user.email = data['email']
    # user.authy_phone = data['authy_phone']
    # user.save()
    return Response(serializer.data)


# drf_social_oauth2
class updateUserProfileView(TokenView):

    @permission_classes([IsAuthenticated])
    def put(self, request, *args, **kwargs):
        # Use the rest framework `.data` to fake the post body of the django request.
        user = request.user
        data = request.data
        serializer = serializers.UpdateUserSerializer(user, many=False)
        email = data['email']
        if user.email != email:
            try:
                if User.objects.get(email=email):
                    print("Email Already Registered")
                    return Response(data={"detail": "Email Already Registered"}, status=statuscode.HTTP_400_BAD_REQUEST)
            except Exception as error:
                user.email = data['email']
                user.email_verified = False
                pass

        serializer.validate_email(data['email'])
        if user.authy_phone != data['authy_phone']:
            user.authy_id = ''
        # user.email = data['email']
        user.first_name = data['name']
        user.username = data['email']
        user.authy_phone = data['authy_phone']
        if user.email_verified:
            user.newsletter = data['newsletter']
        if user.phone_verified:
            user.text_alerts = data['text_alerts']
        user.save()

        return Response(serializer.data)


# drf_social_oauth2
class userLoginView(TokenView):
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
                if not token.user.email_verified:
                    return Response({"detail": "verification"},
                                    status=statuscode.HTTP_400_BAD_REQUEST)
                user_data = serializers.UserSerializer(token.user).data
                body.update(user_data)
                body = json.dumps(body)
        response = Response(data=json.loads(body), status=status)

        for k, v in headers.items():
            response[k] = v
        return response


class newRegisterView(APIView):
    id = None

    def delete_user(self):
        try:
            user = models.User.objects.get(id=self.id)
            user.delete()
        except Exception as error:
            print("Error: ", error)

    def create_user(self, data):
        serializer = serializers.RegisterSerializerWithToken(data=data)
        try:
            serializer.is_valid(raise_exception=True)
            user = models.User.objects.create(
                first_name=data['name'],
                username=data['email'],
                email=data['email'],
                password=make_password(data['password'])
            )
            self.id = user.id
            return serializer.data
        except ValidationError:
            return Response(serializer.errors, status=statuscode.HTTP_400_BAD_REQUEST)

    def post(self, request, *args, **kwargs):
        # Use the rest framework `.data` to fake the post body of the django request.
        mutable_data = request.data.copy()
        request._request.POST = request._request.POST.copy()
        data = mutable_data
        try:
            serialized_data = self.create_user(data)

            return Response(data={"error": "ERROR"}, status=statuscode.HTTP_400_BAD_REQUEST)

        except Exception as error:
            return Response(data={"error": str(error)}, status=statuscode.HTTP_400_BAD_REQUEST)


class userRegisterView(APIView):

    def create_user(self, validated_data):
        user = models.User.objects.create(
            first_name=validated_data['first_name'],
            username=validated_data['email'],
            email=validated_data['email'],
            password=make_password(validated_data['password'])
        )
        return user

    def send_verification_email(self, user):
        obj, created = VerifyToken.objects.get_or_create(user=user)
        obj.token = secrets.token_urlsafe(20)
        obj.save()
        print(obj)
        id = obj.token
        channel_configuration_data = {
            "substitutions": {
                "id": id, "title": "Email Verification", "message": "Confirm Your Email", "callback_url": "http://secureshop.ngrok.io/confirm-email"
            }
        }
        channel_configuration = json.dumps(channel_configuration_data)
        email_verifications(user.email, channel_configuration)


    def post(self, request):
        serializer = serializers.RegistrationSerializer(data=request.data)
        serializer.validate(data=request.data)
        if serializer.is_valid():
            validated_data = serializer.validated_data
            user = self.create_user(validated_data)
            email = validated_data['email']
            try:
                self.send_verification_email(user)
                return Response(data={"detail": "User Registered. Registration Email Sent", "email": email}, status=statuscode.HTTP_201_CREATED)
            except Exception as error:
                return Response(data={"error": error}, status=statuscode.HTTP_400_BAD_REQUEST)
        else:
            for key,value in serializer.errors.items():
                print(value)
            print(serializer.errors)
            return Response(data={json.dumps(serializer.errors)}, status=statuscode.HTTP_400_BAD_REQUEST)


class updateUserNumber(TokenView):
    @permission_classes([IsAuthenticated])
    def put(self, request):
        user = request.user
        serializer = serializers.UserSerializer(user, many=False)
        data = request.data
        number = data['number']

        if (not user.phone_verified and user.number != number):
            phone_verifications(number)
            user.number = number
            user.save()
            response = Response(
                data={str("Sending Verification code")}, status=statuscode.HTTP_200_OK)
        elif not user.phone_verified:
            phone_verifications(number)
            response = Response(
                data={str("Sending Verification code")}, status=statuscode.HTTP_200_OK)
        else:
            response = Response(data={"error": str(
                "Phone Number is already Verified")}, status=statuscode.HTTP_400_BAD_REQUEST)
        return response


class verifyUserNumber(TokenView):
    @permission_classes([IsAuthenticated])
    def get(self, request):
        user = request.user
        serializer = serializers.UserSerializer(user, many=False)
        data = request.data
        ser = serializer.data
        number = ser['number']
        code = data['code']
        if (not user.phone_verified):
            try:
                valid = verification_checks(number, code).valid
                print(valid)
                user.phone_verified = valid
                user.save()
                response = Response(
                    data={"verified": number}, status=statuscode.HTTP_200_OK)
            except Exception as error:
                print(error)
                response = Response(
                    data={"error": str(error)}, status=statuscode.HTTP_400_BAD_REQUEST)
            return response
        else:
            response = Response(data={"valid": user.phone_verified, "message": str(
                "Phone Number is already Verified")}, status=statuscode.HTTP_200_OK)
        return response


class verifyUserEmail(TokenView):

    def put(self, request):
        id = 'nope'
        data = request.data
        email = data['email']
        try:
            if not (models.User.objects.filter(email=email)).exists():
                return Response(data={"detail": f'{email} does not exist',"type": "email_exists"}, status=statuscode.HTTP_400_BAD_REQUEST)

            user = models.User.objects.get(email=email)
            if not user.email_verified:
                obj, created = VerifyToken.objects.get_or_create(user=user)
                obj.token = secrets.token_urlsafe(20)
                obj.save()
                print(obj)
                id = obj.token
            else:
                return Response(data={"detail": "Email already verified"}, status=statuscode.HTTP_400_BAD_REQUEST)
        except Exception as error:
            return Response(data={"detail": error}, status=statuscode.HTTP_400_BAD_REQUEST)
        channel_configuration_data = {
            "substitutions": {
                "id": id, "title": "Email Confirmation", "message": "Confirm Your Email", "callback_url": "http://secureshop.ngrok.io/confirm-email"
            }
        }
        channel_configuration = json.dumps(channel_configuration_data)
        email_verifications(email, channel_configuration)

        return Response(
            data={str("Sending Verification code")}, status=statuscode.HTTP_200_OK)


class confirmUserEmail(TokenView):
    def post(self, request):
        data = request.data
        id = data['id']
        code = data['code']

        try:
            token = VerifyToken.objects.get(token=id)
            print(token)
            email = str(token.user)

        except Exception as error:
            print(error)
            pass

        try:
            valid = verification_checks(email, code).valid
            print(valid)
            if not valid:
                # verifications(email, 'email')
                return Response(
                    data={"error": "Not Valid Sending Code Again"}, status=statuscode.HTTP_400_BAD_REQUEST)
            try:
                user = models.User.objects.get(email=email)
                user.email_verified = valid
                user.save()
                return Response(
                    data={"verified": email}, status=statuscode.HTTP_200_OK)
            except Exception as error:
                return Response(
                    data={"error": str(error)}, status=statuscode.HTTP_400_BAD_REQUEST)
        except Exception as error:
            return Response(
                data={"error": str(error)}, status=statuscode.HTTP_400_BAD_REQUEST)


class passwordResetEmail(TokenView):
    def put(self, request):
        data = request.data
        email = data['email']
        try:
            user = models.User.objects.get(email=email)
            obj, created = VerifyToken.objects.get_or_create(user=user)
            obj.token = secrets.token_urlsafe(20)
            obj.save()
            print(obj)
            id = obj.token
        except Exception as error:
            print(error)
            pass
        # secrets.token_urlsafe(20)
        channel_configuration_data = {
            "substitutions": {
                "id": id, "title": "Password Reset", "message": "Reset your Password", "callback_url": "http://secureshop.ngrok.io/password-reset-email"
            }
        }
        channel_configuration = json.dumps(channel_configuration_data)
        email_verifications(email, channel_configuration)

        return Response(
            data={str("Sending Verification code")}, status=statuscode.HTTP_200_OK)


class confirmResetPasswordEmail(TokenView):
    def post(self, request):
        data = request.data
        id = data['id']
        code = data['code']

        try:
            token = VerifyToken.objects.get(token=id)
            print(token)
            email = str(token.user)

        except Exception as error:
            print(error)
            pass

        try:
            valid = verification_checks(email, code).valid
            print(valid)
            if not valid:
                # verifications(email, 'email')
                return Response(
                    data={"error": "Code Not Valid"}, status=statuscode.HTTP_400_BAD_REQUEST)
            try:
                user = models.User.objects.get(email=email)
                application = Application.objects.get(name='auth')
                expires = timezone.now() + timedelta(seconds=oauth2_settings.ACCESS_TOKEN_EXPIRE_SECONDS)
                access_token = AccessToken(
                    user=user,
                    scope='',
                    expires=expires,
                    token=common.generate_token(),
                    application=application
                )
                access_token.save()
                print("Password Reset Code Valid")
                token.delete()
                return Response(
                    data=str(access_token), status=statuscode.HTTP_200_OK)
            except Exception as error:
                token.delete()
                return Response(
                    data={"error": str(error)}, status=statuscode.HTTP_400_BAD_REQUEST)

        except Exception as error:
            return Response(
                data={"error": str(error)}, status=statuscode.HTTP_400_BAD_REQUEST)


class resetPassword(TokenView):
    @permission_classes([IsAuthenticated])
    def put(self, request):
        user = request.user
        try:
            data = request.data
            password = make_password(data['password'])
            user.password = password
            user.save()
            serializer = serializers.CustomUserSerializer(user)
            return Response(serializer.data, status=statuscode.HTTP_200_OK)


        except Exception as error:
            return Response(data={"error": error}, status=statuscode.HTTP_400_BAD_REQUEST)




class CustomTokenObtainPairView(TokenView):
    """
    2FA JWT Authentication: Step 0
    """

    # serializer_class = TokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        # ret = super().post(request, *args, **kwargs)
        user = models.User.objects.get(username=request.data["username"])
        # check if user has set to true any 2FA method
        # and needs to be re-direct to 2FA verification uri
        if user.is_twofa_on():
            # request 2FA token via sms for user
            sms = authy_api.users.request_sms(user.authy_id, {"force": True})
            if sms.ok():
                return Response(
                    {
                        "message": "SMS request successful. 2FA token verification expected."
                    },
                    status=statuscode.HTTP_206_PARTIAL_CONTENT,
                )
            else:
                return Response(
                    {"error": sms.errors()["message"]},
                    status=statuscode.HTTP_503_SERVICE_UNAVAILABLE,
                )
        # return ret
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
                user_data = serializers.CustomUserSerializer(token.user).data
                body.update(user_data)
                body = json.dumps(body)
        response = Response(data=json.loads(body), status=status)

        for k, v in headers.items():
            response[k] = v
        return response


class PhoneVerificationView(GenericAPIView):
    """
    2FA JWT Authentication: Step 1
    Twilio phone verification view.
    This endpoint will check if user mobile phone number is valid.
    If YES Twilio API send 4 digit verification token via SMS.
    """

    permission_classes = [IsAuthenticated]
    serializer_class = serializers.PhoneSerializer

    def post(self, request):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid(raise_exception=True):
            return Response(status=statuscode.HTTP_204_NO_CONTENT)


class PhoneRegistrationView(GenericAPIView):
    """
    2FA JWT Authentication: Step 2
    Twilio 2FA phone registration view.
    First it will validate if 4 digit tokend sent to user phone number is valid.
    If Twilio verification check pass in next step Twilio API call will register user for 2FA
    If success: user instance will be updated with verified phone number and received from Twilio API authy_id
    """

    serializer_class = serializers.PhoneTokenSerializer
    queryset = models.User.objects.all()
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

    def post(self, request, *args, **kwargs):
        user = self.get_object()
        data = request.data
        print(user.email)

        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        phone = phonenumbers.parse(
            str(serializer.validated_data["authy_phone"]), None)
        print(serializer.validated_data)

        authy_user = authy_api.users.create(
            user.email, str(phone.national_number), phone.country_code, True
        )
        print(str(phone.national_number), phone.country_code)

        if authy_user.ok():
            user.authy_id = authy_user.id

            user.authy_phone = serializer.validated_data["authy_phone"]
            user.save()
            return Response(status=statuscode.HTTP_204_NO_CONTENT)
        else:
            return Response(authy_user.errors(), status=statuscode.HTTP_400_BAD_REQUEST)


class AuthyTokenVerifyView(APIView):

    """
    2FA JWT Authentication: Step 3
    Twilio 2FA user authentication view.
    This view verify if Twilio 2FA registered user entered correct 8 digit token.
    Token will be requested by TwoFaTokenObtainPairView only for 2FA registered users
    Is success: user receive refresh and access JWT.
    """

    def post(self, request, *args, **kwargs):
        # ret = request.post(request, *args, **kwargs)
        user = models.User.objects.get(username=request.data["username"])
        validated_data = request.data
        # check if user has 2FA id assigned
        if user.is_twofa_on():
            # verify received 2FA token with Twilio API
            verification = authy_api.tokens.verify(
                user.authy_id, token=request.data["token"]
            )
            if verification.ok():
                serializer = serializers.CustomUserSerializer(user, many=False)

                return Response(serializer.data, status=statuscode.HTTP_200_OK)
            else:
                # return 2FA token verification error
                return Response(
                    {"error": verification.response.json()[
                        "errors"]["message"]},
                    status=statuscode.HTTP_400_BAD_REQUEST,
                )
        else:
            # user has no 2FA authentication methods enabled
            return Response(
                {"error": "User not allowed for 2FA authentication."},
                status=statuscode.HTTP_400_BAD_REQUEST,
            )


class AuthyLogin(APIView):

    """
    2FA JWT Authentication: Step 3
    Twilio 2FA user authentication view.
    This view verify if Twilio 2FA registered user entered correct 8 digit token.
    Token will be requested by TwoFaTokenObtainPairView only for 2FA registered users
    Is success: user receive refresh and access JWT.
    """

    serializer_class = serializers.PhoneTokenSerializer

    def post(self, request, *args, **kwargs):
        data = request.data
        phone = phonenumbers.parse(str(data.get("authy_phone")), None)
        try:
            user = models.User.objects.get(authy_phone=phone)
        # check if user has 2FA id assigned
            if user.is_twofa_on():
                # verify received 2FA token with Twilio API
                verification = authy_api.tokens.verify(
                    user.authy_id, token=request.data["token"]
                )
                if verification.ok():
                    serializer = serializers.CustomUserSerializer(
                        user, many=False)

                    return Response(serializer.data, status=statuscode.HTTP_200_OK)
                else:
                    # return 2FA token verification error
                    return Response(
                        {"error": verification.response.json()[
                            "errors"]["message"]},
                        status=statuscode.HTTP_400_BAD_REQUEST,
                    )
            else:
                # user has no 2FA authentication methods enabled
                return Response(
                    {"error": "User not allowed for 2FA authentication."},
                    status=statuscode.HTTP_400_BAD_REQUEST,
                )
        except Exception as error:
            return Response(data={"error": str(
                "Phone Number Not Found")}, status=statuscode.HTTP_404_NOT_FOUND)


# @api_view(['Get'])
# @permission_classes([IsAuthenticated])
# def testToken(request):
#     user = request.user
#     data = request.data
#     print(data)
#     serializer = serializers.TokenSerializer(data=data)
#     serializer.is_valid()
#     return Response(serializer.data)

class testToken(GenericAPIView):
    """
    TEST TOKEN GENERATION
    """

    permission_classes = [IsAuthenticated]
    serializer_class = serializers.TokenSerializer

    def get(self, request):
        data = request.data
        serializer = self.get_serializer(data=data, user=self.request.user)
        try:
            serializer.is_valid(raise_exception=True)
            print(serializer.validated_data)
            return Response(data=(serializer.validated_data), status=statuscode.HTTP_200_OK)
        except Exception as error:
            return Response(data={"error": str(error)}, status=statuscode.HTTP_400_BAD_REQUEST)
