from django.core.exceptions import ValidationError
from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status as statuscode
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import make_password
from oauth2_provider.settings import oauth2_settings
from braces.views import CsrfExemptMixin
from oauth2_provider.views.mixins import OAuthLibMixin
from rest_framework.response import Response
from drf_social_oauth2.views import TokenView
from oauth2_provider.models import get_access_token_model, get_application_model
from oauth2_provider.signals import app_authorized
from base import models
from base import serializers
import json
from twilio.rest import Client
from django.conf import settings

client = Client(settings.SOCIAL_AUTH_TWILIO_KEY, settings.SOCIAL_AUTH_TWILIO_SECRET)

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


@api_view(['PUT'])
@permission_classes([IsAuthenticated])
def updateUserProfile(request):
    user = request.user
    authenticated = self.authenticate_client(request)

    serializer = serializers.UserSerializer(user, many=False)

    data = request.data
    user.first_name = data['name']
    user.username = data['email']
    user.email = data['email']

    if data['password'] != '':
        user.password = make_password(data['password'])

    user.save()

    return Response(serializer.data)


# drf_social_oauth2
class updateUserProfileView(TokenView):
    
    @permission_classes([IsAuthenticated])
    def put(self, request, *args, **kwargs):
        # Use the rest framework `.data` to fake the post body of the django request.
        user = request.user

        serializer = serializers.UserSerializer(user, many=False)

        data = request.data
        user.first_name = data['name']
        user.username = data['email']
        user.email = data['email']

        if data['password'] != '':
            user.password = make_password(data['password'])

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
                user_data = serializers.UserSerializer(token.user).data
                body.update(user_data)
                body = json.dumps(body)
        response = Response(data=json.loads(body), status=status)

        for k, v in headers.items():
            response[k] = v
        return response


class userRegisterView(TokenView):
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
            for key, value in serialized_data.items():
                request._request.POST[key] = value
            url, headers, body, status = self.create_token_response(
                request._request)
            print("status: ",body)
            if status == 401:
                self.delete_user()
                body = json.loads(body)

                return Response(data={"error": str(body)}, status=status)

            if status == 200:
                body = json.loads(body)
                access_token = body.get("access_token")
                if access_token is not None:
                    token = get_access_token_model().objects.get(
                        token=access_token)
                    app_authorized.send(
                        sender=self, request=request,
                        token=token)
                    user_data = serializers.UserSerializer(token.user).data
                    #add user data to token body
                    body.update(user_data)
                    body = json.dumps(body)
            response = Response(data=json.loads(body), status=status)

            for k, v in headers.items():
                response[k] = v
            return response
        except Exception as error:
            return Response(data={"error": str(error)}, status=statuscode.HTTP_400_BAD_REQUEST)


class updateUserNumber(TokenView):
    @permission_classes([IsAuthenticated])
    def put(self, request):
        user = request.user
        serializer = serializers.UserSerializer(user, many=False)
        data = request.data
        number=data['number']
        
        if (not user.phone_verified and user.number!=number):
            verifications(number, 'sms')
            user.number = number
            user.save()
            response = Response(data={str("Sending Verification code")}, status=statuscode.HTTP_200_OK)
        elif not user.phone_verified:
            verifications(number, 'sms')
            response = Response(data={str("Sending Verification code")}, status=statuscode.HTTP_200_OK)
        else:
           response = Response(data={"error": str("Phone Number is already Verified")}, status=statuscode.HTTP_400_BAD_REQUEST)
        return response


class verifyUserNumber(TokenView):
    @permission_classes([IsAuthenticated])
    def get(self, request):
        user = request.user
        serializer = serializers.UserSerializer(user, many=False)
        data = request.data
        ser = serializer.data
        number = ser['number']
        code=data['code']
        if (not user.phone_verified):
            try:
                valid = verification_checks(number, code).valid
                print(valid)
                user.phone_verified = valid
                user.save()
                response = Response(data={"verified": number}, status=statuscode.HTTP_200_OK)
            except Exception as error:
                print(error)
                response = Response(data={"error": str(error)}, status=statuscode.HTTP_400_BAD_REQUEST)
            return response
        else:
            response = Response(data={"valid": user.phone_verified,"message": str("Phone Number is already Verified")}, status=statuscode.HTTP_200_OK)
        return response




class verifyUserEmail(TokenView):
    @permission_classes([IsAuthenticated])
    def put(self, request):
        user = request.user
        data = request.data
        email=data['email']
        
        if (not user.phone_verified and user.email!=email):
            verifications(email, 'email')
            user.email= email
            user.save()
            response = Response(data={str("Sending Verification code")}, status=statuscode.HTTP_200_OK)
        elif not user.email_verified:
            verifications(email, 'email')
            response = Response(data={str("Sending Verification code")}, status=statuscode.HTTP_200_OK)
        else:
           response = Response(data={"error": str("Email is already Verified")}, status=statuscode.HTTP_400_BAD_REQUEST)
        return response

class confirmUserEmail(TokenView):
    @permission_classes([IsAuthenticated])
    def get(self, request):
        user = request.user
        serializer = serializers.UserSerializer(user, many=False)
        data = request.data
        ser = serializer.data
        print(ser)
        email = ser['email']
        code=data['code']
        if (not user.email_verified):
            try:
                valid = verification_checks(email, code).valid
                print(valid)
                user.email_verified = valid
                user.save()
                response = Response(data={"verified": email}, status=statuscode.HTTP_200_OK)
            except Exception as error:
                print(error)
                response = Response(data={"error": str(error)}, status=statuscode.HTTP_400_BAD_REQUEST)
            return response
        else:
            response = Response(data={"verified": user.email,"message": str("Email was already Verified")}, status=statuscode.HTTP_200_OK)
        return response

class resetPassword(TokenView):
    @permission_classes([IsAuthenticated])
    def put(self, request):
        user = request.user
        data = request.data
        password=make_password(data['password'])

        if (user.phone_verified):
            number = str(user.number)
            print(number)
            verifications(number, 'sms')
            response = Response(data={"message": str("Phone Number is already Verified")}, status=statuscode.HTTP_200_OK)
        else:
           response = Response(data={"error": str("Phone Number is not Verified")}, status=statuscode.HTTP_400_BAD_REQUEST)
        return response
