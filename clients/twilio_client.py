from twilio.rest import Client
from django.conf import settings

client = Client(settings.SOCIAL_AUTH_TWILIO_KEY, settings.SOCIAL_AUTH_TWILIO_SECRET)

def verifications(phone_number, via):
        return client.verify \
                    .services(settings.TWILIO_VERIFICATION_SID) \
                    .verifications \
                    .create(to=phone_number, channel=via)

def verification_checks(phone_number, token):
        return client.verify \
                    .services(settings.TWILIO_VERIFICATION_SID) \
                    .verification_checks \
                    .create(to=phone_number, code=token)