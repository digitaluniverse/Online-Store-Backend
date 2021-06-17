from twilio.rest import Client
from django.conf import settings

TWILIO_ACCOUNT_SID = settings.TWILIO_ACCOUNT_SID
TWILIO_AUTH_TOKEN = settings.TWILIO_AUTH_TOKEN
TWILIO_VERIFICATION_SID=settings.TWILIO_VERIFICATION_SID


client = Client(TWILIO_ACCOUNT_SID,TWILIO_AUTH_TOKEN)


def phone_verifications(to):
	return client.verify \
		.services(TWILIO_VERIFICATION_SID) \
		.verifications \
		.create(
			to=to,
			channel="sms",
		)

def email_verifications(to, channel_configuration):
	return client.verify \
		.services(TWILIO_VERIFICATION_SID) \
		.verifications \
		.create(
			to=to,
			channel="email",
			channel_configuration=channel_configuration
		)

def verification_checks(to, token):
	return client.verify \
		.services(TWILIO_VERIFICATION_SID) \
		.verification_checks \
		.create(to=to, code=token)
        
# def get_channel_configuration(to, title, callback_url, message):
#     channel_configuration={
#         #used in email template
#         'substitutions': {
# 			'title': title,
#             'email': to,
#             'callback_url': callback_url
#         }
#     }
#     return channel_configuration

