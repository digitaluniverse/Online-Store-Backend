from twilio.rest import Client
from django.conf import settings

TWILIO_ACCOUNT_SID = settings.TWILIO_ACCOUNT_SID
TWILIO_AUTH_TOKEN = settings.TWILIO_AUTH_TOKEN
TWILIO_FROM_NUMBER = settings.TWILIO_FROM_NUMBER

client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)


def sendMessage(to, message):
    message = client.messages.create(
        to=to,
        from_=TWILIO_FROM_NUMBER,
        body=message
    )
    print(message.sid)
