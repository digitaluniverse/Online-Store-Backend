from django.db.models.signals import pre_save
from .models import User

from django.conf import settings
from authy.api import AuthyApiClient

authy_api = AuthyApiClient(settings.AUTHY_API_KEY)

def updateUser(sender,instance, **kwargs):
    print("UPDATING USER")
    user = instance
    print(user)
    if user.email != '':
        user.username = user.email
    if user.authy_id !='':
        authy_id = user.authy_id
        print(authy_id)
        status = authy_api.users.status(authy_id)
        if status.ok():
            print("USER AUTHORIZED")
            user.phone_verified=True
        else:
            print("AUTHY ID AND PHONE SHOULD BE DELETED")
            user.authy_id=''
            user.phone_verified=False

            user.save()
    else:
        print("AUTHY ID AND PHONE SHOULD BE DELETED")
        try:
            user.phone_verified=False
        except Exception as error:
            print(error)

pre_save.connect(updateUser, sender=User)