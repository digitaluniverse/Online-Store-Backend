from django.db.models.signals import pre_save
from accounts.models import User

# def updateUser(sender,instance, **kwargs):
#     user = instance
#     if user.email != '':
#         user.username = user.email
#     if user.email != user.email:
#         user.email_verified = False

# pre_save.connect(updateUser, sender=User)