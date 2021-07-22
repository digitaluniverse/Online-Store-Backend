from django.db.models.signals import post_save, pre_save
from .models import Order
from .twilio_verify.message import sendMessage



def orderUpdate(sender,instance, **kwargs):
    print("Updating Order")
    order = instance
    print(sender)
    user = order.user
    print("order Number", str(order.id))
    message= f'Your order #{order.id} was recieved your total is ${order.totalPrice}\nto view your order go to\nhttp://secureshop.ngrok.io/order/{order.id}'
    number = str(user.number)
    if user.text_alerts:
        sendMessage(number,message)

post_save.connect(orderUpdate, sender=Order)