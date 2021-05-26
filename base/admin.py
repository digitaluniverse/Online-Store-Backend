from django.contrib import admin
from . import models

admin.site.site_header = "Pro Shop Admin"


class CustomModelAdmin(admin.ModelAdmin):
    def __init__(self, model, admin_site):
        self.list_display = [field.name for field in model._meta.fields if field.name != "id"]
        super(CustomModelAdmin, self).__init__(model, admin_site)


# Register your models here.

class ProductAdmin(CustomModelAdmin):
    pass

class OrderAdmin(CustomModelAdmin):
    pass

admin.site.register(models.Product, ProductAdmin)
admin.site.register(models.Order, OrderAdmin)
admin.site.register(models.OrderItem)
admin.site.register(models.ShippingAddress)
admin.site.register(models.Review)