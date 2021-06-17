from django.contrib import admin
from .models import User, VerifyToken
# Register your models here.
# admin.site.register(models.User)

# class CustomModelAdmin(admin.ModelAdmin):
#     def __init__(self, model, admin_site):
#         self.ordering = model._meta.ordering
#         self.list_display = [field.name for field in model._meta.fields if field.name != "id"]
#         super(CustomModelAdmin, self).__init__(model, admin_site)

# class UserAdmin(CustomModelAdmin):
#     pass


class UserAdmin(admin.ModelAdmin):
    list_display = ['id','username', 'last_name','first_name','email','number','phone_verified','is_active','is_staff', 'password']


class VerifyTokenAdmin(admin.ModelAdmin):
    list_display = ['id', 'user', 'token']

admin.site.register(User,UserAdmin)
admin.site.register(VerifyToken,VerifyTokenAdmin)