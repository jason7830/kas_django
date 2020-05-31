from django.contrib import admin
from account.models import Account, ExpiringToken, RegistrationVerifiy
from django.contrib.auth.admin import UserAdmin
# Register your models here.

class AccountAdmin(UserAdmin):
    list_display = ('email','date_joined','last_login','is_active','group')
    search_fields = ('email',)
    readonly_fields = ('date_joined','last_login')
    ordering = ('email','date_joined','last_login')
    filter_horizontal = ()
    list_filter = ()
    fieldsets = (
        (None, {'fields': ('email', 'password','group')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2','group'),
        }),
    )


admin.site.register(Account,AccountAdmin)

@admin.register(ExpiringToken)
class TokenAdmin(admin.ModelAdmin):
    list_display = ('user', 'key', 'created','expire_time')
    fields = ('user',)
    ordering = ('-created',)

@admin.register(RegistrationVerifiy)
class RegistrationVerifiyAdmin(admin.ModelAdmin):
    list_display = ('email','token','verified','apply_time','expire_time')
    fields = ('email',)
    ordering = ('-apply_time',)