from django.contrib import admin
from .models import UserAccount, PasswordRecoveryOTP

@admin.register(UserAccount)
class UserAccountAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'is_active', 'date_joined')
    list_filter = ('is_active', 'date_joined')
    search_fields = ('username', 'email')

@admin.register(PasswordRecoveryOTP)
class PasswordRecoveryOTPAdmin(admin.ModelAdmin):
    list_display = ('user', 'otp', 'created_at', 'is_used', 'recovery_method')
    list_filter = ('is_used', 'recovery_method', 'created_at')
    search_fields = ('user__username', 'otp')
    
