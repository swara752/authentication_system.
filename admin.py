# admin.py
from django.contrib import admin
from .models import PasswordRecoveryOTP

@admin.register(PasswordRecoveryOTP)
class PasswordRecoveryOTPAdmin(admin.ModelAdmin):
    list_display = ('user', 'otp', 'created_at', 'is_used', 'recovery_method')
    list_filter = ('is_used', 'recovery_method', 'created_at')
    search_fields = ('user__username', 'otp')