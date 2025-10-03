# models.py
from django.db import models
from django.contrib.auth.models import AbstractUser, User
from datetime import timedelta
from django.utils import timezone
import random

class UserAccount(AbstractUser):
    phone_number = models.CharField(max_length=12, blank=True, null=True)
    
    def __str__(self):
        return self.email
    
    def save(self, *args, **kwargs):
        if self.first_name:
            self.first_name = self.first_name.upper()
        
        if self.last_name:
            self.last_name = self.last_name.upper()
        
        super().save(*args, **kwargs)

class PasswordRecoveryOTP(models.Model):
    user = models.ForeignKey(UserAccount, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    is_used = models.BooleanField(default=False)
    recovery_method = models.CharField(max_length=10, choices=[
        ('email', 'Email'),
        ('sms', 'SMS')
    ])
    
    def is_valid(self):
        # OTP is valid for 5 minutes
        expiry_time = self.created_at + timedelta(minutes=5)
        return timezone.now() <= expiry_time and not self.is_used
    
    @classmethod
    def generate_otp(cls, user, method):
        # Delete any existing OTPs for this user
        cls.objects.filter(user=user).delete()
        
        # Generate a random 6-digit OTP
        otp = str(random.randint(100000, 999999))
        
        # Create and return the OTP instance
        return cls.objects.create(
            user=user,
            otp=otp,
            recovery_method=method
        )
    
    class Meta:
        verbose_name = "Password Recovery OTP"
        verbose_name_plural = "Password Recovery OTPs"
