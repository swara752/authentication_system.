# serializers.py
from rest_framework import serializers
from django.contrib.auth.models import User
from .models import PasswordRecoveryOTP

class UserCheckSerializer(serializers.Serializer):
    username = serializers.CharField()
    email = serializers.EmailField()

class PhoneSerializer(serializers.Serializer):
    phone_number = serializers.CharField()
    
    def validate_phone_number(self, value):
        # Validate phone number format (XXXX XX XXXX)
        if not value.replace(' ', '').isdigit():
            raise serializers.ValidationError("Phone number must contain only digits and spaces")
        
        parts = value.split(' ')
        if len(parts) != 3 or len(parts[0]) != 4 or len(parts[1]) != 2 or len(parts[2]) != 4:
            raise serializers.ValidationError("Phone number must be in format: XXXX XX XXXX")
        
        return value

class OTPSerializer(serializers.Serializer):
    otp = serializers.CharField(min_length=6, max_length=6)
    
class PasswordResetSerializer(serializers.Serializer):
    otp = serializers.CharField(min_length=6, max_length=6)
    password = serializers.CharField(min_length=5)
    confirm_password = serializers.CharField(min_length=5)
    
    def validate(self, data):
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError("Passwords do not match")
        
        # Password validation: at least 5 chars, 1 capital, 1 special
        if len(data['password']) < 5:
            raise serializers.ValidationError("Password must be at least 5 characters long")
        
        if not any(char.isupper() for char in data['password']):
            raise serializers.ValidationError("Password must contain at least one uppercase letter")
        
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?/"
        if not any(char in special_chars for char in data['password']):
            raise serializers.ValidationError("Password must contain at least one special character")
        
        return data
