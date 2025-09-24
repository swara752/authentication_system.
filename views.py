# views.py
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.conf import settings
from twilio.rest import Client
from .models import PasswordRecoveryOTP
from .serializers import (
    UserCheckSerializer, 
    PhoneSerializer, 
    OTPSerializer, 
    PasswordResetSerializer
)
import logging

logger = logging.getLogger(__name__)

@api_view(['POST'])
@permission_classes([AllowAny])
def check_user(request):
    """
    Check if username and email combination exists
    """
    serializer = UserCheckSerializer(data=request.data)
    if serializer.is_valid():
        username = serializer.validated_data['username']
        email = serializer.validated_data['email']
        
        try:
            user = User.objects.get(username=username, email=email)
            return Response({
                'success': True, 
                'message': 'User verified successfully'
            })
        except User.DoesNotExist:
            return Response({
                'success': False, 
                'message': 'Username and email combination not found'
            }, status=status.HTTP_404_NOT_FOUND)
    
    return Response({
        'success': False, 
        'message': 'Invalid data',
        'errors': serializer.errors
    }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def send_sms(request):
    """
    Send SMS with OTP to user's phone
    """
    # Check if user exists in session (from previous check_user call)
    username = request.data.get('username')
    if not username:
        return Response({
            'success': False, 
            'message': 'Username required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return Response({
            'success': False, 
            'message': 'User not found'
        }, status=status.HTTP_404_NOT_FOUND)
    
    # Validate phone number
    phone_serializer = PhoneSerializer(data=request.data)
    if not phone_serializer.is_valid():
        return Response({
            'success': False, 
            'message': 'Invalid phone number',
            'errors': phone_serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    phone_number = phone_serializer.validated_data['phone_number']
    
    # Generate OTP
    otp_instance = PasswordRecoveryOTP.generate_otp(user, 'sms')
    
    # Send SMS using Twilio
    try:
        client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        message = client.messages.create(
            body=f"Your password reset OTP is: {otp_instance.otp}. It will expire in 5 minutes.",
            from_=settings.TWILIO_PHONE_NUMBER,
            to=phone_number.replace(' ', '')  # Remove spaces for Twilio
        )
        
        logger.info(f"SMS sent to {phone_number} for user {username}, SID: {message.sid}")
        
        return Response({
            'success': True, 
            'message': 'Reset code sent to your phone!',
            'otp': otp_instance.otp  # In production, don't return the OTP
        })
    
    except Exception as e:
        logger.error(f"Failed to send SMS: {str(e)}")
        return Response({
            'success': False, 
            'message': 'Failed to send SMS. Please try again.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([AllowAny])
def send_email(request):
    """
    Send email with OTP to user's email
    """
    username = request.data.get('username')
    email = request.data.get('email')
    
    if not username or not email:
        return Response({
            'success': False, 
            'message': 'Username and email required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.get(username=username, email=email)
    except User.DoesNotExist:
        return Response({
            'success': False, 
            'message': 'User not found'
        }, status=status.HTTP_404_NOT_FOUND)
    
    # Generate OTP
    otp_instance = PasswordRecoveryOTP.generate_otp(user, 'email')
    
    # Send email
    try:
        subject = "Password Reset Request"
        message = f"""
        Hello {user.username},
        
        You requested a password reset. Your OTP is: {otp_instance.otp}
        
        This OTP will expire in 5 minutes.
        
        If you didn't request this reset, please ignore this email.
        
        Thanks,
        The Support Team
        """
        
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [user.email],
            fail_silently=False,
        )
        
        logger.info(f"Email sent to {user.email} for user {username}")
        
        return Response({
            'success': True, 
            'message': 'Reset link sent to your email!',
            'otp': otp_instance.otp  # In production, don't return the OTP
        })
    
    except Exception as e:
        logger.error(f"Failed to send email: {str(e)}")
        return Response({
            'success': False, 
            'message': 'Failed to send email. Please try again.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([AllowAny])
def contact_admin(request):
    """
    Handle contact admin request
    """
    username = request.data.get('username')
    email = request.data.get('email')
    
    if not username or not email:
        return Response({
            'success': False, 
            'message': 'Username and email required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    # In a real application, you might:
    # 1. Create a support ticket
    # 2. Send an email to admin
    # 3. Log the request
    
    try:
        # Example: Send email to admin
        admin_email = "admin@yourdomain.com"  # Should be in settings
        subject = f"Password Reset Assistance Request from {username}"
        message = f"""
        User {username} ({email}) has requested assistance with password reset.
        
        Please contact them to help with the reset process.
        """
        
        send_mail(
            subject,
            message,
            settings.DEFAULT_FROM_EMAIL,
            [admin_email],
            fail_silently=False,
        )
        
        logger.info(f"Admin notified about password reset assistance for {username}")
        
        return Response({
            'success': True, 
            'message': 'Support request submitted successfully!'
        })
    
    except Exception as e:
        logger.error(f"Failed to contact admin: {str(e)}")
        return Response({
            'success': False, 
            'message': 'Failed to submit support request. Please try again.'
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([AllowAny])
def reset_password(request):
    """
    Reset user password with OTP verification
    """
    serializer = PasswordResetSerializer(data=request.data)
    if not serializer.is_valid():
        return Response({
            'success': False, 
            'message': 'Invalid data',
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)
    
    otp = serializer.validated_data['otp']
    password = serializer.validated_data['password']
    
    # Get username from session or request
    username = request.data.get('username')
    if not username:
        return Response({
            'success': False, 
            'message': 'Username required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        return Response({
            'success': False, 
            'message': 'User not found'
        }, status=status.HTTP_404_NOT_FOUND)
    
    # Check OTP validity
    try:
        otp_instance = PasswordRecoveryOTP.objects.get(
            user=user, 
            otp=otp,
            is_used=False
        )
        
        if not otp_instance.is_valid():
            return Response({
                'success': False, 
                'message': 'OTP has expired or is invalid'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Set new password
        user.set_password(password)
        user.save()
        
        # Mark OTP as used
        otp_instance.is_used = True
        otp_instance.save()
        
        logger.info(f"Password reset successfully for user {username}")
        
        return Response({
            'success': True, 
            'message': 'Password successfully reset!'
        })
    
    except PasswordRecoveryOTP.DoesNotExist:
        return Response({
            'success': False, 
            'message': 'Invalid OTP'
        }, status=status.HTTP_400_BAD_REQUEST)