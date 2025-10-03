# views.py
from django.shortcuts import render, redirect
from django.contrib import messages
from django.utils import timezone
from django.contrib.auth.hashers import make_password
from django.contrib.auth import authenticate, login
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.conf import settings
from twilio.rest import Client
import logging

from .models import UserAccount, PasswordRecoveryOTP
from .serializers import (
    UserCheckSerializer, 
    PhoneSerializer, 
    OTPSerializer, 
    PasswordResetSerializer
)

logger = logging.getLogger(__name__)

# Template-based views (Django views)
def registration_page(request):
    context = {
        'username': '',
        'first_name': '',
        'last_name': '',
        'email': '',
        'phone_number': '',
    }

    if request.method == 'POST':
        username = request.POST.get("username")
        first_name = request.POST.get("first_name")
        last_name = request.POST.get("last_name")
        email = request.POST.get("email")
        phone_number = request.POST.get("phone_number")

        context.update({
            'username': username,
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'phone_number': phone_number,
        })

        # Check if email already exists
        if UserAccount.objects.filter(email=email).exists():
            messages.error(request, "Email address already exists, kindly login or try via another email.", extra_tags="emailexist")
            return render(request=request, template_name='accounts/registrationtemp.html', context=context)
        
        # Check if username already exists
        if UserAccount.objects.filter(username=username).exists():
            messages.error(request, "Username is already taken, try another", extra_tags="usernameexist")
            return render(request=request, template_name='accounts/registrationtemp.html', context=context)
        
        # Store registration data in session for verification step
        request.session['registration_data'] = {
            'username': username,
            'first_name': first_name,
            'last_name': last_name,
            'email': email,
            'phone_number': phone_number,
        }
        return redirect('/verification')
    
    return render(request=request, template_name='accounts/registrationtemp.html', context=context)

def verification_page(request):
    registration_data = request.session.get('registration_data')
    
    if not registration_data:
        messages.error(request, "Registration data not found. Please start over.")
        return redirect('/register')

    if request.method == 'POST':
        phone_otp = request.POST.get("phone_otp")
        email_otp = request.POST.get("email_otp")
        password = request.POST.get("password")
        
        # In production, replace with actual OTP validation
        if phone_otp != "111111" or email_otp != "222222":
            messages.error(request, "Invalid OTP entered.")
            return render(request, 'accounts/verificationtemp.html', {
                'email': registration_data['email'],
                'phone_number': registration_data['phone_number'],
                'has_phone': bool(registration_data['phone_number']),
            })

        # Create and save the user
        user = UserAccount(
            username=registration_data['username'],
            first_name=registration_data['first_name'],
            last_name=registration_data['last_name'],
            email=registration_data['email'],
            phone_number=registration_data['phone_number'],
            password=make_password(password),
            date_joined=timezone.now(),
        )
        user.save()

        messages.success(request, "Registration successful, kindly sign in.", extra_tags="registrationsuccessful")
        request.session.pop('registration_data', None)
        return redirect('/login')

    return render(request, 'accounts/verificationtemp.html', {
        'email': registration_data['email'],
        'phone_number': registration_data['phone_number'],
        'has_phone': bool(registration_data['phone_number']),
    })

def login_page(request):
    context = {
        "credential": '',
    }

    if request.method == "POST":
        credential = request.POST.get("credential")
        password = request.POST.get("password")

        # Determine if credential is email or username
        if "@" in credential:
            try:
                user_object = UserAccount.objects.get(email=credential)
                user = authenticate(request, username=user_object.username, password=password)
                context.update({"credential": credential})
            except UserAccount.DoesNotExist:
                user = None
        else:
            user = authenticate(request, username=credential, password=password)
            context.update({"credential": credential})

        if user is not None:
            login(request, user)
            return redirect('home')
        else:
            messages.error(request, "Invalid username or password", extra_tags="usernotexist")
            return render(request, 'accounts/logintemp.html', context={"credential": credential})
        
    return render(request, 'accounts/logintemp.html')

def reset_password_page(request):
    return render(request, 'accounts/reset_passwordtemp.html')

def forgot_password_page(request):
    return render(request, 'accounts/forgot_passwordtemp.html')

def home_page(request):
    return render(request, 'accounts/hometemp.html')

# API views (DRF views)
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
            user = UserAccount.objects.get(username=username, email=email)
            return Response({
                'success': True, 
                'message': 'User verified successfully',
                'user_id': user.id
            })
        except UserAccount.DoesNotExist:
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
    username = request.data.get('username')
    if not username:
        return Response({
            'success': False, 
            'message': 'Username required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = UserAccount.objects.get(username=username)
    except UserAccount.DoesNotExist:
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
            'otp': otp_instance.otp  # Remove this in production
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
        user = UserAccount.objects.get(username=username, email=email)
    except UserAccount.DoesNotExist:
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
            'otp': otp_instance.otp  # Remove this in production
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
    Handle contact admin request for password reset assistance
    """
    username = request.data.get('username')
    email = request.data.get('email')
    
    if not username or not email:
        return Response({
            'success': False, 
            'message': 'Username and email required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        # Send email to admin
        admin_email = getattr(settings, 'ADMIN_EMAIL', 'admin@yourdomain.com')
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
    
    # Get username from request
    username = request.data.get('username')
    if not username:
        return Response({
            'success': False, 
            'message': 'Username required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = UserAccount.objects.get(username=username)
    except UserAccount.DoesNotExist:
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

@api_view(['POST'])
@permission_classes([AllowAny])
def verify_otp(request):
    """
    Verify OTP for registration or password reset
    """
    otp = request.data.get('otp')
    username = request.data.get('username')
    purpose = request.data.get('purpose', 'registration')  # 'registration' or 'password_reset'
    
    if not otp or not username:
        return Response({
            'success': False,
            'message': 'OTP and username required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = UserAccount.objects.get(username=username)
        
        # For registration, you might want to store OTP differently
        if purpose == 'registration':
            # Simple verification for demo (replace with actual OTP validation)
            if otp in ['111111', '222222']:  # Demo OTPs
                return Response({
                    'success': True,
                    'message': 'OTP verified successfully'
                })
            else:
                return Response({
                    'success': False,
                    'message': 'Invalid OTP'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        # For password reset, use PasswordRecoveryOTP model
        elif purpose == 'password_reset':
            otp_instance = PasswordRecoveryOTP.objects.get(
                user=user,
                otp=otp,
                is_used=False
            )
            
            if not otp_instance.is_valid():
                return Response({
                    'success': False,
                    'message': 'OTP has expired'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            return Response({
                'success': True,
                'message': 'OTP verified successfully'
            })
    
    except (UserAccount.DoesNotExist, PasswordRecoveryOTP.DoesNotExist):
        return Response({
            'success': False,
            'message': 'Invalid OTP or user'
        }, status=status.HTTP_400_BAD_REQUEST)
