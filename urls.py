# urls.py
from django.urls import path
from . import views

urlpatterns = [
    # Template URLs (Frontend Pages)
    path('register/', views.registration_page, name='register'),
    path('login/', views.login_page, name='login'),
    path('verification/', views.verification_page, name='verification'),
    path('reset-password/', views.reset_password_page, name='reset_password'),
    path('forgot-password/', views.forgot_password_page, name='forgot_password'),
    path('home/', views.home_page, name='home'),
    
    # API URLs (Backend Endpoints)
    path('api/check-user/', views.check_user, name='api_check_user'),
    path('api/send-sms/', views.send_sms, name='api_send_sms'),
    path('api/send-email/', views.send_email, name='api_send_email'),
    path('api/contact-admin/', views.contact_admin, name='api_contact_admin'),
    path('api/reset-password/', views.reset_password, name='api_reset_password'),
    path('api/verify-otp/', views.verify_otp, name='api_verify_otp'),
]
