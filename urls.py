# urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('api/check-user/', views.check_user, name='check_user'),
    path('api/send-sms/', views.send_sms, name='send_sms'),
    path('api/send-email/', views.send_email, name='send_email'),
    path('api/contact-admin/', views.contact_admin, name='contact_admin'),
    path('api/reset-password/', views.reset_password, name='reset_password'),
]