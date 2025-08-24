"""
URL configuration for system project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from core import views

urlpatterns = [
    path('admin/', admin.site.urls),
    # MSP Admin
    path('msp_specialist/', views.msp_specialist, name='msp_specialist'),
    path('', views.msp_home, name='home'),
    path('apply/submit/', views.submit_synergy_application, name='submit_synergy_application'),

    path('leads/add/', views.submit_lead, name='add_lead'),

    path('approve_synergy_application/<int:application_id>/', views.approve_synergy_application, name='approve_synergy_application'),
    path('reject_synergy_application/<int:application_id>/', views.reject_synergy_application, name='reject_synergy_application'),

    path('convert_lead_to_client/<int:lead_id>/', views.convert_lead_to_client, name='convert_lead_to_client'),
    path('drop_lead/<int:lead_id>/', views.drop_lead, name='drop_lead'),

    path('upload_resource/', views.upload_resource, name='upload_resource'),
    path('delete_resource/<int:resource_id>/', views.delete_resource, name='delete_resource'),
    path('delete_announcement/<int:announcement_id>/', views.delete_announcement, name='delete_announcement'),
    path('add_announcement/', views.add_announcement, name='add_announcement'),
    path('assign_users/', views.assign_users, name='assign_users'),
    path('assign_lead_position/<int:user_id>/', views.assign_lead_position, name='assign_lead_position'),
    path('assign_cas_position/<int:user_id>/', views.assign_cas_position, name='assign_cas_position'),

    path("chat_app/", views.chat_app, name="chat_app"),
    path("email_app/", views.email_app, name="email_app"),
    path("contacts/add/", views.add_contact, name="add_contact"),
    path("emails/add/", views.add_email, name="add_email"),
    path("emails/<int:contact_id>/messages/", views.get_emails, name="get_emails"),
    path("emails/<int:contact_id>/send/", views.send_email, name="send_email"),

    path("contacts/<int:contact_id>/send/", views.send_message, name="send_message"),
    path("contacts/<int:contact_id>/messages/", views.get_messages, name="get_messages"),
    path("webhook/whatsapp/", views.whatsapp_webhook, name="whatsapp_webhook"),

    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('forgotpassword/', views.forgot_password, name='forgot_Password'),
    path('reset_password/<str:uidb64>/<str:token>/', views.PasswordResetConfirmView.as_view(), name='reset_password'),
]
