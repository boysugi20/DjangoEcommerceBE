"""
URL configuration for ecommerce_backend project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
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
from django.urls import path, re_path, include
from users.views import *

urlpatterns = [
    path('admin/', admin.site.urls),
    re_path(r'^auth/register/?$', RegistrationAPIView.as_view(), name='user_register'),
    re_path(r'^auth/login/?$', LoginAPIView.as_view(), name='user_login'),
    re_path(r'^auth/logout/?$', LogoutView.as_view(), name='user_logout'),
    re_path(r'^auth/change-password/?$', ChangePasswordView.as_view(), name='user_pass_change'),
    re_path(r'^auth/forgot-password/?$', ForgotPasswordView.as_view(), name='user_pass_forgot'),
]