"""djangojwt URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url
from django.contrib import admin
from models import HeHe
from rest_framework_jwt.views import obtain_jwt_token, verify_jwt_token, refresh_jwt_token
from .views import MyVerify
urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'hehe/',HeHe.as_view()),
    url(r'^login/$', obtain_jwt_token, name='login'),
    url(r'^verify/$', MyVerify.as_view()),
    url(r'^refresh/$', refresh_jwt_token),

]
