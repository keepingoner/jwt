# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
from django.contrib.auth.backends import ModelBackend
# Create your models here.
from django.contrib.auth.models import User
from mongoengine import *
from rest_framework_jwt.authentication import JSONWebTokenAuthentication

connect('db_core')
from django.contrib.auth.models import AbstractUser

class TbUser(Document):
    username = StringField(required=True, max_length=200)
    pwd = StringField(required=False, max_length=200)
    _id = StringField(required=True, max_length=200)
    create_time = StringField(required=True, max_length=200)
    user_id = StringField(required=True, max_length=200)
    is_active = StringField(required=False, max_length=200)


class MyBackend(ModelBackend):
    def authenticate(self,username=None, password=None, **kwargs):
        try:
            if username is not None:
                users = TbUser.objects
                for i in users:
                    if i.username == username and i.pwd == password:
                        return i
        except Exception as e :
            print e
            return None



