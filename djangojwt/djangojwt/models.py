# -*- coding: utf-8 -*-
from django.http import HttpResponse
from mongoengine import *

connect('db_core')
class TbUser(Document):
    user_name = StringField(required=True, max_length=200)
    pwd = StringField(required=False, max_length=200)
    _id = StringField(required=True, max_length=200)
    create_time = StringField(required=True, max_length=200)
    user_id = StringField(required=True, max_length=200)
    is_active = StringField(required=False, max_length=200)


from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.serializers import Serializer
from rest_framework.generics import ListAPIView
from django.contrib.auth.models import User

def api_jwt(func):
    def refunc(self, *args, **kwargs):
        from django.http import JsonResponse
        resp_data = {"a": "no token"}
        json_resp = JsonResponse(resp_data)
        jwt_user = self.request.user
        jwt_auth = self.request.auth
        if jwt_user == None or jwt_auth == None:
            return json_resp
        return func(self, *args, **kwargs)
    return refunc

"""---------------"""


from rest_framework.permissions import IsAuthenticated
class HeHe(APIView):
    def get(self, request):
        print 132
        return Response({"a": 1})

    @api_jwt
    def post(self, request):
        try:
            auth_d = request.user
            fd = request.auth
            print auth_d


            print fd
        except Exception as e:
            print e
        finally:
            return Response({"a":1})




