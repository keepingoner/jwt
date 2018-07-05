# -*- coding: utf-8 -*-

import jwt

from django.contrib.auth import get_user_model
from django.utils.encoding import smart_text
from django.utils.translation import ugettext as _
from rest_framework import exceptions

from rest_framework.authentication import (
    BaseAuthentication, get_authorization_header
)
from mongoengine import *

connect('db_core')


class TbUser(Document):
    username = StringField(required=True, max_length=200)
    pwd = StringField(required=False, max_length=200)
    _id = StringField(required=True, max_length=200)
    create_time = StringField(required=True, max_length=200)
    user_id = StringField(required=True, max_length=200)
    is_active = StringField(required=False, max_length=200)


from rest_framework_jwt.settings import api_settings

from rest_framework_jwt.utils import jwt_decode_handler


# jwt_decode_handler = api_settings.JWT_DECODE_HANDLER

jwt_get_username_from_payload = api_settings.JWT_PAYLOAD_GET_USERNAME_HANDLER

import jwt
import uuid
import warnings

from django.contrib.auth import get_user_model

from calendar import timegm
from datetime import datetime


from rest_framework_jwt.compat import get_username
from rest_framework_jwt.compat import get_username_field
from rest_framework_jwt.settings import api_settings



"""----------"""
def jwt_decode_handler(token):
    options = {
        'verify_exp': api_settings.JWT_VERIFY_EXPIRATION,
    }
    # get user from token, BEFORE verification, to get user secret key
    unverified_payload = jwt.decode(token, None, False)
    secret_key = jwt_get_secret_key(unverified_payload)
    return jwt.decode(
        token,
        api_settings.JWT_PUBLIC_KEY or secret_key,
        api_settings.JWT_VERIFY,
        options=options,
        leeway=api_settings.JWT_LEEWAY,
        audience=api_settings.JWT_AUDIENCE,
        issuer=api_settings.JWT_ISSUER,
        algorithms=[api_settings.JWT_ALGORITHM]
    )

def jwt_get_secret_key(payload=None):
    """
    For enhanced security you may want to use a secret key based on user.

    This way you have an option to logout only this user if:
        - token is compromised
        - password is changed
        - etc.
    """
    if api_settings.JWT_GET_USER_SECRET_KEY:
        User = get_user_model()  # noqa: N806
        user = User.objects.get(pk=payload.get('user_id'))
        key = str(api_settings.JWT_GET_USER_SECRET_KEY(user))
        return key
    return api_settings.JWT_SECRET_KEY


class BaseJSONWebTokenAuthentication(BaseAuthentication):

    def get_jwt_value(self, request):
        auth = get_authorization_header(request).split()
        auth_header_prefix = api_settings.JWT_AUTH_HEADER_PREFIX.lower()

        if not auth:
            if api_settings.JWT_AUTH_COOKIE:
                return request.COOKIES.get(api_settings.JWT_AUTH_COOKIE)
            return None

        if smart_text(auth[0].lower()) != auth_header_prefix:
            return None

        if len(auth) == 1:
            msg = _('Invalid Authorization header. No credentials provided.')
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid Authorization header. Credentials string '
                    'should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        return auth[1]




    def authenticate(self, request):
        """
        Returns a two-tuple of `User` and token if a valid signature has been
        supplied using JWT-based authentication.  Otherwise returns `None`.
        """
        jwt_value = self.get_jwt_value(request)
        if jwt_value is None:
            return None

        try:
            payload = jwt_decode_handler(jwt_value)
        except jwt.ExpiredSignature:
            msg = _('Signature has expired.')
            raise exceptions.AuthenticationFailed(msg)
        except jwt.DecodeError:
            msg = _('Error decoding signature.')
            raise exceptions.AuthenticationFailed(msg)
        except jwt.InvalidTokenError:
            raise exceptions.AuthenticationFailed()

        user = self.authenticate_credentials(payload)

        return (user, jwt_value)


    def authenticate_credentials(self, payload):
        """
        Returns an active user that matches the payload's user id and email.
        """
        User = TbUser.objects
        username = jwt_get_username_from_payload(payload)

        if not username:
            msg = _('Invalid payload.')
            raise exceptions.AuthenticationFailed(msg)

        try:
            users = TbUser.objects
            for i in users:
                if i.username == username :
                    return i
        except Exception as e:
            print e

        #     user = TbUser.objects.get_by_natural_key(username)
        # except User.DoesNotExist:
            msg = _('Invalid signature.')
            raise exceptions.AuthenticationFailed(msg)
        #
        # if not user.is_active:
        #     msg = _('User account is disabled.')
        #     raise exceptions.AuthenticationFailed(msg)
        # return user


class JSONWebTokenAuthentication(BaseJSONWebTokenAuthentication):
    """
    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string specified in the setting
    `JWT_AUTH_HEADER_PREFIX`. For example:

        Authorization: JWT eyJhbGciOiAiSFMyNTYiLCAidHlwIj
    """
    www_authenticate_realm = 'api'

    def get_jwt_value(self, request):
        auth = get_authorization_header(request).split()
        auth_header_prefix = api_settings.JWT_AUTH_HEADER_PREFIX.lower()

        if not auth:
            if api_settings.JWT_AUTH_COOKIE:
                return request.COOKIES.get(api_settings.JWT_AUTH_COOKIE)
            return None

        if smart_text(auth[0].lower()) != auth_header_prefix:
            return None

        if len(auth) == 1:
            msg = _('Invalid Authorization header. No credentials provided.')
            raise exceptions.AuthenticationFailed(msg)
        elif len(auth) > 2:
            msg = _('Invalid Authorization header. Credentials string '
                    'should not contain spaces.')
            raise exceptions.AuthenticationFailed(msg)

        return auth[1]

    def authenticate_header(self, request):
        """
        Return a string to be used as the value of the `WWW-Authenticate`
        header in a `401 Unauthenticated` response, or `None` if the
        authentication scheme should return `403 Permission Denied` responses.
        """
        return '{0} realm="{1}"'.format(api_settings.JWT_AUTH_HEADER_PREFIX, self.www_authenticate_realm)


