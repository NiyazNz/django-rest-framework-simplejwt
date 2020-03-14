import time
from datetime import datetime, timedelta

from django.middleware import csrf
from django.utils.translation import ugettext_lazy as _
from django.utils import timezone
from django.utils.http import http_date
from rest_framework import generics, status
from rest_framework.exceptions import NotAuthenticated
from rest_framework.response import Response as R
from rest_framework.reverse import reverse
from rest_framework.views import APIView

from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.tokens import RefreshToken
from . import serializers
from .authentication import AUTH_HEADER_TYPES
from .exceptions import InvalidToken, TokenError

#Need to set samesite to None. (Available in django 3.1)
class Response(R):

     def set_cookie(self, key, value='', max_age=None, expires=None, path='/',
                   domain=None, secure=False, httponly=False, samesite=None):
        """
        Set a cookie.
        ``expires`` can be:
        - a string in the correct format,
        - a naive ``datetime.datetime`` object in UTC,
        - an aware ``datetime.datetime`` object in any time zone.
        If it is a ``datetime.datetime`` object then calculate ``max_age``.
        """
        self.cookies[key] = value
        if expires is not None:
            if isinstance(expires, datetime):
                if timezone.is_aware(expires):
                    expires = timezone.make_naive(expires, timezone.utc)
                delta = expires - expires.utcnow()
                # Add one second so the date matches exactly (a fraction of
                # time gets lost between converting to a timedelta and
                # then the date string).
                delta = delta + timedelta(seconds=1)
                # Just set max_age - the max_age logic will set expires.
                expires = None
                max_age = max(0, delta.days * 86400 + delta.seconds)
            else:
                self.cookies[key]['expires'] = expires
        else:
            self.cookies[key]['expires'] = ''
        if max_age is not None:
            self.cookies[key]['max-age'] = max_age
            # IE requires expires, so set it if hasn't been already.
            if not expires:
                self.cookies[key]['expires'] = http_date(time.time() + max_age)
        if path is not None:
            self.cookies[key]['path'] = path
        if domain is not None:
            self.cookies[key]['domain'] = domain
        if secure:
            self.cookies[key]['secure'] = True
        if httponly:
            self.cookies[key]['httponly'] = True
        if samesite:
            if samesite.lower() not in ('lax', 'none', 'strict'):
                raise ValueError('samesite must be "lax", "none", or "strict".')
            self.cookies[key]['samesite'] = samesite


class TokenViewBase(generics.GenericAPIView):
    permission_classes = ()
    authentication_classes = ()

    serializer_class = None

    www_authenticate_realm = 'api'

    def get_authenticate_header(self, request):
        return '{0} realm="{1}"'.format(
            AUTH_HEADER_TYPES[0],
            self.www_authenticate_realm,
        )

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as e:
            raise InvalidToken(e.args[0])

        response = Response(serializer.validated_data, status=status.HTTP_200_OK)

        if api_settings.AUTH_COOKIE:
            csrf.get_token(self.request)
            response = self.set_auth_cookies(response, serializer.validated_data)

        return response

    def set_auth_cookies(self, response, data):
        return response


class TokenRefreshViewBase(TokenViewBase):
    def extract_token_from_cookie(self, request):
        return request

    def post(self, request, *args, **kwargs):
        if api_settings.AUTH_COOKIE:
            request = self.extract_token_from_cookie(request)
        return super().post(request, *args, **kwargs)


class TokenCookieViewMixin:
    token_refresh_view_name = 'token_refresh'

    def extract_token_from_cookie(self, request):
        """Extracts token from cookie and sets it in request.data as it would be sent by the user"""
        if not request.data:
            token = request.COOKIES.get('{}_refresh'.format(api_settings.AUTH_COOKIE))
            if not token:
                raise NotAuthenticated(detail=_('Refresh cookie not set. Try to authenticate first.'))
            else:
                request.data['refresh'] = token
        return request

    def set_auth_cookies(self, response, data):
        expires = self.get_refresh_token_expiration()
        response.set_cookie(
            api_settings.AUTH_COOKIE, data['access'],
            expires=expires,
            domain=api_settings.AUTH_COOKIE_DOMAIN,
            path=api_settings.AUTH_COOKIE_PATH,
            secure=api_settings.AUTH_COOKIE_SECURE or None,
            httponly=True,
            samesite=api_settings.AUTH_COOKIE_SAMESITE,
        )
        if 'refresh' in data:
            response.set_cookie(
                '{}_refresh'.format(api_settings.AUTH_COOKIE), data['refresh'],
                expires=expires,
                domain=None,
                path=reverse(self.token_refresh_view_name),
                secure=api_settings.AUTH_COOKIE_SECURE or None,
                httponly=True,
                samesite=api_settings.AUTH_COOKIE_SAMESITE,
            )
        return response

    def get_refresh_token_expiration(self):
        return datetime.now() + api_settings.REFRESH_TOKEN_LIFETIME


class TokenObtainPairView(TokenCookieViewMixin, TokenViewBase):
    """
    Takes a set of user credentials and returns an access and refresh JSON web
    token pair to prove the authentication of those credentials.
    """
    serializer_class = serializers.TokenObtainPairSerializer


token_obtain_pair = TokenObtainPairView.as_view()


class TokenRefreshView(TokenCookieViewMixin, TokenRefreshViewBase):
    """
    Takes a refresh type JSON web token and returns an access type JSON web
    token if the refresh token is valid.
    """
    serializer_class = serializers.TokenRefreshSerializer

    def get_refresh_token_expiration(self):
        if api_settings.ROTATE_REFRESH_TOKENS:
            return super().get_refresh_token_expiration()
        token = RefreshToken(self.request.data['refresh'])
        return datetime.fromtimestamp(token.payload['exp'])


token_refresh = TokenRefreshView.as_view()


class SlidingTokenCookieViewMixin:
    def extract_token_from_cookie(self, request):
        """Extracts token from cookie and sets it in request.data as it would be sent by the user"""
        if not request.data:
            token = request.COOKIES.get(api_settings.AUTH_COOKIE)
            if not token:
                raise NotAuthenticated(detail=_('Refresh cookie not set. Try to authenticate first.'))
            else:
                request.data['token'] = token
        return request

    def set_auth_cookies(self, response, data):
        response.set_cookie(
            api_settings.AUTH_COOKIE, data['token'],
            expires=datetime.now() + api_settings.REFRESH_TOKEN_LIFETIME,
            domain=api_settings.AUTH_COOKIE_DOMAIN,
            path=api_settings.AUTH_COOKIE_PATH,
            secure=api_settings.AUTH_COOKIE_SECURE or None,
            httponly=True,
            samesite=api_settings.AUTH_COOKIE_SAMESITE,
        )
        return response


class TokenObtainSlidingView(SlidingTokenCookieViewMixin, TokenViewBase):
    """
    Takes a set of user credentials and returns a sliding JSON web token to
    prove the authentication of those credentials.
    """
    serializer_class = serializers.TokenObtainSlidingSerializer


token_obtain_sliding = TokenObtainSlidingView.as_view()


class TokenRefreshSlidingView(SlidingTokenCookieViewMixin, TokenRefreshViewBase):
    """
    Takes a sliding JSON web token and returns a new, refreshed version if the
    token's refresh period has not expired.
    """
    serializer_class = serializers.TokenRefreshSlidingSerializer


token_refresh_sliding = TokenRefreshSlidingView.as_view()


class TokenVerifyView(TokenViewBase):
    """
    Takes a token and indicates if it is valid.  This view provides no
    information about a token's fitness for a particular use.
    """
    serializer_class = serializers.TokenVerifySerializer


token_verify = TokenVerifyView.as_view()


class TokenCookieDeleteView(APIView):
    """
    Deletes httpOnly auth cookies.
    Used as logout view while using AUTH_COOKIE
    """
    token_refresh_view_name = 'token_refresh'
    authentication_classes = ()
    permission_classes = ()

    def post(self, request):
        response = Response({})

        if api_settings.AUTH_COOKIE:
            self.delete_auth_cookies(response)

        return response

    def delete_auth_cookies(self, response):
        response.delete_cookie(
            api_settings.AUTH_COOKIE,
            domain=api_settings.AUTH_COOKIE_DOMAIN,
            path=api_settings.AUTH_COOKIE_PATH
        )
        response.delete_cookie(
            '{}_refresh'.format(api_settings.AUTH_COOKIE),
            domain=None,
            path=reverse(self.token_refresh_view_name),
        )


token_delete = TokenCookieDeleteView.as_view()
