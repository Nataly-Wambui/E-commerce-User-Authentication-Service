import json
import requests
from jose import jwt
from django.conf import settings
from rest_framework import authentication, exceptions

class Auth0JSONWebTokenAuthentication(authentication.BaseAuthentication):
    """
    Custom authentication class to validate Auth0 JWT access tokens.
    """

    def authenticate(self, request):
        auth_header = authentication.get_authorization_header(request).split()

        if not auth_header or auth_header[0].lower() != b"bearer":
            return None  # No token, move to the next authentication class

        if len(auth_header) == 1:
            raise exceptions.AuthenticationFailed("Invalid Authorization header. No credentials provided.")
        elif len(auth_header) > 2:
            raise exceptions.AuthenticationFailed("Invalid Authorization header. Token string should not contain spaces.")

        token = auth_header[1].decode("utf-8")

        try:
            payload = self.decode_jwt(token)
        except Exception as e:
            raise exceptions.AuthenticationFailed(f"Invalid token: {str(e)}")

        user_id = payload.get("sub")
        if not user_id:
            raise exceptions.AuthenticationFailed("Invalid payload: missing subject (sub) claim")

        # You could fetch a User from DB here or create a dummy one
        from django.contrib.auth import get_user_model
        User = get_user_model()
        user, _ = User.objects.get_or_create(username=user_id)

        return (user, None)

    def decode_jwt(self, token):
        jwks_url = f"https://{settings.AUTH0_DOMAIN}/.well-known/jwks.json"
        jwks = requests.get(jwks_url).json()

        unverified_header = jwt.get_unverified_header(token)

        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"],
                }
        if not rsa_key:
            raise exceptions.AuthenticationFailed("Unable to find appropriate key.")

        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=[settings.ALGORITHMS],
            audience=settings.API_IDENTIFIER,
            issuer=f"https://{settings.AUTH0_DOMAIN}/",
        )
        return payload
