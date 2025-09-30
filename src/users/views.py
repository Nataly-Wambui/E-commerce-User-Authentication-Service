from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth import authenticate, login, get_user_model
import requests
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from .serializers import (
    UserRegisterSerializer,
    UserProfileSerializer,
    UserUpdateSerializer,
)
from .auth0 import Auth0JSONWebTokenAuthentication  # ✅ import your Auth0 authentication class

User = get_user_model()


@method_decorator(csrf_exempt, name="dispatch")
class UserRegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserRegisterSerializer
    permission_classes = [permissions.AllowAny]


class UserProfileView(generics.RetrieveAPIView):
    serializer_class = UserProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user


class UserUpdateView(generics.UpdateAPIView):
    serializer_class = UserUpdateSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user


class AuthCheckView(APIView):
    authentication_classes = [Auth0JSONWebTokenAuthentication]  # ✅ Auth0 tokens only
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        return Response({"message": "Auth0 JWT verified!", "user": str(request.user)})


class LoginView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")

        if not email or not password:
            return Response(
                {"error": "Email and password are required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        user = authenticate(request, username=email, password=password)
        if not user:
            return Response(
                {"error": "Invalid email or password"},
                status=status.HTTP_401_UNAUTHORIZED
            )

        login(request, user)

        # 1. Request access token from Auth0
        token_url = f"https://{settings.AUTH0_DOMAIN}/oauth/token"
        payload = {
            "grant_type": "client_credentials",
            "client_id": settings.AUTH0_CLIENT_ID,
            "client_secret": settings.AUTH0_CLIENT_SECRET,
            "audience": settings.API_IDENTIFIER
        }

        resp = requests.post(token_url, json=payload)
        data = resp.json()
        if resp.status_code != 200:
            return Response(data, status=resp.status_code)

        # 2. Issue Django refresh token
        refresh = RefreshToken.for_user(user)

        # 3. Sync local user info (optional)
        local_user, created = User.objects.update_or_create(
            email=email,
            defaults={"username": user.username}
        )

        return Response({
            "access_token": data["access_token"],   # From Auth0
            "refresh_token": str(refresh),          # From Django
            "token_type": data.get("token_type", "Bearer"),
            "user": {
                "id": local_user.id,
                "username": local_user.username,
                "email": local_user.email
            }
        }, status=status.HTTP_200_OK)


class RefreshTokenView(APIView):
    authentication_classes = [JWTAuthentication]  # ✅ Django refresh tokens
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get("refresh_token")
        if not refresh_token:
            return Response(
                {"error": "Refresh token is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # 1. Validate refresh token locally
            refresh = RefreshToken(refresh_token)
            user = User.objects.get(id=refresh["user_id"])

            # 2. Get new Auth0 access token
            token_url = f"https://{settings.AUTH0_DOMAIN}/oauth/token"
            payload = {
                "grant_type": "client_credentials",
                "client_id": settings.AUTH0_CLIENT_ID,
                "client_secret": settings.AUTH0_CLIENT_SECRET,
                "audience": settings.API_IDENTIFIER
            }
            resp = requests.post(token_url, json=payload)
            data = resp.json()
            if resp.status_code != 200:
                return Response(data, status=resp.status_code)

            # 3. Issue a new local refresh token
            new_refresh = RefreshToken.for_user(user)

            return Response({
                "access_token": data["access_token"],
                "refresh_token": str(new_refresh),
                "token_type": data.get("token_type", "Bearer"),
            }, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(
                {"error": f"Invalid refresh token: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )


# 🔑 Verify Token Endpoint (Auth0 access tokens)
class VerifyTokenView(APIView):
    authentication_classes = [Auth0JSONWebTokenAuthentication]  # ✅ Auth0 only
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        return Response({"valid": True}, status=status.HTTP_200_OK)


# 🔑 Validate Token and return user details (Auth0 access tokens)
class ValidateTokenView(APIView):
    authentication_classes = [Auth0JSONWebTokenAuthentication]  # ✅ Auth0 only
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({
            "id": user.id,
            "username": user.username,
            "email": user.email,
        }, status=status.HTTP_200_OK)
