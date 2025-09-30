from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.contrib.auth import authenticate, login, get_user_model
import requests
import logging
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from .serializers import (
    UserRegisterSerializer,
    UserProfileSerializer,
    UserUpdateSerializer,
)
from .auth0 import Auth0JSONWebTokenAuthentication

# Initialize loggers
logger = logging.getLogger('users')
auth_logger = logging.getLogger('auth')

User = get_user_model()


@method_decorator(csrf_exempt, name="dispatch")
class UserRegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserRegisterSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        email = request.data.get('email')
        logger.info(f"User registration attempt for email: {email}")
        
        try:
            response = super().create(request, *args, **kwargs)
            logger.info(f"User registered successfully: {email}")
            return response
        except Exception as e:
            logger.error(f"User registration failed for {email}: {str(e)}")
            raise


class UserProfileView(generics.RetrieveAPIView):
    serializer_class = UserProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        logger.info(f"User profile accessed by: {self.request.user.email}")
        return self.request.user


class UserUpdateView(generics.UpdateAPIView):
    serializer_class = UserUpdateSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        logger.info(f"User profile update attempt by: {request.user.email}")
        try:
            response = super().update(request, *args, **kwargs)
            logger.info(f"User profile updated successfully: {request.user.email}")
            return response
        except Exception as e:
            logger.error(f"User profile update failed for {request.user.email}: {str(e)}")
            raise


class AuthCheckView(APIView):
    authentication_classes = [Auth0JSONWebTokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        auth_logger.info(f"Auth check successful for user: {request.user}")
        return Response({"message": "Auth0 JWT verified!", "user": str(request.user)})


class LoginView(APIView):
    authentication_classes = []
    permission_classes = []

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")
        
        auth_logger.info(f"Login attempt for email: {email}")

        if not email or not password:
            auth_logger.warning(f"Login failed: Missing credentials for {email}")
            return Response(
                {"error": "Email and password are required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        user = authenticate(request, username=email, password=password)
        if not user:
            auth_logger.warning(f"Login failed: Invalid credentials for {email}")
            return Response(
                {"error": "Invalid email or password"},
                status=status.HTTP_401_UNAUTHORIZED
            )

        login(request, user)
        auth_logger.info(f"User authenticated successfully: {email}")

        # 1. Request access token from Auth0
        token_url = f"https://{settings.AUTH0_DOMAIN}/oauth/token"
        payload = {
            "grant_type": "client_credentials",
            "client_id": settings.AUTH0_CLIENT_ID,
            "client_secret": settings.AUTH0_CLIENT_SECRET,
            "audience": settings.API_IDENTIFIER
        }

        try:
            resp = requests.post(token_url, json=payload)
            data = resp.json()
            
            if resp.status_code != 200:
                auth_logger.error(f"Auth0 token request failed for {email}: {data}")
                return Response(data, status=resp.status_code)
            
            auth_logger.info(f"Auth0 token obtained successfully for {email}")
        except Exception as e:
            auth_logger.error(f"Auth0 token request error for {email}: {str(e)}")
            return Response(
                {"error": "Failed to obtain Auth0 token"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        # 2. Issue Django refresh token
        refresh = RefreshToken.for_user(user)

        # 3. Sync local user info
        local_user, created = User.objects.update_or_create(
            email=email,
            defaults={"username": user.username}
        )
        
        if created:
            auth_logger.info(f"New local user created: {email}")
        else:
            auth_logger.info(f"Existing local user updated: {email}")

        auth_logger.info(f"Login successful for user: {email}")
        
        return Response({
            "access_token": data["access_token"],
            "refresh_token": str(refresh),
            "token_type": data.get("token_type", "Bearer"),
            "user": {
                "id": local_user.id,
                "username": local_user.username,
                "email": local_user.email
            }
        }, status=status.HTTP_200_OK)


class RefreshTokenView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        refresh_token = request.data.get("refresh_token")
        
        auth_logger.info("Refresh token request received")
        
        if not refresh_token:
            auth_logger.warning("Refresh token request failed: Missing token")
            return Response(
                {"error": "Refresh token is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # 1. Validate refresh token locally
            refresh = RefreshToken(refresh_token)
            user = User.objects.get(id=refresh["user_id"])
            
            auth_logger.info(f"Refresh token validated for user: {user.email}")

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
                auth_logger.error(f"Auth0 token refresh failed for {user.email}: {data}")
                return Response(data, status=resp.status_code)
            
            auth_logger.info(f"New Auth0 token obtained for {user.email}")

            # 3. Issue a new local refresh token
            new_refresh = RefreshToken.for_user(user)
            
            auth_logger.info(f"Token refresh successful for user: {user.email}")

            return Response({
                "access_token": data["access_token"],
                "refresh_token": str(new_refresh),
                "token_type": data.get("token_type", "Bearer"),
            }, status=status.HTTP_200_OK)

        except Exception as e:
            auth_logger.error(f"Token refresh failed: {str(e)}")
            return Response(
                {"error": f"Invalid refresh token: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )


class VerifyTokenView(APIView):
    authentication_classes = [Auth0JSONWebTokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        auth_logger.info(f"Token verification successful for user: {request.user}")
        return Response({"valid": True}, status=status.HTTP_200_OK)


class ValidateTokenView(APIView):
    authentication_classes = [Auth0JSONWebTokenAuthentication]
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user
        auth_logger.info(f"Token validation successful for user: {user.email}")
        return Response({
            "id": user.id,
            "username": user.username,
            "email": user.email,
        }, status=status.HTTP_200_OK)