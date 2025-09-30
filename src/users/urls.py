from django.urls import path
from .views import (
    UserRegisterView,
    UserProfileView,
    UserUpdateView,
    AuthCheckView,
    LoginView,
    RefreshTokenView,
    ValidateTokenView,
    VerifyTokenView,
)

urlpatterns = [
    path('register/', UserRegisterView.as_view(), name='user-register'),
    path('profile/', UserProfileView.as_view(), name='user-profile'),
    path('profile/update/', UserUpdateView.as_view(), name='user-update'),
    path('auth-check/', AuthCheckView.as_view(), name='auth-check'),
    path('refresh-token/', RefreshTokenView.as_view(), name='refresh-token'),
    path("verify-token/", VerifyTokenView.as_view(), name="verify-token"),
    path("validate-token/", ValidateTokenView.as_view(), name="validate-token"),
    path('login/', LoginView.as_view(), name='auth-login'),  # 👈 new
]
