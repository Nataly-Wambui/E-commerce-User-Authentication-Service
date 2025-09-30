from django.contrib import admin
from django.urls import path, include, re_path
from django.http import JsonResponse  # ✅ Use JsonResponse
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
    openapi.Info(
        title="User Auth Service API",
        default_version="v1",
        description="API documentation for User Authentication Service",
        contact=openapi.Contact(email="support@example.com"),
    ),
    public=True,
    permission_classes=[permissions.AllowAny],
)

# ✅ JSON response for home
def home(request):
    return JsonResponse({
        "message": "Welcome to the User Auth Service API!",
        "docs": {
            "swagger": "/swagger/",
            "redoc": "/redoc/"
        },
        "endpoints": {
            "users": "/api/users/"
        }
    })

urlpatterns = [
    path("", home, name="home"),  # 👈 Root endpoint
    path("admin/", admin.site.urls),
    path("api/users/", include("users.urls")),

    # Swagger / ReDoc endpoints
    re_path(
        r"^swagger(?P<format>\.json|\.yaml)$",
        schema_view.without_ui(cache_timeout=0),
        name="schema-json",
    ),
    path(
        "swagger/",
        schema_view.with_ui("swagger", cache_timeout=0),
        name="schema-swagger-ui",
    ),
    path(
        "redoc/",
        schema_view.with_ui("redoc", cache_timeout=0),
        name="schema-redoc",
    ),
]
