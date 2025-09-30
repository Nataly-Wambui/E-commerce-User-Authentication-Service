from django.contrib.auth.models import AbstractUser
from django.db import models

class User(AbstractUser):
    email = models.EmailField(unique=True)

    USERNAME_FIELD = 'email'      # Use email for authentication
    REQUIRED_FIELDS = ['username']  # Still require username for Django admin

    def __str__(self):
        return self.email
