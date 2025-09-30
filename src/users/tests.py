
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from unittest.mock import patch, MagicMock


class UserLoginTests(APITestCase):
    def setUp(self):
        self.login_url = reverse('user-login')
        self.user = UserLoginTests.objects.create(
            email='test@example.com',
            auth0_user_id='auth0|123456789',
            first_name='John',
            last_name='Doe'
        )

    @patch('auth_service.api.views.requests.post')
    def test_login_success(self, mock_post):
        """Test successful login with Auth0"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'access_token': 'mock_access_token',
            'refresh_token': 'mock_refresh_token',
            'expires_in': 3600,
            'token_type': 'Bearer'
        }
        mock_post.return_value = mock_response

        login_payload = {
            'email': 'test@example.com',
            'password': 'testpassword123'
        }

        response = self.client.post(self.login_url, login_payload, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access_token', response.data)
        self.assertIn('refresh_token', response.data)
        self.assertIn('expires_in', response.data)

    @patch('auth_service.api.views.requests.post')
    def test_login_invalid_credentials(self, mock_post):
        """Test login fails with invalid credentials"""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.json.return_value = {
            'error': 'invalid_grant',
            'error_description': 'Wrong email or password.'
        }
        mock_post.return_value = mock_response

        login_payload = {
            'email': 'test@example.com',
            'password': 'wrongpassword'
        }

        response = self.client.post(self.login_url, login_payload, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('error', response.data)

    @patch('auth_service.api.views.requests.post')
    def test_login_nonexistent_user(self, mock_post):
        """Test login fails with non-existent user"""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.json.return_value = {
            'error': 'invalid_grant',
            'error_description': 'User does not exist.'
        }
        mock_post.return_value = mock_response

        login_payload = {
            'email': 'nonexistent@example.com',
            'password': 'somepassword'
        }

        response = self.client.post(self.login_url, login_payload, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_login_missing_credentials(self):
        """Test login fails with missing email or password"""
        login_payload = {
            'email': 'test@example.com'
        }

        response = self.client.post(self.login_url, login_payload, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch('auth_service.api.views.requests.post')
    def test_login_account_locked(self, mock_post):
        """Test login fails when account is locked (Auth0 blocked)"""
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.json.return_value = {
            'error': 'unauthorized',
            'error_description': 'Account is blocked.'
        }
        mock_post.return_value = mock_response

        login_payload = {
            'email': 'test@example.com',
            'password': 'testpassword123'
        }

        response = self.client.post(self.login_url, login_payload, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIn('error', response.data)

    @patch('auth_service.api.views.requests.post')
    def test_login_auth0_service_unavailable(self, mock_post):
        """Test login fails when Auth0 service is unavailable"""
        mock_response = MagicMock()
        mock_response.status_code = 503
        mock_post.return_value = mock_response

        login_payload = {
            'email': 'test@example.com',
            'password': 'testpassword123'
        }

        response = self.client.post(self.login_url, login_payload, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_503_SERVICE_UNAVAILABLE)