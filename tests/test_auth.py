import unittest
import requests
from datetime import datetime

class TestAuthenticationAPI(unittest.TestCase):
    """
    Test suite for Authentication API endpoints.
    
    Test Categories:
    1. User Registration & Login
    2. Profile Management
    3. Token Management
    4. Security Features
    5. User Management (Admin)
    
    Each test method is named to clearly indicate what it tests.
    """
    
    BASE_URL = 'http://localhost:8000/api'
    AUTH_URL = f'{BASE_URL}/auth'
    USERS_URL = f'{BASE_URL}/users'
    
    def setUp(self):
        """Set up test data for each test."""
        self.test_user = {
            "email": f"test_{datetime.now().strftime('%Y%m%d%H%M%S')}@example.com",
            "password": "Test@123",
            "first_name": "Test",
            "last_name": "User"
        }
        self.access_token = None
        self.refresh_token = None
        
        # Admin credentials
        self.admin_user = {
            "email": "admin@example.com",
            "password": "Admin@123"
        }
        self.admin_token = None
    
    def login_as_admin(self):
        """Helper method to login as admin."""
        response = requests.post(f"{self.AUTH_URL}/login", json=self.admin_user)
        self.assertEqual(response.status_code, 200)
        self.admin_token = response.json()['access_token']
        return self.admin_token
    
    # ===== User Registration & Login Tests =====
    
    def test_01_user_registration(self):
        """
        Test user registration functionality.
        - Successful registration
        - Duplicate email registration
        """
        # Test successful registration
        response = requests.post(f"{self.AUTH_URL}/register", json=self.test_user)
        self.assertEqual(response.status_code, 201)
        
        # Test duplicate registration
        response = requests.post(f"{self.AUTH_URL}/register", json=self.test_user)
        self.assertEqual(response.status_code, 409)  # Changed from 400 to 409 for duplicate email
    
    def test_02_user_login(self):
        """
        Test user login functionality.
        - Successful login
        - Invalid credentials
        - Account locking
        """
        # Register user first
        requests.post(f"{self.AUTH_URL}/register", json=self.test_user)
        
        # Test successful login
        response = requests.post(f"{self.AUTH_URL}/login", json={
            "email": self.test_user["email"],
            "password": self.test_user["password"]
        })
        self.assertEqual(response.status_code, 200)
        data = response.json()
        
        # Store tokens for subsequent tests
        self.access_token = data['access_token']
        self.refresh_token = data['refresh_token']
        
        # Test invalid login
        response = requests.post(f"{self.AUTH_URL}/login", json={
            "email": self.test_user["email"],
            "password": "wrongpassword"
        })
        self.assertEqual(response.status_code, 400)
        
        # Test account locking after multiple failed attempts
        for _ in range(5):
            requests.post(f"{self.AUTH_URL}/login", json={
                "email": self.test_user["email"],
                "password": "wrongpassword"
            })
        
        # Try to login with correct credentials after locking
        response = requests.post(f"{self.AUTH_URL}/login", json={
            "email": self.test_user["email"],
            "password": self.test_user["password"]
        })
        self.assertEqual(response.status_code, 403)  # Account locked
    
    # ===== Profile Management Tests =====
    
    def test_03_profile_retrieval(self):
        """
        Test profile retrieval functionality.
        - Get profile with valid token
        - Get profile without token
        """
        # Setup: Register and login
        self.test_02_user_login()
        
        # Test get profile with valid token
        headers = {"Authorization": f"Bearer {self.access_token}"}
        response = requests.get(f"{self.AUTH_URL}/me", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['email'], self.test_user['email'])
        
        # Test get profile without token
        response = requests.get(f"{self.AUTH_URL}/me")
        self.assertEqual(response.status_code, 401)
    
    def test_04_profile_update(self):
        """
        Test profile update functionality.
        - Update profile information
        - Verify updates
        """
        # Setup: Register and login
        self.test_02_user_login()
        
        # Test profile update
        headers = {"Authorization": f"Bearer {self.access_token}"}
        update_data = {
            "first_name": "Updated",
            "last_name": "Name",
            "password": "NewPassword123"
        }
        response = requests.put(f"{self.AUTH_URL}/me", headers=headers, json=update_data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['first_name'], update_data['first_name'])
        self.assertEqual(response.json()['last_name'], update_data['last_name'])
    
    # ===== Token Management Tests =====
    
    def test_05_token_refresh(self):
        """
        Test token refresh functionality.
        - Refresh access token
        - Invalid refresh token
        """
        # Setup: Register and login
        self.test_02_user_login()
        
        # Test token refresh
        headers = {"Authorization": f"Bearer {self.refresh_token}"}
        response = requests.post(f"{self.AUTH_URL}/refresh", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn('access_token', response.json())
        
        # Test invalid refresh token
        headers = {"Authorization": "Bearer invalid-token"}
        response = requests.post(f"{self.AUTH_URL}/refresh", headers=headers)
        self.assertEqual(response.status_code, 401)
    
    def test_06_user_logout(self):
        """
        Test logout functionality.
        - Successful logout
        - Verify token invalidation
        """
        # Setup: Register and login
        self.test_02_user_login()
        
        # Test logout
        headers = {"Authorization": f"Bearer {self.access_token}"}
        response = requests.post(f"{self.AUTH_URL}/logout", headers=headers)
        self.assertEqual(response.status_code, 200)
        
        # Verify token is invalidated
        response = requests.get(f"{self.AUTH_URL}/me", headers=headers)
        self.assertEqual(response.status_code, 401)
    
    # ===== User Management Tests (Admin) =====
    
    def test_07_user_management(self):
        """
        Test user management functionality (admin only).
        - List users
        - Get user details
        - Update user
        - Delete user
        """
        # Login as admin
        admin_token = self.login_as_admin()
        headers = {"Authorization": f"Bearer {admin_token}"}
        
        # Register a test user
        requests.post(f"{self.AUTH_URL}/register", json=self.test_user)
        
        # Test list users
        response = requests.get(f"{self.USERS_URL}/", headers=headers)
        self.assertEqual(response.status_code, 200)
        users = response.json()
        self.assertIsInstance(users, list)
        
        # Find our test user
        test_user_id = None
        for user in users:
            if user['email'] == self.test_user['email']:
                test_user_id = user['id']
                break
        self.assertIsNotNone(test_user_id)
        
        # Test get user details
        response = requests.get(f"{self.USERS_URL}/{test_user_id}", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['email'], self.test_user['email'])
        
        # Test update user
        update_data = {
            "email": "updated@example.com",
            "first_name": "Updated",
            "last_name": "User",
            "is_active": False
        }
        response = requests.put(f"{self.USERS_URL}/{test_user_id}", headers=headers, json=update_data)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['email'], update_data['email'])
        self.assertEqual(response.json()['is_active'], update_data['is_active'])
        
        # Test delete user
        response = requests.delete(f"{self.USERS_URL}/{test_user_id}", headers=headers)
        self.assertEqual(response.status_code, 204)
        
        # Verify user is deleted
        response = requests.get(f"{self.USERS_URL}/{test_user_id}", headers=headers)
        self.assertEqual(response.status_code, 404)
    
    def test_08_non_admin_access(self):
        """
        Test non-admin user access restrictions.
        - Attempt to access admin endpoints
        """
        # Setup: Register and login as regular user
        self.test_02_user_login()
        headers = {"Authorization": f"Bearer {self.access_token}"}
        
        # Test access to admin endpoints
        response = requests.get(f"{self.USERS_URL}/", headers=headers)
        self.assertEqual(response.status_code, 403)
        
        response = requests.get(f"{self.USERS_URL}/1", headers=headers)
        self.assertEqual(response.status_code, 403)
        
        response = requests.put(f"{self.USERS_URL}/1", headers=headers, json={"is_active": False})
        self.assertEqual(response.status_code, 403)
        
        response = requests.delete(f"{self.USERS_URL}/1", headers=headers)
        self.assertEqual(response.status_code, 403)

if __name__ == '__main__':
    unittest.main() 