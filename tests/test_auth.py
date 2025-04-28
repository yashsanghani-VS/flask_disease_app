import unittest
import json
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
    
    def setUp(self):
        """Set up test data for each test."""
        from app import create_app, db
        self.app = create_app('testing')
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        
        # Create database tables
        db.create_all()
        
        # Create default roles
        from app.models.role import Role
        Role.create_default_roles()
        
        # Create admin user if it doesn't exist
        from app.models.user import User
        admin = User.query.filter_by(email='admin@example.com').first()
        if not admin:
            admin_role = Role.query.filter_by(name='admin').first()
            admin = User(
                email='admin@example.com',
                password='Admin@123',
                first_name='Admin',
                last_name='User',
                role=admin_role
            )
            db.session.add(admin)
            db.session.commit()
        
        # Test user data
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
    
    def tearDown(self):
        """Clean up after each test."""
        from app import db
        db.session.remove()
        db.drop_all()
        self.app_context.pop()
    
    def login_as_admin(self):
        """Helper method to login as admin."""
        response = self.client.post(
            '/api/auth/login',
            data=json.dumps(self.admin_user),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.admin_token = data['access_token']
        return self.admin_token
    
    # ===== User Registration & Login Tests =====
    
    def test_01_user_registration(self):
        """
        Test user registration functionality.
        - Successful registration
        - Duplicate email registration
        """
        # Test successful registration
        response = self.client.post(
            '/api/auth/register',
            data=json.dumps(self.test_user),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 201)
        data = json.loads(response.data)
        self.assertIn('access_token', data)
        self.assertIn('refresh_token', data)
        self.assertIn('user', data)

        # Test duplicate registration
        response = self.client.post(
            '/api/auth/register',
            data=json.dumps(self.test_user),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 409)
        self.assertEqual(json.loads(response.data)['message'], 'Email already registered')
    
    def test_02_user_login(self):
        """
        Test user login functionality.
        - Successful login
        - Invalid credentials
        - Account locking
        """
        # Register user first
        self.client.post(
            '/api/auth/register',
            data=json.dumps(self.test_user),
            content_type='application/json'
        )
        
        # Test successful login
        response = self.client.post(
            '/api/auth/login',
            data=json.dumps({
                "email": self.test_user["email"],
                "password": self.test_user["password"]
            }),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn('access_token', data)
        self.assertIn('refresh_token', data)
        self.assertIn('user', data)
        
        # Store tokens for subsequent tests
        self.access_token = data['access_token']
        self.refresh_token = data['refresh_token']
        
        # Test invalid login
        response = self.client.post(
            '/api/auth/login',
            data=json.dumps({
                "email": self.test_user["email"],
                "password": "wrongpassword"
            }),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(json.loads(response.data)['message'], 'Invalid email or password')
        
        # Test account locking after multiple failed attempts
        for _ in range(5):
            self.client.post(
                '/api/auth/login',
                data=json.dumps({
                    "email": self.test_user["email"],
                    "password": "wrongpassword"
                }),
                content_type='application/json'
            )
        
        # Try to login with correct credentials after locking
        response = self.client.post(
            '/api/auth/login',
            data=json.dumps({
                "email": self.test_user["email"],
                "password": self.test_user["password"]
            }),
            content_type='application/json'
        )
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
        response = self.client.get('/api/auth/me', headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(json.loads(response.data)['email'], self.test_user['email'])
        
        # Test get profile without token
        response = self.client.get('/api/auth/me')
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
        response = self.client.put(
            '/api/auth/me',
            headers=headers,
            data=json.dumps(update_data),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['first_name'], update_data['first_name'])
        self.assertEqual(data['last_name'], update_data['last_name'])
    
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
        response = self.client.post('/api/auth/refresh', headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertIn('access_token', json.loads(response.data))
        
        # Test invalid refresh token
        headers = {"Authorization": "Bearer invalid-token"}
        response = self.client.post('/api/auth/refresh', headers=headers)
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
        response = self.client.post('/api/auth/logout', headers=headers)
        self.assertEqual(response.status_code, 200)
        
        # Verify token is invalidated
        response = self.client.get('/api/auth/me', headers=headers)
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
        
        # Test list users
        headers = {"Authorization": f"Bearer {admin_token}"}
        response = self.client.get('/api/users/', headers=headers)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIsInstance(data, list)
        
        # Test get user details
        user_id = data[0]['id']  # Get first user's ID
        response = self.client.get(f'/api/users/{user_id}', headers=headers)
        self.assertEqual(response.status_code, 200)
        
        # Test update user
        update_data = {
            "first_name": "Updated",
            "last_name": "Name"
        }
        response = self.client.put(
            f'/api/users/{user_id}',
            headers=headers,
            data=json.dumps(update_data),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 200)
        
        # Test delete user
        response = self.client.delete(f'/api/users/{user_id}', headers=headers)
        self.assertEqual(response.status_code, 204)
    
    def test_08_non_admin_access(self):
        """
        Test non-admin access to user management.
        - Attempt to list users
        - Attempt to get user details
        - Attempt to update user
        - Attempt to delete user
        """
        # Setup: Register and login as regular user
        self.test_02_user_login()
        
        # Test list users
        headers = {"Authorization": f"Bearer {self.access_token}"}
        response = self.client.get('/api/users/', headers=headers)
        self.assertEqual(response.status_code, 403)
        
        # Test get user details
        response = self.client.get('/api/users/1', headers=headers)
        self.assertEqual(response.status_code, 403)
        
        # Test update user
        update_data = {
            "first_name": "Updated",
            "last_name": "Name"
        }
        response = self.client.put(
            '/api/users/1',
            headers=headers,
            data=json.dumps(update_data),
            content_type='application/json'
        )
        self.assertEqual(response.status_code, 403)
        
        # Test delete user
        response = self.client.delete('/api/users/1', headers=headers)
        self.assertEqual(response.status_code, 403)

if __name__ == '__main__':
    unittest.main() 