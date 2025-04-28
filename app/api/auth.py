from flask_restx import Namespace, Resource, fields
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt
from app.models.user import User, UserSchema
from app.models.token import TokenBlacklist
from app import db
from marshmallow import ValidationError
from datetime import datetime, timedelta
from app.utils.logger import logger
from app.utils.error_handler import APIError
from flask_jwt_extended.exceptions import NoAuthorizationError, InvalidHeaderError, WrongTokenError, RevokedTokenError, FreshTokenRequired
from werkzeug.security import generate_password_hash
import re

auth_ns = Namespace('auth', description='Authentication operations')

# Constants
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=30)
TOKEN_EXPIRY = timedelta(hours=1)
REFRESH_TOKEN_EXPIRY = timedelta(days=30)

# Request models
login_model = auth_ns.model('Login', {
    'email': fields.String(required=True, description='User email'),
    'password': fields.String(required=True, description='User password')
})

register_model = auth_ns.model('Register', {
    'email': fields.String(required=True, description='User email'),
    'password': fields.String(required=True, description='User password'),
    'first_name': fields.String(required=True, description='User first name'),
    'last_name': fields.String(required=True, description='User last name')
})

# Response models
token_model = auth_ns.model('Token', {
    'access_token': fields.String(description='Access token'),
    'refresh_token': fields.String(description='Refresh token'),
    'user': fields.Nested(auth_ns.model('User', {
        'id': fields.Integer,
        'email': fields.String,
        'first_name': fields.String,
        'last_name': fields.String,
        'role': fields.String
    }))
})

error_model = auth_ns.model('Error', {
    'status': fields.String(description='Error status'),
    'message': fields.String(description='Error message'),
    'status_code': fields.Integer(description='HTTP status code')
})

# Helper functions
def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character"
    return True, "Password is valid"

def validate_email(email):
    """Validate email format"""
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(email_pattern, email))

def handle_jwt_error(error):
    """Handle JWT-related errors and return appropriate responses"""
    if isinstance(error, NoAuthorizationError):
        return APIError('Missing Authorization Header', 401).to_dict(), 401
    elif isinstance(error, InvalidHeaderError):
        return APIError('Invalid Authorization Header', 401).to_dict(), 401
    elif isinstance(error, WrongTokenError):
        return APIError('Invalid token', 401).to_dict(), 401
    elif isinstance(error, RevokedTokenError):
        return APIError('Token has been revoked', 401).to_dict(), 401
    elif isinstance(error, FreshTokenRequired):
        return APIError('Fresh token required', 401).to_dict(), 401
    else:
        return APIError('Authentication failed', 401).to_dict(), 401

# Error handlers
@auth_ns.errorhandler(NoAuthorizationError)
@auth_ns.errorhandler(InvalidHeaderError)
@auth_ns.errorhandler(WrongTokenError)
@auth_ns.errorhandler(RevokedTokenError)
@auth_ns.errorhandler(FreshTokenRequired)
def handle_jwt_errors(error):
    return handle_jwt_error(error)

@auth_ns.errorhandler(Exception)
def handle_generic_error(error):
    logger.error(f"Unexpected error: {str(error)}")
    return APIError('An unexpected error occurred', 500).to_dict(), 500

# Route definitions
@auth_ns.route('/register')
class Register(Resource):
    @auth_ns.expect(register_model)
    @auth_ns.response(201, 'User registered successfully', token_model)
    @auth_ns.response(400, 'Validation error', error_model)
    @auth_ns.response(409, 'Email already registered', error_model)
    def post(self):
        """Register a new user."""
        try:
            data = auth_ns.payload
            
            # Validate email format
            if not validate_email(data['email']):
                raise APIError('Invalid email format', 400)
            
            # Validate password strength
            is_valid, message = validate_password(data['password'])
            if not is_valid:
                raise APIError(message, 400)
            
            try:
                data = UserSchema().load(data)
            except ValidationError as err:
                raise APIError('Validation error', 400, {'errors': err.messages})
            
            # Check for existing user
            existing_user = User.query.filter_by(email=data['email']).first()
            if existing_user:
                raise APIError('Email already registered', 409)
            
            # Create new user
            user = User(
                email=data['email'],
                password=data['password'],
                first_name=data['first_name'],
                last_name=data['last_name']
            )
            
            try:
                db.session.add(user)
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                logger.error(f"Database error during registration: {str(e)}")
                raise APIError('Failed to create user', 500)
            
            # Generate tokens
            access_token = create_access_token(
                identity=user,
                expires_delta=TOKEN_EXPIRY
            )
            refresh_token = create_refresh_token(
                identity=user,
                expires_delta=REFRESH_TOKEN_EXPIRY
            )
            
            return {
                'message': 'User registered successfully',
                'access_token': access_token,
                'refresh_token': refresh_token,
                'user': user.to_dict()
            }, 201
            
        except APIError as e:
            return e.to_dict(), e.status_code
        except Exception as e:
            logger.error(f"Registration failed: {str(e)}")
            raise APIError('Failed to register user', 500)

@auth_ns.route('/login')
class Login(Resource):
    @auth_ns.expect(login_model)
    @auth_ns.response(200, 'Login successful', token_model)
    @auth_ns.response(400, 'Invalid credentials', error_model)
    @auth_ns.response(403, 'Account locked', error_model)
    def post(self):
        """Login user and get tokens."""
        try:
            data = auth_ns.payload
            email = data.get('email')
            password = data.get('password')
            
            if not email or not password:
                raise APIError('Email and password are required', 400)
            
            # Validate email format
            if not validate_email(email):
                raise APIError('Invalid email format', 400)
            
            # Find user
            user = User.query.filter_by(email=email).first()
            
            # Check credentials
            if not user or not user.verify_password(password):
                if user:
                    try:
                        user.record_login_failure()
                        if user.login_attempts >= MAX_LOGIN_ATTEMPTS:
                            user.lock_account(LOCKOUT_DURATION)
                            db.session.commit()
                            raise APIError('Account locked due to too many failed attempts', 403)
                    except APIError:
                        pass
                raise APIError('Invalid email or password', 400)
            
            # Check if account is locked
            if user.is_account_locked():
                raise APIError('Account is locked. Please try again later', 403)
            
            # Record successful login
            try:
                user.record_login_success()
                db.session.commit()
            except APIError:
                pass
            
            # Generate tokens
            access_token = create_access_token(
                identity=user,
                expires_delta=TOKEN_EXPIRY
            )
            refresh_token = create_refresh_token(
                identity=user,
                expires_delta=REFRESH_TOKEN_EXPIRY
            )
            
            return {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'user': user.to_dict()
            }, 200
            
        except APIError as e:
            return e.to_dict(), e.status_code
        except Exception as e:
            logger.error(f"Login failed: {str(e)}")
            raise APIError('Login failed', 500)

@auth_ns.route('/refresh')
class Refresh(Resource):
    @auth_ns.doc(security='Bearer Auth')
    @jwt_required(refresh=True)
    @auth_ns.response(200, 'Token refreshed', token_model)
    @auth_ns.response(401, 'Invalid token', error_model)
    def post(self):
        """Refresh access token."""
        try:
            current_user_id = get_jwt_identity()
            user = db.session.get(User, current_user_id)
            
            if not user:
                raise APIError('User not found', 404)
            
            if user.is_account_locked():
                raise APIError('Account is locked', 403)
                
            access_token = create_access_token(
                identity=user,
                expires_delta=TOKEN_EXPIRY
            )
            return {
                'access_token': access_token,
                'user': user.to_dict()
            }, 200
            
        except APIError as e:
            return e.to_dict(), e.status_code
        except Exception as e:
            logger.error(f"Token refresh failed: {str(e)}")
            raise APIError('Failed to refresh token', 401)

@auth_ns.route('/me')
class UserProfile(Resource):
    @auth_ns.doc(security='Bearer Auth')
    @jwt_required()
    @auth_ns.response(200, 'User profile retrieved', token_model)
    @auth_ns.response(401, 'Invalid token', error_model)
    @auth_ns.response(404, 'User not found', error_model)
    def get(self):
        """Get current user profile."""
        try:
            current_user_id = get_jwt_identity()
            user = db.session.get(User, current_user_id)
            
            if not user:
                raise APIError('User not found', 404)
            
            if user.is_account_locked():
                raise APIError('Account is locked', 403)
                
            return user.to_dict(), 200
            
        except APIError as e:
            return e.to_dict(), e.status_code
        except Exception as e:
            logger.error(f"Profile retrieval failed: {str(e)}")
            raise APIError('Failed to get user profile', 401)
    
    @auth_ns.doc(security='Bearer Auth')
    @jwt_required()
    @auth_ns.expect(register_model)
    @auth_ns.response(200, 'User profile updated', token_model)
    @auth_ns.response(400, 'Validation error', error_model)
    @auth_ns.response(401, 'Invalid token', error_model)
    @auth_ns.response(404, 'User not found', error_model)
    def put(self):
        """Update current user profile."""
        try:
            current_user_id = get_jwt_identity()
            user = db.session.get(User, current_user_id)
            
            if not user:
                raise APIError('User not found', 404)
            
            if user.is_account_locked():
                raise APIError('Account is locked', 403)
            
            data = auth_ns.payload
            
            # Validate email if provided
            if 'email' in data and not validate_email(data['email']):
                raise APIError('Invalid email format', 400)
            
            # Validate password if provided
            if 'password' in data:
                is_valid, message = validate_password(data['password'])
                if not is_valid:
                    raise APIError(message, 400)
            
            try:
                data = UserSchema().load(data, partial=True)
            except ValidationError as err:
                raise APIError('Validation error', 400, {'errors': err.messages})
            
            if 'first_name' in data:
                user.first_name = data['first_name']
            if 'last_name' in data:
                user.last_name = data['last_name']
            if 'password' in data:
                user.password = data['password']
            if 'email' in data:
                # Check if new email is already taken
                existing_user = User.query.filter_by(email=data['email']).first()
                if existing_user and existing_user.id != user.id:
                    raise APIError('Email already registered', 409)
                user.email = data['email']
            
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                logger.error(f"Database error during profile update: {str(e)}")
                raise APIError('Failed to update profile', 500)
            
            return user.to_dict(), 200
            
        except APIError as e:
            return e.to_dict(), e.status_code
        except Exception as e:
            db.session.rollback()
            logger.error(f"Profile update failed: {str(e)}")
            raise APIError('Failed to update user profile', 401)

@auth_ns.route('/logout')
class Logout(Resource):
    @auth_ns.doc(security='Bearer Auth')
    @jwt_required()
    @auth_ns.response(200, 'Successfully logged out')
    @auth_ns.response(401, 'Invalid token', error_model)
    def post(self):
        """Logout user and blacklist token."""
        try:
            # Get the JTI from the current token
            jti = get_jwt()['jti']
            
            # Add the token to the blacklist
            token = TokenBlacklist(jti=jti, created_at=datetime.utcnow())
            db.session.add(token)
            
            # If there's a refresh token in the request, blacklist it too
            try:
                refresh_jti = get_jwt(refresh=True)['jti']
                refresh_token = TokenBlacklist(jti=refresh_jti, created_at=datetime.utcnow())
                db.session.add(refresh_token)
            except Exception:
                # If no refresh token, that's fine
                pass
            
            try:
                db.session.commit()
            except Exception as e:
                db.session.rollback()
                logger.error(f"Database error during logout: {str(e)}")
                raise APIError('Failed to logout', 500)
            
            return {
                'status': 'success',
                'message': 'Successfully logged out. All tokens have been invalidated.'
            }, 200
            
        except APIError as e:
            return e.to_dict(), e.status_code
        except Exception as e:
            db.session.rollback()
            logger.error(f"Logout failed: {str(e)}")
            raise APIError('Failed to logout. Please try again.', 401)