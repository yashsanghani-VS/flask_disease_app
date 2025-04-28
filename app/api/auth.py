from flask_restx import Namespace, Resource, fields
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt
from app.models.user import User, UserSchema
from app.models.token import TokenBlacklist
from app import db
from marshmallow import ValidationError
from datetime import datetime
from app.utils.logger import logger
from app.utils.error_handler import APIError
from flask_jwt_extended.exceptions import NoAuthorizationError, InvalidHeaderError, WrongTokenError, RevokedTokenError, FreshTokenRequired

auth_ns = Namespace('auth', description='Authentication operations')

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

@auth_ns.route('/register')
class Register(Resource):
    @auth_ns.expect(register_model)
    @auth_ns.response(201, 'User registered successfully', token_model)
    @auth_ns.response(400, 'Validation error', error_model)
    @auth_ns.response(409, 'Email already registered', error_model)
    def post(self):
        """Register a new user."""
        try:
            try:
                data = UserSchema().load(auth_ns.payload)
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
                raise APIError('Failed to create user', 500)
            
            # Generate tokens
            access_token = create_access_token(identity=user)
            refresh_token = create_refresh_token(identity=user)
            
            return {
                'message': 'User registered successfully',
                'access_token': access_token,
                'refresh_token': refresh_token,
                'user': user.to_dict()
            }, 201
            
        except APIError:
            raise
        except Exception as e:
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
            
            # Find user
            user = User.query.filter_by(email=email).first()
            
            # Check credentials
            if not user or not user.verify_password(password):
                if user:
                    try:
                        user.record_login_failure()
                    except APIError:
                        pass  # Ignore recording failure, just return invalid credentials
                raise APIError('Invalid email or password', 400)
            
            # Check if account is locked
            if user.is_account_locked():
                raise APIError('Account is locked. Please try again later', 403)
            
            # Record successful login
            try:
                user.record_login_success()
            except APIError:
                pass  # Ignore recording success, just proceed with login
            
            # Generate tokens
            access_token = create_access_token(identity=user)
            refresh_token = create_refresh_token(identity=user)
            
            return {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'user': user.to_dict()
            }, 200
            
        except APIError:
            raise
        except Exception as e:
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
            user = User.query.get(current_user_id)
            
            if not user:
                raise APIError('User not found', 404)
                
            access_token = create_access_token(identity=user)
            return {
                'access_token': access_token,
                'user': user.to_dict()
            }, 200
            
        except APIError:
            raise
        except Exception as e:
            raise APIError('Failed to refresh token', 500)

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
            user = User.query.get(current_user_id)
            
            if not user:
                raise APIError('User not found', 404)
                
            return user.to_dict(), 200
            
        except APIError:
            raise
        except Exception as e:
            raise APIError('Failed to get user profile', 500)
    
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
            user = User.query.get(current_user_id)
            
            if not user:
                raise APIError('User not found', 404)
            
            try:
                data = UserSchema().load(auth_ns.payload, partial=True)
            except ValidationError as err:
                raise APIError('Validation error', 400, {'errors': err.messages})
            
            if 'first_name' in data:
                user.first_name = data['first_name']
            if 'last_name' in data:
                user.last_name = data['last_name']
            if 'password' in data:
                user.password = data['password']
            
            db.session.commit()
            return user.to_dict(), 200
            
        except APIError:
            raise
        except Exception as e:
            db.session.rollback()
            raise APIError('Failed to update user profile', 500)

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
            
            db.session.commit()
            
            return {
                'status': 'success',
                'message': 'Successfully logged out. All tokens have been invalidated.'
            }, 200
            
        except APIError:
            raise
        except Exception as e:
            db.session.rollback()
            logger.error(f"Logout failed: {str(e)}")
            raise APIError('Failed to logout. Please try again.', 500)