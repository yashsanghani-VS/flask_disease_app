from flask_restx import Namespace, Resource, fields
from flask_jwt_extended import jwt_required
from app.models.user import User, UserSchema
from app import db
from marshmallow import ValidationError
from app.utils.decorators import admin_required
from app.utils.error_handler import APIError

users_ns = Namespace('users', description='User operations')

# Request/Response models
user_model = users_ns.model('User', {
    'id': fields.Integer(readonly=True),
    'email': fields.String(required=True),
    'first_name': fields.String(required=True),
    'last_name': fields.String(required=True),
    'is_active': fields.Boolean(default=True),
    'role': fields.String(readonly=True)
})

error_model = users_ns.model('Error', {
    'status': fields.String(description='Error status'),
    'message': fields.String(description='Error message'),
    'status_code': fields.Integer(description='HTTP status code')
})

@users_ns.route('/')
class UserList(Resource):
    @users_ns.doc(security='Bearer Auth')
    @jwt_required()
    @admin_required
    @users_ns.response(200, 'List of users', [user_model])
    @users_ns.response(403, 'Admin access required', error_model)
    def get(self):
        """Get all users (admin only)."""
        try:
            users = User.query.all()
            return [user.to_dict() for user in users], 200
        except Exception as e:
            raise APIError('Failed to fetch users', 500)

@users_ns.route('/<int:user_id>')
class UserResource(Resource):
    @users_ns.doc(security='Bearer Auth')
    @jwt_required()
    @admin_required
    @users_ns.response(200, 'User details', user_model)
    @users_ns.response(404, 'User not found', error_model)
    @users_ns.response(403, 'Admin access required', error_model)
    def get(self, user_id):
        """Get user by ID (admin only)."""
        try:
            user = db.session.get(User, user_id)
            if not user:
                raise APIError('User not found', 404)
            return user.to_dict(), 200
        except APIError:
            raise
        except Exception as e:
            raise APIError('Failed to fetch user', 500)
    
    @users_ns.doc(security='Bearer Auth')
    @jwt_required()
    @admin_required
    @users_ns.expect(user_model)
    @users_ns.response(200, 'User updated', user_model)
    @users_ns.response(400, 'Validation error', error_model)
    @users_ns.response(404, 'User not found', error_model)
    @users_ns.response(403, 'Admin access required', error_model)
    def put(self, user_id):
        """Update user (admin only)."""
        try:
            user = db.session.get(User, user_id)
            if not user:
                raise APIError('User not found', 404)
            
            try:
                data = UserSchema().load(users_ns.payload, partial=True)
            except ValidationError as err:
                raise APIError('Validation error', 400, {'errors': err.messages})
            
            if 'email' in data and data['email'] != user.email:
                if User.query.filter_by(email=data['email']).first():
                    raise APIError('Email already registered', 400)
                user.email = data['email']
            
            if 'first_name' in data:
                user.first_name = data['first_name']
            if 'last_name' in data:
                user.last_name = data['last_name']
            if 'password' in data:
                user.password = data['password']
            if 'is_active' in data:
                user.is_active = data['is_active']
            
            db.session.commit()
            return user.to_dict(), 200
            
        except APIError:
            raise
        except Exception as e:
            db.session.rollback()
            raise APIError('Failed to update user', 500)
    
    @users_ns.doc(security='Bearer Auth')
    @jwt_required()
    @admin_required
    @users_ns.response(204, 'User deleted')
    @users_ns.response(404, 'User not found', error_model)
    @users_ns.response(403, 'Admin access required', error_model)
    def delete(self, user_id):
        """Delete user (admin only)."""
        try:
            user = db.session.get(User, user_id)
            if not user:
                raise APIError('User not found', 404)
                
            db.session.delete(user)
            db.session.commit()
            return '', 204
            
        except APIError:
            raise
        except Exception as e:
            db.session.rollback()
            raise APIError('Failed to delete user', 500)