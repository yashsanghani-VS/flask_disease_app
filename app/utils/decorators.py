from functools import wraps
from flask import jsonify
from flask_jwt_extended import get_jwt_identity
from app.models.user import User
from app.utils.error_handler import APIError
from app import db

def admin_required(fn):
    """Decorator to require admin role."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            current_user_id = get_jwt_identity()
            user = db.session.get(User, current_user_id)
            
            if not user:
                raise APIError('User not found', 404)
            
            if not user.is_admin():
                raise APIError('Admin access required', 403)
            
            return fn(*args, **kwargs)
        except APIError as e:
            return e.to_dict(), e.status_code
        except Exception as e:
            raise APIError('Authentication error', 401)
    return wrapper

def role_required(roles):
    """Decorator to require specific roles."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                current_user_id = get_jwt_identity()
                user = db.session.get(User, current_user_id)
                
                if not user:
                    raise APIError('User not found', 404)
                
                if user.role.name not in roles:
                    raise APIError('Insufficient permissions', 403)
                
                return fn(*args, **kwargs)
            except APIError as e:
                return e.to_dict(), e.status_code
            except Exception as e:
                raise APIError('Authentication error', 401)
        return wrapper
    return decorator