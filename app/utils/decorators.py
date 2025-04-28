from functools import wraps
from flask import jsonify
from flask_jwt_extended import get_jwt_identity
from app.models.user import User
from app.utils.error_handler import APIError

def admin_required(fn):
    """Decorator to require admin role."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user or not user.is_admin():
            raise APIError('Admin access required', status_code=403)
        
        return fn(*args, **kwargs)
    return wrapper

def role_required(roles):
    """Decorator to require specific roles."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            current_user_id = get_jwt_identity()
            user = User.query.get(current_user_id)
            
            if not user or user.role.name not in roles:
                raise APIError('Insufficient permissions', status_code=403)
            
            return fn(*args, **kwargs)
        return wrapper
    return decorator