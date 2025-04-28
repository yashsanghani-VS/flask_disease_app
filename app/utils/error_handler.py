from flask import jsonify, current_app
from werkzeug.exceptions import HTTPException
from marshmallow import ValidationError
from sqlalchemy.exc import IntegrityError
from flask_jwt_extended.exceptions import NoAuthorizationError, InvalidHeaderError, WrongTokenError, RevokedTokenError, FreshTokenRequired
import traceback
import jwt

class APIError(Exception):
    """Base exception for API errors."""
    def __init__(self, message, status_code=400, payload=None):
        super().__init__()
        self.message = message
        self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        rv['status'] = 'error'
        rv['status_code'] = self.status_code
        return rv

def handle_api_error(error):
    """Handle API errors."""
    response = error.to_dict()
    return jsonify(response), error.status_code

def handle_validation_error(error):
    """Handle validation errors."""
    return jsonify({
        'status': 'error',
        'message': 'Validation error',
        'errors': error.messages,
        'status_code': 400
    }), 400

def handle_http_error(error):
    """Handle HTTP errors."""
    return jsonify({
        'status': 'error',
        'message': error.description,
        'status_code': error.code
    }), error.code

def handle_integrity_error(error):
    """Handle database integrity errors."""
    return jsonify({
        'status': 'error',
        'message': 'Database integrity error',
        'status_code': 409
    }), 409

def handle_jwt_error(error):
    """Handle JWT-related errors."""
    if isinstance(error, (NoAuthorizationError, InvalidHeaderError, WrongTokenError, RevokedTokenError, FreshTokenRequired)):
        current_app.logger.warning(f"JWT Error: {str(error)}")
        return jsonify({
            'status': 'error',
            'message': str(error),
            'status_code': 401
        }), 401
    elif isinstance(error, jwt.exceptions.DecodeError):
        current_app.logger.warning("Invalid token format")
        return jsonify({
            'status': 'error',
            'message': 'Invalid token format. Please login again.',
            'status_code': 401
        }), 401
    elif isinstance(error, jwt.exceptions.ExpiredSignatureError):
        current_app.logger.warning("Token has expired")
        return jsonify({
            'status': 'error',
            'message': 'Token has expired. Please login again.',
            'status_code': 401
        }), 401
    elif isinstance(error, jwt.exceptions.InvalidTokenError):
        current_app.logger.warning("Invalid token")
        return jsonify({
            'status': 'error',
            'message': 'Invalid token. Please login again.',
            'status_code': 401
        }), 401
    
    current_app.logger.error(f'JWT Error: {str(error)}')
    return jsonify({
        'status': 'error',
        'message': 'Authentication error. Please login again.',
        'status_code': 401
    }), 401

def handle_generic_error(error):
    """Handle generic errors."""
    # Handle specific error types
    if isinstance(error, IntegrityError):
        return handle_integrity_error(error)
    elif isinstance(error, (NoAuthorizationError, InvalidHeaderError, WrongTokenError, RevokedTokenError, FreshTokenRequired)):
        return handle_jwt_error(error)
    elif isinstance(error, APIError):
        return handle_api_error(error)
    elif isinstance(error, jwt.exceptions.DecodeError):
        return handle_jwt_error(error)
    
    # Log the error with full traceback
    current_app.logger.error(f'Unhandled error: {str(error)}\n{traceback.format_exc()}')
    
    # Return generic error response
    return jsonify({
        'status': 'error',
        'message': 'An unexpected error occurred. Please try again later.',
        'status_code': 500
    }), 500
