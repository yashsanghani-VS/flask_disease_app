from flask import jsonify, current_app
from werkzeug.exceptions import HTTPException
from marshmallow import ValidationError
from sqlalchemy.exc import IntegrityError
from flask_jwt_extended.exceptions import NoAuthorizationError, InvalidHeaderError, WrongTokenError, RevokedTokenError, FreshTokenRequired
import traceback

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
    current_app.logger.error(f'API Error: {error.message} (Status: {error.status_code})')
    if error.payload:
        current_app.logger.error(f'Error payload: {error.payload}')
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response

def handle_validation_error(error):
    """Handle validation errors."""
    current_app.logger.warning(f'Validation Error: {error.messages}')
    return jsonify({
        'status': 'error',
        'message': 'Validation error occurred',
        'errors': error.messages,
        'status_code': 400
    }), 400

def handle_http_error(error):
    """Handle HTTP errors."""
    current_app.logger.error(f'HTTP Error: {error.description} (Status: {error.code})')
    return jsonify({
        'status': 'error',
        'message': error.description,
        'status_code': error.code
    }), error.code

def handle_integrity_error(error):
    """Handle database integrity errors."""
    if 'duplicate key' in str(error.orig).lower():
        current_app.logger.warning('Duplicate entry found in database')
        return jsonify({
            'status': 'error',
            'message': 'A record with this information already exists',
            'status_code': 400
        }), 400
    
    current_app.logger.error(f'Database integrity error: {str(error)}')
    return jsonify({
        'status': 'error',
        'message': 'Database integrity error occurred',
        'status_code': 400
    }), 400

def handle_jwt_error(error):
    """Handle JWT-related errors."""
    if isinstance(error, NoAuthorizationError):
        current_app.logger.warning("Missing Authorization Header")
        return jsonify({
            'status': 'error',
            'message': 'Missing Authorization Header. Please provide a valid token.',
            'status_code': 401
        }), 401
    elif isinstance(error, InvalidHeaderError):
        current_app.logger.warning("Invalid Authorization Header")
        return jsonify({
            'status': 'error',
            'message': 'Invalid Authorization Header. Please provide a valid token.',
            'status_code': 401
        }), 401
    elif isinstance(error, WrongTokenError):
        current_app.logger.warning("Wrong token type")
        return jsonify({
            'status': 'error',
            'message': 'Wrong token type. Please provide a valid token.',
            'status_code': 401
        }), 401
    elif isinstance(error, RevokedTokenError):
        current_app.logger.warning("Token has been revoked")
        return jsonify({
            'status': 'error',
            'message': 'Token has been revoked. Please login again.',
            'status_code': 401
        }), 401
    elif isinstance(error, FreshTokenRequired):
        current_app.logger.warning("Fresh token required")
        return jsonify({
            'status': 'error',
            'message': 'Fresh token required. Please login again.',
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
    
    # Log the error with full traceback
    current_app.logger.error(f'Unhandled error: {str(error)}\n{traceback.format_exc()}')
    
    # Return generic error response
    return jsonify({
        'status': 'error',
        'message': 'An unexpected error occurred. Please try again later.',
        'status_code': 500
    }), 500
