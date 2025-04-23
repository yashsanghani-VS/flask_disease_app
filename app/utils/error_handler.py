from flask import jsonify
from werkzeug.exceptions import HTTPException
from marshmallow import ValidationError

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
        return rv

def register_error_handlers(app):
    @app.errorhandler(APIError)
    def handle_api_error(error):
        response = jsonify(error.to_dict())
        response.status_code = error.status_code
        return response

    @app.errorhandler(ValidationError)
    def handle_validation_error(error):
        return jsonify({
            'status': 'error',
            'message': 'Validation error',
            'errors': error.messages
        }), 400

    @app.errorhandler(HTTPException)
    def handle_http_error(error):
        return jsonify({
            'status': 'error',
            'message': error.description
        }), error.code

    @app.errorhandler(Exception)
    def handle_generic_error(error):
        app.logger.error(f'Unhandled error: {str(error)}')
        return jsonify({
            'status': 'error',
            'message': 'An unexpected error occurred'
        }), 500
