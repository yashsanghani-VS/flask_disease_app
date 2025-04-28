from flask_restx import Api
from flask import Blueprint

# Create blueprint
api_bp = Blueprint('api', __name__)

# Initialize API
api = Api(
    api_bp,
    version='1.0',
    title='Flask Auth API',
    description='A secure authentication API with role-based access control',
    doc='/docs',
    security='Bearer Auth',
    authorizations={
        'Bearer Auth': {
            'type': 'apiKey',
            'in': 'header',
            'name': 'Authorization',
            'description': 'Type in the *Value* input box: Bearer {your JWT token}'
        }
    }
)

# Import and register namespaces
from app.api.auth import auth_ns
from app.api.users import users_ns

api.add_namespace(auth_ns)
api.add_namespace(users_ns)